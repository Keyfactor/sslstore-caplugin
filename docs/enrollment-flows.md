# SSL Store AnyCA Gateway — Operation Flows

This document describes what the plugin does for each operation, the calls involved, the
status mapping, and how to read the `FlowLogger` traces. It complements the configuration
reference in [`docsource/configuration.md`](../docsource/configuration.md).

There are **two API layers** in play:

1. **AnyCA Gateway REST API** — the EJBCA-compatible REST surface Keyfactor Command calls
   (e.g. `POST /ejbca/ejbca-rest-api/v1/certificate/certificaterequest`). These are the calls
   in the Postman collection under [`postman/`](../postman).
2. **SSL Store WBAPI** — the vendor API the plugin calls internally
   (`/rest/order/neworder`, `/rest/order/status`, `/rest/order/download`, etc.). You do **not**
   call these directly; they are shown here so the traces make sense.

The plugin never bundles a DNS provider. Automated DNS validation uses the gateway's
**DNS provider plugin framework**: the plugin asks `IDomainValidatorFactory.ResolveDomainValidator(domain, "cname")`
and the operator maps each domain to a **CNAME** validator (e.g. `Ns1CnameDomainValidator`) in the
gateway's **Domain Validation** configuration. `"cname"` is intrinsic to SSL Store DCV and is not a setting.

---

## Status mapping

`RequestManager.MapReturnStatus` maps SSL Store order status to the gateway's `EndEntityStatus`:

| SSL Store `MajorStatus` | Gateway status | Meaning |
|-------------------------|----------------|---------|
| `Active`                | `GENERATED` (40) | Issued; certificate downloadable |
| `Initial`, `Pending`    | `EXTERNALVALIDATION` | Awaiting DCV / issuance |
| `Cancelled`             | `REVOKED` (50) | Cancelled / refunded |
| anything else           | `NEW` | Unknown / not yet actionable |

When `Enroll` returns `EXTERNALVALIDATION`, the gateway surfaces
*"The enrollment requires external validation before a certificate can be issued."* to the
synchronous enroll caller (HTTP 400). This is **expected** for asynchronous DCV — the certificate
is retrieved later by CA Sync (or returned inline if it issues within the poll window; see below).

---

## Flow 1 — New enrollment with email approver validation

Used when DNS validation is **not** enabled and no `PriorCertSN` is present.

1. Extract CN from the subject and SANs from the `dns` set.
2. For each domain, `POST /rest/order/approverlist` (SSL Store) and validate the configured
   `Approver Email` against the returned list (`ValidateEmails`). Invalid → `FAILED`.
3. `POST /rest/order/neworder` (SSL Store) → order created, returns `TheSSLStoreOrderId` + `PartnerOrderId`.
4. Return an `EnrollmentResult`:
   - order `Active` → `GENERATED` (rare on first call);
   - otherwise `EXTERNALVALIDATION` (pending; the approver must click the email).

**Gateway REST calls:** `POST /v1/endentity` → `POST /v1/certificate/certificaterequest`.

**FlowLogger:** `Enroll-New` › `EmailApproverValidation` › `SubmitNewOrderToSslStore` › `MapEnrollmentResult`.

## Flow 2 — New enrollment with automated DNS (CNAME) validation

Used when `DnsValidationEnabled=true` **or** the `CName Auth Domain Validation` template parameter is `True`.

1. `POST /rest/order/neworder` with the CNAME DCV indicator set.
2. SSL Store returns the CNAME record(s) (`CNAMEAuthName` → `CNAMEAuthValue`, plus any per-domain
   records in `DomainAuthVettingStatus`). `CollectDnsRecords` de-duplicates by record name.
3. For each record, resolve the domain's CNAME validator and **publish** the CNAME
   (`IDomainValidator.StageValidation`). Publish failure → `FAILED`.
4. **Verify propagation** across public resolvers (or `DnsVerificationServer`) —
   `DnsPropagationMaxAttempts` × `DnsPropagationDelaySeconds`. Best-effort: failure/exception only warns.
5. **Poll for issuance** up to `DcvPollTimeoutSeconds` (via `GetSingleRecord`, interval 15s):
   - issued in time → download the leaf cert and return `GENERATED` **with the certificate inline**;
   - window expires → return `EXTERNALVALIDATION` (pending); CA Sync retrieves it later.

**Gateway REST calls:** `POST /v1/endentity` → `POST /v1/certificate/certificaterequest`
(→ optionally `POST /v2/certificate/search` to observe issuance).

**FlowLogger:** `Enroll-New` › `SubmitNewOrderToSslStore` › `StageDnsValidation`
(`ResolveValidator` › `PublishRecord` › `VerifyPropagation`) › `PollForIssuance` › `PollResult`.

## Flow 3 — Renewal vs. reissue

Triggered by `EnrollmentType.RenewOrReissue`; requires `PriorCertSN`.

1. Resolve the prior order via `_certDataReader.GetRequestIDBySerialNumber(PriorCertSN)` then
   `POST /rest/order/status` (SSL Store).
2. Compare order expiry to `RenewalWindow`:
   - within the window (or expiry unparseable) → **renewal** (`POST /rest/order/neworder` with `IsRenewalOrder`);
   - otherwise → **reissue** (`POST /rest/order/reissue`, same order).
3. Return the mapped `EnrollmentResult`.

**FlowLogger:** `Enroll-RenewOrReissue` › `LookupPriorRequestId` › `FetchPriorOrderStatus`
› `EvaluateRenewalWindow` › `SubmitRenewalToSslStore` | `SubmitReissueToSslStore`.

## Flow 4 — Get single record (status check / poll)

1. Parse the composite `CARequestID` (`{TheSSLStoreOrderId}-{PartnerOrderId}`) or fall back to legacy CustomOrderId.
2. `POST /rest/order/status` (SSL Store) → map status.
3. If `GENERATED` **or** `REVOKED`, `POST /rest/order/download` and extract the leaf cert.
   A revoked order that was never issued yields no content (returned empty rather than crashing).
4. On `GENERATED`, best-effort DNS cleanup (`CleanupValidation`) removes the CNAME.

**Gateway REST calls:** `POST /v2/certificate/search`.

## Flow 5 — Synchronize

1. `POST /rest/order/query` (SSL Store, paginated) streams orders into a bounded queue.
2. For each order: `POST /rest/order/status`; if `GENERATED`/`REVOKED`, download the leaf cert.
   **Rows are only written when actual certificate bytes exist** — a revoked order with no
   downloadable certificate is skipped (writing empty bytes crashes the gateway's certificate search).
3. Issued rows trigger best-effort DNS cleanup.
4. Emits a summary: `processed / added / skipped`.

**Gateway REST calls:** `POST /v2/certificate/search`, `POST /v1/endentity/search` (Command drives sync).

## Flow 6 — Revocation

1. Parse the SSL Store order id from the `CARequestID`.
2. `POST /rest/order/refundrequest` (SSL Store).
3. `IsError` → `FAILED`; otherwise `REVOKED`.

**Gateway REST call:** `PUT /v1/certificate/{issuer_dn}/{serial}/revoke`.

**FlowLogger:** `Revoke(...)` › `BuildRevokeRequest` › `SubmitRevokeToSslStore` › `RevokeResult`.

---

## Reading FlowLogger output

Each operation renders a step diagram to **Trace** logs on completion:

```
  ===== FLOW: Enroll-New (24211ms total) =====

    [OK] SubmitNewOrderToSslStore (312ms)
    |
    v
    [...] NewEnrollment
    |
    +-- [OK] StageDnsValidation (20120ms)
    +-- [SKIP] PollResult [not issued within poll window; returning pending]
  ===== FLOW RESULT: SUCCESS =====
```

Operational summaries are logged at **Information**; the full step diagram is at **Trace**. Icons:
`[OK]` success, `[FAIL]` failure, `[SKIP]` skipped/best-effort, `[...]` branch.

## Hardening / guardrails

- CA-connection timing values are clamped at `Initialize`: `RenewalWindow` 1–3650 days,
  `DnsPropagationMaxAttempts` 1–30, `DnsPropagationDelaySeconds` 1–120, `DcvPollTimeoutSeconds` 0–600.
  Out-of-range values are logged and overridden.
- Propagation verification never fails an enrollment whose record was published (best-effort, exception-guarded).
- Issuance polling is skipped when SSL Store did not return both order IDs, and disabled entirely with `DcvPollTimeoutSeconds=0`.
- `Enroll` rejects null `productInfo`, tolerates a null `ProductParameters`, and requires `PriorCertSN` for renew/reissue.
- Synchronize/GetSingleRecord never store empty certificate bytes for revoked orders.
