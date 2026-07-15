# Postman collection — SSL Store AnyCA Gateway REST

Exercises the **AnyCA Gateway REST** (EJBCA-compatible) API that fronts the SSL Store CA plugin,
grouped by operation flow. Use it to smoke-test the gateway, drive enrollments, watch issuance,
search inventory, and revoke — without going through Keyfactor Command.

## Files

| File | Purpose |
|------|---------|
| `SslStoreCaGateway.postman_collection.json` | The requests, grouped into flow folders |
| `SslStoreCaGateway.postman_environment.json` | Environment variables (base URL, CA/profile names, CSR, etc.) |

## Import

1. Postman → **Import** → select both JSON files.
2. Select the **SSL Store Gateway** environment (top-right).
3. Fill in the environment values (see below).

## Authentication (important)

The gateway REST API authenticates with a **client certificate (mutual TLS)** — there is no
API key or bearer token. In **Postman → Settings → Certificates**:

- Add a client certificate for the gateway host (e.g. `20.7.36.37:8475`) with your PFX (or PEM + key).
- The certificate must be one the gateway trusts/has enrolled (the gateway logs its thumbprint via
  `AuthCertificateValidationCache`).
- If the gateway presents a self-signed TLS server cert, turn **SSL certificate verification** off
  (Settings → General) or add its CA to Postman.

## Variables

| Variable | Example | Notes |
|----------|---------|-------|
| `baseUrl` | `https://20.7.36.37:8475` | Gateway REST base URL |
| `caName` | `SslStoreGw` | Logical CA name |
| `endEntityProfile` | `AnyCA` | End entity profile |
| `certificateProfile` | `PositiveSsl-RSA` | Maps to an SSL Store product |
| `username` | `Keyfactor_POSTMAN_TEST` | End entity username |
| `password` | | End entity enrollment code (if required) |
| `commonName` | `www.example.com` | CN / primary SAN |
| `csrPem` | `-----BEGIN CERTIFICATE REQUEST-----\n...` | Single-line PEM with `\n`, or paste multi-line in the env editor |
| `issuerDn` | `CN=SslStoreGw` | For revocation |
| `serialNumber` | | Certificate serial (revocation) |
| `priorCertSN` | | Prior cert serial (renew/reissue) |
| `revocationReason` | `CESSATION_OF_OPERATION` | RFC 5280 reason name |

## Flows (folders)

1. **Discovery & Health** — `GET ca/status`, `GET ca`, authorized/EE/cert profiles. Confirms auth + plugin are up.
2. **Enroll - New (Email DCV)** — create end entity (with `Approver Email`) → certificate request. Returns pending until the approver validates; cert arrives via sync.
3. **Enroll - New (DNS CNAME DCV)** — create end entity (with `CName Auth Domain Validation=True`) → certificate request (blocks while the plugin publishes the CNAME, verifies propagation, and polls for issuance) → poll search.
4. **Renew / Reissue** — certificate request carrying `PriorCertSN`; the plugin picks renew vs reissue from expiry vs `RenewalWindow`.
5. **Sync / Search** — `certificate/search` and `endentity/search` used during synchronization/inventory.
6. **Revocation** — `PUT certificate/{issuerDn}/{serial}/revoke` → SSL Store refund request.

## Expected "errors" that are actually normal

- **HTTP 400 "The enrollment requires external validation before a certificate can be issued."** —
  the order is pending DCV. Expected for email DCV, and for DNS DCV when the cert isn't issued within
  `DcvPollTimeoutSeconds`. The cert is retrieved on the next CA sync.

## Caveat

The AnyCA Gateway REST surface mirrors the EJBCA REST contract, so request bodies here follow that
shape. Product/template parameters (Approver Email, Validity Period, CName Auth Domain Validation,
PriorCertSN, …) are normally supplied by Command from the certificate profile's enrollment fields;
in this collection they appear as `extension_data` entries and may need tailoring to match your
profile's field names. See [`../docs/enrollment-flows.md`](../docs/enrollment-flows.md) for the full
per-flow behavior and the internal SSL Store WBAPI calls each flow triggers.
