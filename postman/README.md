# Postman collection — SSL Store WBAPI

The actual **SSL Store Web-Based API (WBAPI)** calls the SSL Store CA plugin makes, grouped by
operation flow. Use it to reproduce and debug what the plugin does against SSL Store directly
(the same endpoints `SslStoreClient` calls).

## Files

| File | Purpose |
|------|---------|
| `SslStoreApi.postman_collection.json` | The SSL Store requests, grouped into flow folders |
| `SslStoreApi.postman_environment.json` | Environment variables (base URL, credentials, CSR, order id, …) |

## Import

1. Postman → **Import** → select both JSON files.
2. Select the **SSL Store WBAPI** environment (top-right).
3. Fill in `partnerCode`, `authToken`, and `csrPem` (at minimum).

## Base URL

- Sandbox: `https://sandbox-wbapi.thesslstore.com` (default)
- Production: `https://wbapi.thesslstore.com`

## Authentication

SSL Store authenticates **in the request body**, not with headers. Every request includes:

```json
"AuthRequest": { "PartnerCode": "{{partnerCode}}", "AuthToken": "{{authToken}}" }
```

All calls are `POST` with `Content-Type: application/json`.

## Variables

| Variable | Example | Notes |
|----------|---------|-------|
| `baseUrl` | `https://sandbox-wbapi.thesslstore.com` | Sandbox or production |
| `partnerCode` | | SSL Store Partner Code |
| `authToken` | | SSL Store Auth Token |
| `productCode` | `positivessl` | SSL Store product code |
| `commonName` | `www.example.com` | CN / domain |
| `csrPem` | `-----BEGIN CERTIFICATE REQUEST-----\n...` | PEM CSR (single-line with `\n`, or paste multi-line in env editor) |
| `approverEmail` | `admin@example.com` | Approver / contact email |
| `validityDays` | `365` | Validity period |
| `webServerType` | `Other` | Web server type |
| `customOrderId` | `postman-{{$guid}}` | Your tracking id |
| `theSslStoreOrderId` | | Set automatically from the neworder response by a test script |

## Flows (folders) and their calls

| Flow | Calls (in order) |
|------|------------------|
| **1. Enroll - New (Email DCV)** | `POST /rest/order/approverlist` → `POST /rest/order/neworder` |
| **2. Enroll - New (DNS CNAME DCV)** | `POST /rest/order/neworder` (`CNAMEAuthDVIndicator=true`) |
| **3. Renew / Reissue** | `POST /rest/order/status` → `POST /rest/order/neworder` (renew) **or** `POST /rest/order/reissue` |
| **4. Status & Download** | `POST /rest/order/status` → `POST /rest/order/download` |
| **5. Synchronize** | `POST /rest/order/query` (paged) → status → download per order |
| **6. Revoke** | `POST /rest/order/refundrequest` |

The **New order** requests include a test script that captures `TheSSLStoreOrderID` from the
response into the `theSslStoreOrderId` variable, so the status/download/revoke calls target the
order you just created.

## Notes

- **DNS CNAME DCV:** the `neworder` response returns the CNAME record (`CNAMEAuthName` →
  `CNAMEAuthValue`, plus per-domain entries under `OrderStatus.DomainAuthVettingStatus`). In the
  plugin, that record is published via the CNAME DNS validator mapped to the domain; with raw
  Postman you would create the CNAME yourself, then poll `status`.
- **Contacts:** `AdminContact`/`TechnicalContact` are required for OV/EV products; DV products
  (e.g. `positivessl`) generally ignore them. Example values are inlined in the bodies.
- See [`../docs/enrollment-flows.md`](../docs/enrollment-flows.md) for how each SSL Store call maps
  to the plugin's gateway operations and status codes.
