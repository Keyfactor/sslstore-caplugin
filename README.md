<h1 align="center" style="border-bottom: none">
    SSL Store AnyCA Gateway REST Plugin
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-production-3D1973?style=flat-square" alt="Integration Status: production" />
<a href="https://github.com/Keyfactor/sslstore-caplugin/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/sslstore-caplugin?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/sslstore-caplugin?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/sslstore-caplugin/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
</p>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a> 
  ·
  <a href="#requirements">
    <b>Requirements</b>
  </a>
  ·
  <a href="#installation">
    <b>Installation</b>
  </a>
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/orgs/Keyfactor/repositories?q=anycagateway">
    <b>Related Integrations</b>
  </a>
</p>


The SSL Store AnyCA Gateway REST plugin extends the capabilities of the SSL Store Certificate Authority Service to Keyfactor Command via the Keyfactor AnyCA Gateway. SSL Store is a certificate reseller providing access to 80+ certificate products from vendors including DigiCert, Sectigo, RapidSSL, GeoTrust, and Comodo through a single REST API. The plugin represents a fully featured AnyCA Plugin with the following capabilities:

* **CA Sync**:
    * Download all certificates issued through SSL Store
    * Full synchronization of all orders with paginated retrieval
    * Automatic extraction of end-entity certificates from certificate chains
    * Resilient retry logic (up to 5 retries) for large certificate inventories
* **Certificate Enrollment**:
    * Support for new certificate enrollment with CSR
    * Intelligent renewal vs. reissue logic based on configurable renewal window
    * Support for DV, OV, and EV certificate products
    * Multi-domain (MDC/SAN) and wildcard certificate support
    * Automatic domain validation with approver email verification
    * 80+ pre-configured certificate products across DigiCert and Sectigo families
* **Certificate Revocation**:
    * Request revocation of previously issued certificates via SSL Store refund request API

## Compatibility

The SSL Store AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 25.5 and later.

## Support
The SSL Store AnyCA Gateway REST plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket with your Keyfactor representative. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com. 

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Requirements

### SSL Store System Prerequisites

Before configuring the AnyCA Gateway plugin, ensure the following prerequisites are met:

1. **SSL Store Account**:
   - Active SSL Store partner account with API access enabled
   - Access to the SSL Store web-based API (WBAPI)
   - SSL Store account configured and operational

2. **API Credentials**:
   - SSL Store Partner Code
   - SSL Store Authentication Token
   - These credentials must have permissions for:
     - Certificate enrollment (new order submission)
     - Certificate download
     - Certificate revocation (refund request)
     - Order query and status retrieval
     - Email approver list retrieval

3. **Network Connectivity**:
   - Gateway server must have HTTPS access to the SSL Store API endpoint
   - Production endpoint: `https://wbapi.thesslstore.com`
   - Sandbox endpoint: `https://sandbox-wbapi.thesslstore.com`
   - TLS 1.2 or higher must be supported

### Obtaining Required Configuration Information

#### 1. SSL Store Base URL

The SSL Store Base URL is the root endpoint for the SSL Store REST API.

**Available environments:**
- Production: `https://wbapi.thesslstore.com`
- Sandbox/Testing: `https://sandbox-wbapi.thesslstore.com`

**To obtain your Base URL:**
1. Log in to your SSL Store partner portal
2. Determine whether you are using the production or sandbox environment
3. Verify the URL is accessible from the Gateway server

#### 2. API Authentication Credentials

The Gateway authenticates to SSL Store using a Partner Code and Authentication Token.

**Steps to obtain API credentials:**

1. **Access SSL Store Partner Portal**:
   - Log in to your SSL Store partner account
   - Navigate to API settings

2. **Obtain Credentials**:
   - **Partner Code**: Your unique partner identifier assigned by SSL Store
   - **Authentication Token**: A secret token for API authentication
   - Store these credentials securely

3. **Verify Permissions**:
   - Ensure the API credentials have permissions for:
     - Order creation (`/rest/order/neworder`)
     - Order reissue (`/rest/order/reissue`)
     - Order query (`/rest/order/query`)
     - Order status (`/rest/order/status`)
     - Certificate download (`/rest/order/download`)
     - Revocation/refund (`/rest/order/refundrequest`)
     - Email approver list (`/rest/order/approverlist`)

#### 3. Supported Certificate Products

The plugin supports 80+ certificate products from multiple vendors. Products are organized by validation type and vendor:

**DigiCert Products:**

| Product Code | Description | Validation |
|-------------|-------------|------------|
| `digi_securesite_flex` | DigiCert Secure Site | OV |
| `digi_securesite_flex-EO` | DigiCert Secure Site (Enterprise Org) | OV |
| `digi_securesite_ev_flex` | DigiCert Secure Site EV | EV |
| `digi_securesite_ev_flex-EO` | DigiCert Secure Site EV (Enterprise Org) | EV |
| `digi_securesite_pro_flex` | DigiCert Secure Site Pro | OV |
| `digi_securesite_pro_flex-EO` | DigiCert Secure Site Pro (Enterprise Org) | OV |
| `digi_securesite_pro_ev_flex` | DigiCert Secure Site Pro EV | EV |
| `digi_securesite_pro_ev_flex-EO` | DigiCert Secure Site Pro EV (Enterprise Org) | EV |
| `digi_sslwebserver_flex` | DigiCert SSL Web Server | OV |
| `digi_sslwebserver_flex-EO` | DigiCert SSL Web Server (Enterprise Org) | OV |
| `digi_sslwebserver_ev_flex` | DigiCert SSL Web Server EV | EV |
| `digi_sslwebserver_ev_flex-EO` | DigiCert SSL Web Server EV (Enterprise Org) | EV |
| `digi_truebizid_flex` | DigiCert TrueBizID | OV |
| `digi_truebizid_flex-EO` | DigiCert TrueBizID (Enterprise Org) | OV |
| `digi_truebizid_ev_flex` | DigiCert TrueBizID EV | EV |
| `digi_truebizid_ev_flex-EO` | DigiCert TrueBizID EV (Enterprise Org) | EV |
| `digi_ssl_basic` | DigiCert Basic SSL | OV |
| `digi_ssl_basic-EO` | DigiCert Basic SSL (Enterprise Org) | OV |
| `digi_ssl_ev_basic` | DigiCert Basic SSL EV | EV |
| `digi_ssl_ev_basic-EO` | DigiCert Basic SSL EV (Enterprise Org) | EV |
| `digi_rapidssl` | RapidSSL | DV |
| `digi_rapidssl_wc` | RapidSSL Wildcard | DV |
| `digi_ssl_dv_geotrust_flex` | GeoTrust DV SSL | DV |
| `digi_ssl123_flex` | GeoTrust SSL123 | DV |
| `digi_quickssl_md` | DigiCert QuickSSL Multi-Domain | DV |
| `digi_client_premium` | DigiCert Client Premium | Client |
| `digi_csc` | DigiCert Code Signing | Code Signing |
| `digi_csc_ev` | DigiCert EV Code Signing | EV Code Signing |
| `digi_doc_signing_ind_500` | DigiCert Document Signing Individual 500 | Document Signing |
| `digi_doc_signing_ind_2000` | DigiCert Document Signing Individual 2000 | Document Signing |
| `digi_doc_signing_org_2000` | DigiCert Document Signing Organization 2000 | Document Signing |
| `digi_doc_signing_org_5000` | DigiCert Document Signing Organization 5000 | Document Signing |

**Sectigo/Comodo Products:**

| Product Code | Description | Validation |
|-------------|-------------|------------|
| `positivessl` | Positive SSL | DV |
| `positivesslwildcard` | Positive SSL Wildcard | DV |
| `positivemdcssl` | Positive SSL Multi-Domain | DV |
| `positivemdcwildcard` | Positive SSL MDC Wildcard | DV |
| `positiveevssl` | Positive EV SSL | EV |
| `positiveevmdc` | Positive EV Multi-Domain | EV |
| `sectigossl` | Sectigo SSL | DV |
| `sectigowildcard` | Sectigo Wildcard | DV |
| `sectigoovssl` | Sectigo OV SSL | OV |
| `sectigoovwildcard` | Sectigo OV Wildcard | OV |
| `sectigoevssl` | Sectigo EV SSL | EV |
| `sectigodvucc` | Sectigo DV UCC | DV |
| `sectigouccwildcard` | Sectigo UCC Wildcard | DV |
| `sectigomdc` | Sectigo Multi-Domain | OV |
| `sectigomdcwildcard` | Sectigo MDC Wildcard | OV |
| `sectigoevmdc` | Sectigo EV Multi-Domain | EV |
| `comodopremiumssl` | Comodo Premium SSL | OV |
| `comodopremiumwildcard` | Comodo Premium Wildcard | OV |
| `comodossl` | Comodo SSL | OV |
| `comodoevssl` | Comodo EV SSL | EV |
| `comodomdc` | Comodo Multi-Domain | OV |
| `comodomdcwildcard` | Comodo MDC Wildcard | OV |
| `comodoevmdc` | Comodo EV Multi-Domain | EV |
| `comodoucc` | Comodo UCC | OV |
| `comodouccwildcard` | Comodo UCC Wildcard | OV |
| `comodowildcard` | Comodo Wildcard | OV |
| `comodocsc` | Comodo Code Signing | Code Signing |
| `comodoevcsc` | Comodo EV Code Signing | EV Code Signing |
| `comododvucc` | Comodo DV UCC | DV |
| `comodopciscan` | Comodo PCI Scan | Scanning |
| `instantssl` | InstantSSL | OV |
| `instantsslpro` | InstantSSL Pro | OV |
| `enterprisepro` | Enterprise Pro SSL | OV |
| `enterpriseprowc` | Enterprise Pro Wildcard | OV |
| `enterpriseproev` | Enterprise Pro EV | EV |
| `enterpriseproevmdc` | Enterprise Pro EV Multi-Domain | EV |
| `enterprisessl` | Enterprise SSL | OV |
| `essentialssl` | Essential SSL | DV |
| `essentialwildcard` | Essential Wildcard | DV |
| `elitessl` | Elite SSL | OV |

**Note:** Products with the `-EO` suffix are Enterprise Organization variants that use a pre-configured DigiCert organization instead of requiring organization details during enrollment. These products require only a Validity Period and Organization ID.

#### 4. Certificate Validity Configuration

Certificate validity is specified in days during enrollment and automatically converted to months for the SSL Store API:

| Days | Months |
|------|--------|
| 90 | 3 |
| 180 | 6 |
| 365 | 12 |
| 730 | 24 |
| 1095 | 36 |

#### 5. Renewal vs. Reissue Logic

The plugin uses a configurable **Renewal Window** (default: 30 days) to determine behavior during certificate renewal:

- If the existing order is **within** the renewal window (i.e., expiring within N days), the plugin performs a **renewal** (new order linked to the original)
- If the existing order is **outside** the renewal window (still has significant life remaining), the plugin performs a **reissue** on the same order

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [SSL Store AnyCA Gateway REST plugin](https://github.com/Keyfactor/sslstore-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0` or `net8.0`) to the Extensions directory:


    ```shell
    Depending on your AnyCA Gateway REST version, copy the unzipped directory to one of the following locations:
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net8.0\Extensions
    ```

    > The directory containing the SSL Store AnyCA Gateway REST plugin DLLs (`net6.0` or `net8.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the SSL Store plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Configuration

1. Follow the [official AnyCA Gateway REST documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) to define a new Certificate Authority, and use the notes below to configure the **Gateway Registration** and **CA Connection** tabs:

    * **Gateway Registration**

        ### CA Connection Configuration

        When registering the SSL Store CA in the AnyCA Gateway, you'll need to provide the following configuration parameters:

        | Parameter | Description | Required | Default |
        |-----------|-------------|----------|---------|
        | **SSLStoreURL** | Full URL to the SSL Store API endpoint | Yes | `https://sandbox-wbapi.thesslstore.com` |
        | **PartnerCode** | Partner Code obtained from SSL Store | Yes | |
        | **AuthToken** | Authentication Token obtained from SSL Store | Yes | |
        | **PageSize** | Number of records per page during synchronization | No | `100` |
        | **Enabled** | Flag to Enable or Disable the CA connector | No | `true` |
        | **RenewalWindow** | Days before order expiry to trigger renewal vs. reissue | No | `30` |

        ### Gateway Registration Notes

        - Each defined Certificate Authority in the AnyCA Gateway REST can support one SSL Store API endpoint
        - If you have multiple SSL Store environments (production/sandbox), define separate Certificate Authorities for each
        - Each CA configuration will manifest in Command as a separate CA entry
        - The plugin uses REST API authentication with Partner Code and Authentication Token
        - The plugin automatically handles:
          - Product discovery (80+ products)
          - Certificate status mapping (Active, Pending, Cancelled)
          - End-entity certificate extraction from certificate chains
          - Paginated order synchronization with retry logic

        ### Security Considerations

        1. **Credential Storage**: The AuthToken field is configured as a secret/hidden field and should be stored securely
        2. **Network Security**: Ensure TLS/SSL is properly configured for all API communications
        3. **Least Privilege**: Request API credentials with minimal required permissions
        4. **Audit Logging**: Enable comprehensive logging in both the Gateway and SSL Store for security monitoring
        5. **Credential Rotation**: Regularly rotate API credentials according to your security policy
        6. **Sandbox Testing**: Use the sandbox endpoint (`https://sandbox-wbapi.thesslstore.com`) for initial configuration and testing before switching to production

        ### CA Connection Fields

        Populate using the configuration fields collected in the [requirements](#requirements) section.

        * **SSLStoreURL** - The base URL for the SSL Store API endpoint. Use `https://wbapi.thesslstore.com` for production or `https://sandbox-wbapi.thesslstore.com` for testing.
        * **PartnerCode** - The Partner Code obtained from your SSL Store partner account.
        * **AuthToken** - The Authentication Token obtained from your SSL Store partner account.
        * **PageSize** - Number of records to retrieve per page during certificate synchronization. Default is 100.
        * **Enabled** - Flag to enable or disable the CA connector. Set to `true` to enable.
        * **RenewalWindow** - Number of days before an order's expiration date to trigger a renewal (new order) instead of a reissue (same order). Default is 30 days.

    * **CA Connection**

        Populate using the configuration fields collected in the [requirements](#requirements) section.

        * **SSLStoreURL** - The Base URL for the SSL Store API endpoint (e.g. https://sandbox-wbapi.thesslstore.com). 
        * **PartnerCode** - The Partner Code obtained from SSL Store. 
        * **AuthToken** - The Authentication Token obtained from SSL Store. 
        * **PageSize** - The number of records to return per page during synchronization. 
        * **Enabled** - Flag to Enable or Disable the CA connector. 
        * **RenewalWindow** - Number of days before order expiry to trigger a renewal instead of a reissue. 

2. ### Template (Product) Configuration

    After adding the CA to the Gateway, certificate templates are automatically discovered from the plugin's built-in product registry. Each template may require different enrollment fields depending on the product type and validation level.

    **Enrollment fields vary by product type. The following categories exist:**

    #### DV Products (Minimal Fields)

    Products like `positivessl`, `sectigossl`, `sectigowildcard`:

    | Parameter | Description | Required |
    |-----------|-------------|----------|
    | **Admin Contact - Email** | Administrative contact email | Yes |
    | **Approver Email** | Domain validation approver email | Yes |
    | **Validity Period (In Days)** | Certificate validity in days | Yes |

    #### OV Products (Organization Fields)

    Products like `sectigoovssl`, `comodopremiumssl`, `instantssl`:

    | Parameter | Description | Required |
    |-----------|-------------|----------|
    | **Admin Contact - Email** | Administrative contact email | Yes |
    | **Approver Email** | Domain validation approver email | Yes |
    | **Validity Period (In Days)** | Certificate validity in days | Yes |
    | **Organization Name** | Organization name | Yes |
    | **Organization Address** | Organization street address | Yes |
    | **Organization State/Province** | Organization state or province | Yes |
    | **Organization Postal Code** | Organization postal/zip code | Yes |
    | **Organization Country** | Two-letter country code (e.g. US) | Yes |
    | **Organization Phone** | Organization phone number | Yes |

    #### DigiCert OV Flex Products

    Products like `digi_securesite_flex`, `digi_sslwebserver_flex`, `digi_truebizid_flex`:

    | Parameter | Description | Required |
    |-----------|-------------|----------|
    | **Admin Contact - First Name** | Administrative contact first name | Yes |
    | **Admin Contact - Last Name** | Administrative contact last name | Yes |
    | **Admin Contact - Phone** | Administrative contact phone | Yes |
    | **Admin Contact - Email** | Administrative contact email | Yes |
    | **Approver Email** | Domain validation approver email | Yes |
    | **Validity Period (In Days)** | Certificate validity in days | Yes |
    | **Organization Name** | Organization name | Yes |
    | **Organization Address** | Organization street address | Yes |
    | **Organization City** | Organization city | Yes |
    | **Organization State/Province** | Organization state or province | Yes |
    | **Organization Postal Code** | Organization postal/zip code | Yes |
    | **Organization Country** | Two-letter country code | Yes |
    | **Organization Phone** | Organization phone number | Yes |

    #### DigiCert EV Flex Products

    Products like `digi_securesite_ev_flex`, `digi_ssl_ev_basic`, `digi_truebizid_ev_flex`:

    Same as DigiCert OV Flex, plus:

    | Parameter | Description | Required |
    |-----------|-------------|----------|
    | **Admin Contact - Title** | Administrative contact job title | Yes |

    #### Enterprise Organization (-EO) Products

    Products like `digi_securesite_flex-EO`, `digi_sslwebserver_ev_flex-EO`:

    | Parameter | Description | Required |
    |-----------|-------------|----------|
    | **Validity Period (In Days)** | Certificate validity in days | Yes |
    | **Organization ID** | DigiCert Organization ID | Yes |

    #### EV Products with Jurisdiction

    Products like `enterpriseproev`, `positiveevssl`, `positiveevmdc`:

    Same as OV Products, plus:

    | Parameter | Description | Required |
    |-----------|-------------|----------|
    | **Organization Jurisdiction Country** | Jurisdiction country code for EV validation | Yes |

    ### Domain Validation - Approver Emails

    The plugin validates approver emails against SSL Store's approved list for each domain before enrollment:

    - **DigiCert products**: Exactly one approver email is required and must be from the approved list
    - **Sectigo/Comodo products**: At least one approver email must be from the approved list
    - Emails are validated per-domain for multi-domain certificates

    ### Important Notes

    - Product IDs are automatically registered from the plugin's built-in product registry
    - The `Validity Period (In Days)` is automatically converted to months for the SSL Store API
    - For `-EO` (Enterprise Organization) products, the Organization ID dropdown is populated from your DigiCert account's active organizations
    - DNS names (SANs) are extracted from the Keyfactor enrollment request; they do not need to be provided as a separate enrollment field
    - The Common Name (CN) is extracted from the CSR subject

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.

4. In Keyfactor Command (v12.3+), for each imported Certificate Template, follow the [official documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Configuring%20Template%20Options.htm) to define enrollment fields for each of the following parameters:

    * **Approver Email** - Comma-separated approver email address(es) for domain validation. 
    * **Validity Period (In Days)** - Certificate validity period in days (e.g. 90, 365, 730). 
    * **Admin Contact - First Name** - Administrative contact first name. 
    * **Admin Contact - Last Name** - Administrative contact last name. 
    * **Admin Contact - Phone** - Administrative contact phone number. 
    * **Admin Contact - Email** - Administrative contact email address. 
    * **Admin Contact - Title** - Administrative contact job title. 
    * **Admin Contact - Organization Name** - Administrative contact organization name. 
    * **Admin Contact - Address** - Administrative contact street address. 
    * **Admin Contact - City** - Administrative contact city. 
    * **Admin Contact - Region** - Administrative contact state/province/region. 
    * **Admin Contact - Postal Code** - Administrative contact postal/zip code. 
    * **Admin Contact - Country** - Administrative contact two-letter country code (e.g. US). 
    * **Technical Contact - First Name** - Technical contact first name. 
    * **Technical Contact - Last Name** - Technical contact last name. 
    * **Technical Contact - Phone** - Technical contact phone number. 
    * **Technical Contact - Email** - Technical contact email address. 
    * **Technical Contact - Organization Name** - Technical contact organization name. 
    * **Technical Contact - Address** - Technical contact street address. 
    * **Technical Contact - City** - Technical contact city. 
    * **Technical Contact - Region** - Technical contact state/province/region. 
    * **Technical Contact - Postal Code** - Technical contact postal/zip code. 
    * **Technical Contact - Country** - Technical contact two-letter country code (e.g. US). 
    * **Organization Name** - Organization name for the certificate. 
    * **Organization Address** - Organization street address. 
    * **Organization City** - Organization city. 
    * **Organization Region** - Organization state/province/region. 
    * **Organization State/Province** - Organization state or province. 
    * **Organization Postal Code** - Organization postal/zip code. 
    * **Organization Country** - Organization two-letter country code (e.g. US). 
    * **Organization Phone** - Organization phone number. 
    * **Organization Jurisdiction Country** - Jurisdiction country code for EV certificates. 
    * **Organization ID** - DigiCert organization ID for EO (Enterprise Organization) products. 
    * **Server Count** - Number of server licenses for the certificate. 
    * **Web Server Type** - Web server type (e.g. apacheopenssl, iis, tomcat, Other). 
    * **Signature Hash Algorithm** - Signature hash algorithm (PREFER_SHA2, REQUIRE_SHA2, PREFER_SHA1). 
    * **File Auth Domain Validation** - Use file-based domain validation (True/False). 
    * **CName Auth Domain Validation** - Use CNAME-based domain validation (True/False). 
    * **Is CU Order?** - Is this a CU (Customer) order (True/False). 
    * **Is Renewal Order?** - Is this a renewal order (True/False). 
    * **Is Trial Order?** - Is this a trial order (True/False). 


## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [SSL Store AnyCA Gateway REST plugin](https://github.com/Keyfactor/sslstore-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0` or `net8.0`) to the Extensions directory:

    ```shell
    Depending on your AnyCA Gateway REST version, copy the unzipped directory to one of the following locations:
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net8.0\Extensions
    ```

    > The directory containing the SSL Store AnyCA Gateway REST plugin DLLs (`net6.0` or `net8.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the SSL Store plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.


## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).