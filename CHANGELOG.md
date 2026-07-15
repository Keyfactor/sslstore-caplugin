# v2.1.0
* Added support for the generic DNS provider plugin framework (Keyfactor.AnyGateway.IAnyCAPlugin 3.3.0)
* Automated DNS (CNAME) domain control validation: when enabled, the plugin requests CNAME-based
  validation from SSL Store and publishes the returned record via the DNS provider plugin resolved
  by the AnyCA Gateway (Azure, Route53, Cloudflare, Google, NS1, Infoblox, RFC2136, etc.)
* Verifies public DNS propagation of the validation record before returning (configurable attempts/delay)
* Best-effort cleanup of DNS validation records once an order is issued (GetSingleRecord/Synchronize)
* New CA-connection settings: `DnsValidationEnabled`, `DnsVerificationServer`, `DnsPropagationMaxAttempts`, `DnsPropagationDelaySeconds`
* CNAME is the intrinsic DCV method for SSL Store; the DNS record type is determined by the CNAME
  validator you map to each domain in the gateway's Domain Validation configuration (no CA-connection knob)
* Email approver validation remains the default when DNS validation is disabled
* Revoked (Cancelled) orders now download and store the actual certificate; orders with no
  downloadable certificate are skipped instead of storing empty cert bytes (which previously
  crashed the gateway certificate search with "m_safeCertContext is an invalid handle")
* Added FlowLogger step tracing and expanded operational logging across all plugin operations

# v2.0.0
* Converted from AnyCA Gateway (DB) to AnyCA Gateway REST plugin architecture
* Migrated from CAProxy.AnyGateway (BaseCAConnector) to IAnyCAPlugin interface
* Fully async operations throughout (no more Task.Run().Result blocking)
* Self-describing plugin configuration with annotations (no external template JSON files)
* Built-in product registry with 80+ certificate products
* Smart renewal vs. reissue logic with configurable renewal window
* Uses CustomOrderId for stable order tracking
* End-entity certificate extraction using X509Utilities.ExtractEndEntityCertificateContents
* GetSingleRecord now downloads and returns the actual certificate
* Connection validation with required field checks
* Enable/disable toggle for CA connector lifecycle management
* Removed Keyfactor API client dependency (no more direct template updates)

# v1.1.1
* SSL Store Api Changed Encoding Rules, needed to fix integration to match

# v1.1.0
* Added new AutoWWW field for single domain SSL Store products

# v1.0.4
* Original Release Version
