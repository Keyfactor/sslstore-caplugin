# v2.1.0
* Added support for the generic DNS provider plugin framework (Keyfactor.AnyGateway.IAnyCAPlugin 3.3.0)
* Automated DNS (CNAME) domain control validation: when enabled, the plugin requests CNAME-based
  validation from SSL Store and publishes the returned record via the DNS provider plugin resolved
  by the AnyCA Gateway (Azure, Route53, Cloudflare, Google, NS1, Infoblox, RFC2136, etc.)
* Verifies public DNS propagation of the validation record before returning
* Best-effort cleanup of DNS validation records once an order is issued (GetSingleRecord/Synchronize)
* New CA-connection settings: `DnsValidationEnabled`, `DnsValidationType`, `DnsVerificationServer`
* Email approver validation remains the default when DNS validation is disabled

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
