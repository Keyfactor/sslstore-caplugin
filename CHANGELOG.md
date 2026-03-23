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
