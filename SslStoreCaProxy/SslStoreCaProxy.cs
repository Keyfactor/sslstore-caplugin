using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.AnyGateway.SslStore.Client;
using Keyfactor.AnyGateway.SslStore.Client.Models;
using Keyfactor.AnyGateway.SslStore.Interfaces;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Linq;
using Keyfactor.PKI.X509;
using Keyfactor.AnyGateway.SslStore.Clients.DNS;
using DnsClient;


namespace Keyfactor.AnyGateway.SslStore
{
    public class SslStoreCaProxy : IAnyCAPlugin
    {
        private static readonly ILogger _logger = LogHandler.GetClassLogger<SslStoreCaProxy>();
        private RequestManager _requestManager;
        private IAnyCAPluginConfigProvider Config { get; set; }
        private ICertificateDataReader _certDataReader;
        private SslStoreCAPluginConfig.Config _config;
        private readonly IDomainValidatorFactory _validatorFactory;

        public string PartnerCode { get; set; }
        public string AuthenticationToken { get; set; }
        public int PageSize { get; set; }
        public int RenewalWindow { get; set; }

        /// <summary>
        /// Constructor. The AnyCA Gateway platform injects an <see cref="IDomainValidatorFactory"/>
        /// used to resolve DNS provider plugins for automated (CNAME) domain control validation.
        /// The factory is only required when DNS validation is enabled in the CA configuration.
        /// </summary>
        public SslStoreCaProxy(IDomainValidatorFactory validatorFactory)
        {
            _validatorFactory = validatorFactory;
        }

        public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
        {
            _logger.MethodEntry();
            using var flow = new FlowLogger(_logger, "Initialize");
            try
            {
                flow.Step("ReadConfigProvider", () =>
                {
                    _certDataReader = certificateDataReader;
                    Config = configProvider;
                });

                flow.Step("DeserializeConnectionData", () =>
                {
                    var rawData = JsonConvert.SerializeObject(configProvider.CAConnectionData);
                    _config = JsonConvert.DeserializeObject<SslStoreCAPluginConfig.Config>(rawData);
                });

                flow.Step("ApplyConfig", () =>
                {
                    PartnerCode = _config.PartnerCode;
                    AuthenticationToken = _config.AuthToken;
                    PageSize = _config.PageSize > 0 ? _config.PageSize : SslStoreCAPluginConfig.DefaultPageSize;
                    RenewalWindow = _config.RenewalWindow > 0 ? _config.RenewalWindow : 30;
                }, $"PageSize={PageSize}, RenewalWindow={RenewalWindow}");

                flow.Step("CreateRequestManager", () => _requestManager = new RequestManager(this));

                _logger.LogInformation(
                    "SslStore CAPlugin initialized. Enabled={Enabled}, SSLStoreURL={Url}, PartnerCode set={HasPartner}, AuthToken set={HasToken}, PageSize={PageSize}, RenewalWindow={RenewalWindow}, DnsValidationEnabled={DnsEnabled}, DnsValidationType={DnsType}, DnsVerificationServer={DnsServer}, DnsPropagationMaxAttempts={DnsAttempts}, DnsPropagationDelaySeconds={DnsDelay}, DomainValidatorFactory available={HasFactory}",
                    _config.Enabled, _config.SSLStoreURL, !string.IsNullOrEmpty(_config.PartnerCode), !string.IsNullOrEmpty(_config.AuthToken),
                    PageSize, RenewalWindow, _config.DnsValidationEnabled, _config.DnsValidationType,
                    string.IsNullOrEmpty(_config.DnsVerificationServer) ? "(public resolvers)" : _config.DnsVerificationServer,
                    _config.DnsPropagationMaxAttempts, _config.DnsPropagationDelaySeconds, _validatorFactory != null);
            }
            catch (Exception ex)
            {
                flow.Fail("Initialize", ex.Message);
                _logger.LogError(ex, "Failed to initialize SslStore CAPlugin");
                throw;
            }
            finally
            {
                _logger.MethodExit();
            }
        }

        public async Task Ping()
        {
            _logger.MethodEntry();
            if (!_config.Enabled)
            {
                _logger.LogWarning("The CA is currently in the Disabled state. Skipping connectivity test...");
                _logger.MethodExit();
                return;
            }
            _logger.LogDebug("Pinging SslStore to validate connection");
            _logger.MethodExit();
        }

        public Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
        {
            _logger.MethodEntry();
            _logger.LogDebug("Validating SslStore CA Connection properties");
            var rawData = JsonConvert.SerializeObject(connectionInfo);
            var config = JsonConvert.DeserializeObject<SslStoreCAPluginConfig.Config>(rawData);

            if (!config.Enabled)
            {
                _logger.LogWarning("The CA is currently in the Disabled state. Skipping config validation...");
                _logger.MethodExit();
                return Task.CompletedTask;
            }

            List<string> missingFields = new List<string>();
            if (string.IsNullOrEmpty(config.SSLStoreURL)) missingFields.Add(nameof(config.SSLStoreURL));
            if (string.IsNullOrEmpty(config.PartnerCode)) missingFields.Add(nameof(config.PartnerCode));
            if (string.IsNullOrEmpty(config.AuthToken)) missingFields.Add(nameof(config.AuthToken));

            if (missingFields.Count > 0)
            {
                throw new ArgumentException($"The following required fields are missing or empty: {string.Join(", ", missingFields)}");
            }

            _config = config;
            _logger.MethodExit();
            return Ping();
        }

        public Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
        {
            _logger.MethodEntry();
            _logger.MethodExit();
            return Task.CompletedTask;
        }

        public List<string> GetProductIds()
        {
            return ProductDefinitions.GetProductIds();
        }

        public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
        {
            _logger.MethodEntry();
            _logger.MethodExit();
            return SslStoreCAPluginConfig.GetPluginAnnotations();
        }

        public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            _logger.MethodEntry();
            _logger.MethodExit();
            return SslStoreCAPluginConfig.GetTemplateParameterAnnotations();
        }

        public async Task<int> Revoke(string caRequestId, string hexSerialNumber, uint revocationReason)
        {
            _logger.MethodEntry();
            _logger.LogInformation("Revoke requested for CARequestID '{CaRequestId}', serial '{Serial}', reason {Reason}",
                caRequestId ?? "(null)", hexSerialNumber ?? "(null)", revocationReason);
            using var flow = new FlowLogger(_logger, $"Revoke({caRequestId ?? "null"})");

            var sslStoreOrderId = ParseSslStoreOrderId(caRequestId);
            RevokeOrderRequest revokeOrderRequest;
            if (sslStoreOrderId != null)
            {
                flow.Step("BuildRevokeRequest", $"by SSLStoreOrderId={sslStoreOrderId}");
                revokeOrderRequest = _requestManager.GetRevokeOrderRequestBySslStoreId(sslStoreOrderId);
            }
            else
            {
                flow.Step("BuildRevokeRequest", $"legacy CustomOrderId={caRequestId}");
                revokeOrderRequest = _requestManager.GetRevokeOrderRequest(caRequestId);
            }
            _logger.LogTrace($"Revoke Request JSON {JsonConvert.SerializeObject(revokeOrderRequest)}");
            try
            {
                var client = new SslStoreClient(Config);
                IOrderStatusResponse requestResponse = null;
                await flow.StepAsync("SubmitRevokeToSslStore",
                    async () => requestResponse = await client.SubmitRevokeCertificateAsync(revokeOrderRequest));

                _logger.LogTrace($"Revoke Response JSON {JsonConvert.SerializeObject(requestResponse)}");

                if (requestResponse.AuthResponse.IsError)
                {
                    var msg = requestResponse.AuthResponse.Message != null ? string.Join("; ", requestResponse.AuthResponse.Message) : "(no message)";
                    flow.Fail("RevokeResult", msg);
                    _logger.LogError("Revoke error for CARequestID '{CaRequestId}': {Message}", caRequestId, msg);
                    return (int)EndEntityStatus.FAILED;
                }

                flow.Step("RevokeResult", "REVOKED");
                _logger.LogInformation("Revoke succeeded for CARequestID '{CaRequestId}'", caRequestId);
                return (int)EndEntityStatus.REVOKED;
            }
            catch (Exception e)
            {
                flow.Fail("UNHANDLED", e.Message);
                _logger.LogError(e, "An error has occurred during the revoke process for CARequestID '{CaRequestId}'", caRequestId);
                return (int)EndEntityStatus.FAILED;
            }
            finally
            {
                _logger.MethodExit();
            }
        }

        public async Task<EnrollmentResult> Enroll(string csr, string subject, Dictionary<string, string[]> san,
            EnrollmentProductInfo productInfo, RequestFormat requestFormat, EnrollmentType enrollmentType)
        {
            _logger.MethodEntry();
            _logger.LogInformation(
                "Enroll requested. Type={EnrollmentType}, ProductID={ProductId}, Subject='{Subject}', SAN dns count={SanCount}, RequestFormat={RequestFormat}",
                enrollmentType, productInfo?.ProductID, subject,
                san != null && san.ContainsKey("dns") ? san["dns"].Length : 0, requestFormat);
            using var flow = new FlowLogger(_logger, $"Enroll-{enrollmentType}");
            var client = new SslStoreClient(Config);

            try
            {
                INewOrderResponse enrollmentResponse = null;

                if (enrollmentType == EnrollmentType.New)
                {
                    flow.Branch("NewEnrollment");
                    _logger.LogTrace("Entering New Enrollment");

                    if (!productInfo.ProductParameters.ContainsKey("PriorCertSN"))
                    {
                        // Extract domain name from CSR subject and SANs from the Keyfactor san parameter
                        var domainName = subject?.Split(',')
                            .Select(p => p.Trim())
                            .Where(p => p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                            .Select(p => p.Substring(3))
                            .FirstOrDefault() ?? "";
                        _logger.LogTrace($"Domain Name from subject: {domainName}");

                        var dnsNames = san != null && san.ContainsKey("dns") ? san["dns"] : Array.Empty<string>();
                        _logger.LogTrace($"DNS Names from SAN: {string.Join(",", dnsNames)}");

                        var useDnsValidation = ResolveUseDnsValidation(productInfo);
                        flow.Step("ResolveValidationMethod", useDnsValidation ? "CNAME/DNS" : "Email approver");
                        _logger.LogInformation("Enroll new order for CN '{Domain}' with {SanCount} SAN(s); DNS DCV enabled={UseDns}",
                            domainName, dnsNames.Length, useDnsValidation);

                        if (!useDnsValidation)
                        {
                            flow.Branch("EmailApproverValidation");
                            string[] arrayApproverEmails = Array.Empty<string>();
                            if (productInfo.ProductParameters.ContainsKey("Approver Email"))
                            {
                                _logger.LogTrace($"Approver Email {productInfo.ProductParameters["Approver Email"]}");
                                arrayApproverEmails = productInfo.ProductParameters["Approver Email"].Split(new char[] { ',' });
                            }

                            // Validate approver emails against all domains (CN + SANs)
                            var allDomains = new List<string>();
                            if (!string.IsNullOrEmpty(domainName)) allDomains.Add(domainName);
                            allDomains.AddRange(dnsNames.Where(d => !string.Equals(d, domainName, StringComparison.OrdinalIgnoreCase)));
                            _logger.LogTrace($"Validating approver emails against {allDomains.Count} domain(s): {string.Join(", ", allDomains)}");

                            var count = 1;
                            foreach (var domain in allDomains)
                            {
                                var emailApproverRequest = _requestManager.GetEmailApproverListRequest(productInfo.ProductID, domain);
                                _logger.LogTrace($"Email Approver Request JSON {JsonConvert.SerializeObject(emailApproverRequest)}");

                                EmailApproverResponse emailApproverResponse = null;
                                await flow.StepAsync($"FetchApproverEmails[{domain}]",
                                    async () => emailApproverResponse = await client.SubmitEmailApproverRequestAsync(emailApproverRequest));
                                _logger.LogTrace($"Email Approver Response JSON {JsonConvert.SerializeObject(emailApproverResponse)}");

                                var emailValidation = ValidateEmails(emailApproverResponse, arrayApproverEmails, productInfo, count);
                                _logger.LogTrace($"Email Validation Result {emailValidation}");

                                if (emailValidation.Length > 0)
                                {
                                    flow.Fail($"ValidateApproverEmail[{domain}]", emailValidation);
                                    _logger.LogError("Approver email validation failed for '{Domain}': {Message}", domain, emailValidation);
                                    return new EnrollmentResult
                                    {
                                        Status = (int)EndEntityStatus.FAILED,
                                        StatusMessage = emailValidation
                                    };
                                }
                                flow.Step($"ValidateApproverEmail[{domain}]", "OK");
                                count++;
                            }
                            flow.EndBranch();
                        }

                        var enrollmentRequest = _requestManager.GetEnrollmentRequest(csr, subject, san, productInfo, Config, false, useDnsValidation);
                        _logger.LogTrace($"enrollmentRequest JSON {JsonConvert.SerializeObject(enrollmentRequest)}");

                        await flow.StepAsync("SubmitNewOrderToSslStore",
                            async () => enrollmentResponse = await client.SubmitNewOrderRequestAsync(enrollmentRequest));
                        _logger.LogTrace($"enrollmentResponse JSON {JsonConvert.SerializeObject(enrollmentResponse)}");
                        _logger.LogInformation("New order submitted. SSLStoreOrderId={OrderId}, PartnerOrderId={PartnerId}, IsError={IsError}",
                            enrollmentResponse?.TheSslStoreOrderId, enrollmentResponse?.PartnerOrderId, enrollmentResponse?.AuthResponse?.IsError);

                        if (useDnsValidation && enrollmentResponse != null && !(enrollmentResponse.AuthResponse?.IsError ?? false))
                        {
                            string dnsError = null;
                            await flow.StepAsync("StageDnsValidation",
                                async () => dnsError = await StageDnsValidationAsync(enrollmentResponse, domainName));
                            if (!string.IsNullOrEmpty(dnsError))
                            {
                                flow.Fail("StageDnsValidation", dnsError);
                                return new EnrollmentResult
                                {
                                    Status = (int)EndEntityStatus.FAILED,
                                    StatusMessage = dnsError
                                };
                            }
                        }
                        flow.EndBranch();
                    }
                    else
                    {
                        flow.Fail("RejectExpiredRenew", "PriorCertSN present on New enrollment");
                        _logger.LogWarning("Rejecting New enrollment: PriorCertSN present (expired cert cannot be renewed via New).");
                        return new EnrollmentResult
                        {
                            Status = (int)EndEntityStatus.FAILED,
                            StatusMessage = "You cannot renew an expired cert please perform a new enrollment."
                        };
                    }
                }
                else if (enrollmentType == EnrollmentType.RenewOrReissue)
                {
                    flow.Branch("RenewOrReissue");
                    _logger.LogTrace("Entering Renew/Reissue Logic...");

                    var sn = productInfo.ProductParameters["PriorCertSN"];
                    _logger.LogTrace($"Prior Cert Serial Number: {sn}");

                    var caRequestId = await _certDataReader.GetRequestIDBySerialNumber(sn);
                    flow.Step("LookupPriorRequestId", $"SN={sn} -> {caRequestId}");
                    _logger.LogTrace($"Prior CA Request ID: {caRequestId}");

                    var priorSslStoreOrderId = ParseSslStoreOrderId(caRequestId);
                    OrderStatusRequest orderStatusRequest;
                    if (priorSslStoreOrderId != null)
                    {
                        _logger.LogTrace($"Parsed TheSSLStoreOrderID: {priorSslStoreOrderId}");
                        orderStatusRequest = _requestManager.GetOrderStatusRequestBySslStoreId(priorSslStoreOrderId);
                    }
                    else
                    {
                        _logger.LogTrace($"Legacy GUID format, querying by CustomOrderId: {caRequestId}");
                        orderStatusRequest = _requestManager.GetOrderStatusRequest(caRequestId);
                    }
                    _logger.LogTrace($"orderStatusRequest JSON {JsonConvert.SerializeObject(orderStatusRequest)}");

                    INewOrderResponse orderStatusResponse = null;
                    await flow.StepAsync("FetchPriorOrderStatus",
                        async () => orderStatusResponse = await client.SubmitOrderStatusRequestAsync(orderStatusRequest));
                    _logger.LogTrace($"orderStatusResponse JSON {JsonConvert.SerializeObject(orderStatusResponse)}");

                    // Determine renewal vs reissue based on order expiry and RenewalWindow
                    var shouldRenew = false;
                    if (DateTime.TryParse(orderStatusResponse.OrderExpiryDateInUtc, out var orderExpiry))
                    {
                        var daysUntilOrderExpiry = (orderExpiry - DateTime.UtcNow).TotalDays;
                        _logger.LogTrace($"Order expiry: {orderExpiry:u}, days remaining: {daysUntilOrderExpiry:F0}, renewal window: {RenewalWindow} days");
                        shouldRenew = daysUntilOrderExpiry <= RenewalWindow;
                        flow.Step("EvaluateRenewalWindow", $"daysRemaining={daysUntilOrderExpiry:F0}, window={RenewalWindow} -> {(shouldRenew ? "renew" : "reissue")}");
                    }
                    else
                    {
                        _logger.LogWarning($"Could not parse OrderExpiryDateInUTC '{orderStatusResponse.OrderExpiryDateInUtc}', defaulting to renewal");
                        flow.Step("EvaluateRenewalWindow", "unparseable expiry -> defaulting to renew");
                        shouldRenew = true;
                    }

                    if (shouldRenew)
                    {
                        _logger.LogInformation("Order is within renewal window, performing renewal (new order).");
                        var renewRequest = _requestManager.GetRenewalRequest(orderStatusResponse, csr);
                        _logger.LogTrace($"renewRequest JSON {JsonConvert.SerializeObject(renewRequest)}");

                        await flow.StepAsync("SubmitRenewalToSslStore",
                            async () => enrollmentResponse = await client.SubmitRenewRequestAsync(renewRequest));
                        _logger.LogTrace($"enrollmentResponse JSON {JsonConvert.SerializeObject(enrollmentResponse)}");
                    }
                    else
                    {
                        _logger.LogInformation("Order has life remaining, performing reissue (same order).");
                        var reIssueRequest = _requestManager.GetReIssueRequest(orderStatusResponse, csr, false);
                        _logger.LogTrace($"reIssueRequest JSON {JsonConvert.SerializeObject(reIssueRequest)}");

                        await flow.StepAsync("SubmitReissueToSslStore",
                            async () => enrollmentResponse = await client.SubmitReIssueRequestAsync(reIssueRequest));
                        _logger.LogTrace($"reissue enrollmentResponse JSON {JsonConvert.SerializeObject(enrollmentResponse)}");
                    }
                    flow.EndBranch();
                }

                var result = GetEnrollmentResult(enrollmentResponse);
                flow.Step("MapEnrollmentResult", $"Status={result.Status}, CARequestID={result.CARequestID ?? "(null)"}");
                return result;
            }
            catch (Exception ex)
            {
                flow.Fail("UNHANDLED", ex.Message);
                _logger.LogError(ex, "Unhandled error during Enroll (Type={EnrollmentType}, ProductID={ProductId})", enrollmentType, productInfo?.ProductID);
                throw;
            }
            finally
            {
                _logger.MethodExit();
            }
        }

        /// <summary>
        /// Builds a composite CARequestID in the format "{TheSSLStoreOrderID}-{PartnerOrderID}".
        /// This ensures uniqueness across reissues (same order, different PartnerOrderID).
        /// </summary>
        private static string BuildCompositeRequestId(string theSslStoreOrderId, string partnerOrderId)
        {
            return $"{theSslStoreOrderId}-{partnerOrderId}";
        }

        /// <summary>
        /// Parses the TheSSLStoreOrderID from a CARequestID. Supports both composite format
        /// ("{TheSSLStoreOrderID}-{PartnerOrderID}") and legacy GUID format (falls back to
        /// treating the whole string as a CustomOrderId for backward compatibility).
        /// </summary>
        private static string ParseSslStoreOrderId(string caRequestId)
        {
            if (string.IsNullOrEmpty(caRequestId)) return caRequestId;

            var dashIndex = caRequestId.IndexOf('-');
            // Composite IDs have a numeric TheSSLStoreOrderID before the first dash.
            // Legacy GUIDs have hex chars before the first dash so we check for digits only.
            if (dashIndex > 0 && caRequestId.Substring(0, dashIndex).All(char.IsDigit))
            {
                return caRequestId.Substring(0, dashIndex);
            }

            // Legacy GUID format — return as-is for backward compatibility
            return null;
        }

        private EnrollmentResult GetEnrollmentResult(INewOrderResponse newOrderResponse)
        {
            if (newOrderResponse != null && newOrderResponse.AuthResponse.IsError)
            {
                _logger.MethodExit();
                return new EnrollmentResult
                {
                    Status = (int)EndEntityStatus.FAILED,
                    StatusMessage = newOrderResponse.AuthResponse.Message[0]
                };
            }

            var majorStatus = newOrderResponse?.OrderStatus?.MajorStatus;
            var status = _requestManager.MapReturnStatus(majorStatus);
            var compositeId = BuildCompositeRequestId(newOrderResponse?.TheSslStoreOrderId, newOrderResponse?.PartnerOrderId);

            _logger.LogTrace($"Order {compositeId} (SSLStoreOrderId: {newOrderResponse?.TheSslStoreOrderId}, PartnerOrderId: {newOrderResponse?.PartnerOrderId}) status: {majorStatus} -> mapped to {status}");
            _logger.MethodExit();

            return new EnrollmentResult
            {
                CARequestID = compositeId,
                Status = status,
                StatusMessage = $"Order Successfully Created With Order Number {compositeId}"
            };
        }

        public async Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestId)
        {
            _logger.MethodEntry();
            _logger.LogInformation("GetSingleRecord requested for CARequestID '{CaRequestId}'", caRequestId ?? "(null)");
            using var flow = new FlowLogger(_logger, $"GetSingleRecord({caRequestId ?? "null"})");

            var client = new SslStoreClient(Config);
            var sslStoreOrderId = ParseSslStoreOrderId(caRequestId);

            OrderStatusRequest orderStatusRequest;
            if (sslStoreOrderId != null)
            {
                flow.Step("BuildOrderStatusRequest", $"by SSLStoreOrderId={sslStoreOrderId}");
                _logger.LogTrace($"Parsed TheSSLStoreOrderID: {sslStoreOrderId} from CARequestID: {caRequestId}");
                orderStatusRequest = _requestManager.GetOrderStatusRequestBySslStoreId(sslStoreOrderId);
            }
            else
            {
                flow.Step("BuildOrderStatusRequest", $"legacy CustomOrderId={caRequestId}");
                _logger.LogTrace($"Legacy GUID format, querying by CustomOrderId: {caRequestId}");
                orderStatusRequest = _requestManager.GetOrderStatusRequest(caRequestId);
            }

            try
            {
                INewOrderResponse orderStatusResponse = null;
                await flow.StepAsync("FetchOrderStatus",
                    async () => orderStatusResponse = await client.SubmitOrderStatusRequestAsync(orderStatusRequest));
                _logger.LogTrace($"orderStatusResponse JSON {JsonConvert.SerializeObject(orderStatusResponse)}");

                var certStatus = _requestManager.MapReturnStatus(orderStatusResponse?.OrderStatus.MajorStatus);
                flow.Step("MapStatus", $"{orderStatusResponse?.OrderStatus?.MajorStatus} -> {certStatus}");
                var certificate = string.Empty;

                if (certStatus == (int)EndEntityStatus.GENERATED)
                {
                    flow.Branch("DownloadIssuedCert");
                    var downloadCertificateRequest = _requestManager.GetCertificateRequestBySslStoreId(sslStoreOrderId ?? orderStatusResponse.TheSslStoreOrderId);
                    IDownloadCertificateResponse certResponse = null;
                    await flow.StepAsync("DownloadCertificate",
                        async () => certResponse = await client.SubmitDownloadCertificateAsync(downloadCertificateRequest));
                    if (!certResponse.AuthResponse.IsError)
                    {
                        flow.Step("ExtractLeafCert", () =>
                        {
                            var fullChain = string.Join("\n", certResponse.Certificates.Select(c => c.FileContent));
                            var endEntityCert = X509Utilities.ExtractEndEntityCertificateContents(fullChain, null);
                            certificate = Convert.ToBase64String(endEntityCert.RawData);
                        });
                    }
                    else
                    {
                        flow.Fail("DownloadCertificate", "AuthResponse.IsError");
                        _logger.LogWarning("Certificate download reported an error for CARequestID '{CaRequestId}'", caRequestId);
                    }

                    // Order is issued - best-effort cleanup of any DNS validation records we published.
                    await flow.StepAsync("CleanupDnsValidation",
                        async () => await CleanupDnsValidationAsync(orderStatusResponse));
                    flow.EndBranch();
                }

                _logger.LogInformation("GetSingleRecord result for '{CaRequestId}': Status={Status}, certReturned={HasCert}",
                    caRequestId, certStatus, !string.IsNullOrEmpty(certificate));

                return new AnyCAPluginCertificate
                {
                    CARequestID = caRequestId,
                    Certificate = certificate,
                    Status = certStatus
                };
            }
            catch (Exception ex)
            {
                flow.Fail("UNHANDLED", ex.Message);
                _logger.LogError(ex, "Unhandled error in GetSingleRecord for CARequestID '{CaRequestId}'", caRequestId);
                throw;
            }
            finally
            {
                _logger.MethodExit();
            }
        }

        public async Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer,
            DateTime? lastSync, bool fullSync, CancellationToken cancelToken)
        {
            _logger.MethodEntry();
            _logger.LogInformation("Synchronize started. fullSync={FullSync}, lastSync={LastSync}",
                fullSync, lastSync.HasValue ? lastSync.Value.ToString("u") : "(none)");
            using var flow = new FlowLogger(_logger, $"Synchronize-{(fullSync ? "Full" : "Incremental")}");

            var processed = 0;
            var added = 0;
            var skipped = 0;

            try
            {
                var client = new SslStoreClient(Config);
                var certs = new BlockingCollection<INewOrderResponse>(100);
                flow.Step("StartQueryOrders");
                _ = client.SubmitQueryOrderRequestAsync(certs, cancelToken, _requestManager);

                foreach (var currentResponseItem in certs.GetConsumingEnumerable(cancelToken))
                {
                    if (cancelToken.IsCancellationRequested)
                    {
                        _logger.LogWarning("Synchronize was canceled after processing {Processed} order(s).", processed);
                        flow.Fail("Cancelled", $"after {processed} processed");
                        break;
                    }

                    try
                    {
                        processed++;
                        _logger.LogTrace($"Took Certificate ID {currentResponseItem?.TheSslStoreOrderId} (CustomOrderId: {currentResponseItem?.CustomOrderId}) from Queue");

                        // Use TheSslStoreOrderId for sync lookups since that's what the query returns
                        var orderStatusRequest = _requestManager.GetOrderStatusRequestBySslStoreId(currentResponseItem?.TheSslStoreOrderId);
                        var orderStatusResponse = await client.SubmitOrderStatusRequestAsync(orderStatusRequest);

                        var theSslStoreOrderId = orderStatusResponse.TheSslStoreOrderId;
                        var partnerOrderId = orderStatusResponse.PartnerOrderId;
                        if (string.IsNullOrEmpty(theSslStoreOrderId) || string.IsNullOrEmpty(partnerOrderId))
                        {
                            skipped++;
                            _logger.LogTrace($"Order {currentResponseItem?.TheSslStoreOrderId} missing required IDs, skipping");
                            continue;
                        }

                        var compositeId = BuildCompositeRequestId(theSslStoreOrderId, partnerOrderId);
                        var fileContent = "";
                        var certStatus = _requestManager.MapReturnStatus(orderStatusResponse.OrderStatus.MajorStatus);
                        _logger.LogTrace("Sync order {CompositeId}: MajorStatus={MajorStatus} -> {CertStatus}",
                            compositeId, orderStatusResponse.OrderStatus.MajorStatus, certStatus);

                        if (certStatus == (int)EndEntityStatus.GENERATED)
                        {
                            var downloadCertificateRequest = _requestManager.GetCertificateRequestBySslStoreId(theSslStoreOrderId);
                            var certResponse = await client.SubmitDownloadCertificateAsync(downloadCertificateRequest);
                            if (!certResponse.AuthResponse.IsError)
                            {
                                var fullChain = string.Join("\n", certResponse.Certificates.Select(c => c.FileContent));
                                var endEntityCert = X509Utilities.ExtractEndEntityCertificateContents(fullChain, null);
                                fileContent = Convert.ToBase64String(endEntityCert.RawData);
                            }
                            else
                            {
                                _logger.LogWarning("Certificate download error during sync for order {CompositeId}", compositeId);
                            }

                            // Order is issued - best-effort cleanup of any DNS validation records we published.
                            await CleanupDnsValidationAsync(orderStatusResponse);
                        }

                        if ((certStatus == (int)EndEntityStatus.GENERATED && fileContent.Length > 0) ||
                            certStatus == (int)EndEntityStatus.REVOKED)
                        {
                            added++;
                            blockingBuffer.Add(new AnyCAPluginCertificate
                            {
                                CARequestID = compositeId,
                                Certificate = fileContent,
                                Status = certStatus,
                                ProductID = $"{orderStatusResponse.ProductCode}"
                            }, cancelToken);
                        }
                        else
                        {
                            skipped++;
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        _logger.LogWarning("Synchronize was canceled after processing {Processed} order(s).", processed);
                        flow.Fail("Cancelled", $"after {processed} processed");
                        break;
                    }
                }

                flow.Step("SyncSummary", $"processed={processed}, added={added}, skipped={skipped}");
                _logger.LogInformation("Synchronize finished. Processed={Processed}, added={Added}, skipped={Skipped}",
                    processed, added, skipped);
            }
            catch (AggregateException ae)
            {
                flow.Fail("SyncError", ae.Message);
                _logger.LogError(ae, "SslStore Synchronize Task failed after processing {Processed} order(s)!", processed);
                throw;
            }
            finally
            {
                _logger.MethodExit();
            }
        }

        private string ValidateEmails(EmailApproverResponse validEmails, string[] arrayApproverEmails, EnrollmentProductInfo productInfo, int count)
        {
            if (arrayApproverEmails.Length > 1 && productInfo.ProductID.Contains("digi"))
            {
                return "There should only be one approval email for Digicert products.";
            }

            if (count == 1 && productInfo.ProductID.Contains("digi") && arrayApproverEmails.Length > 0)
            {
                if (!validEmails.ApproverEmailList.Contains(arrayApproverEmails[0]))
                {
                    return $"Digicert Approver Email must be one of the following {string.Join(",", validEmails.ApproverEmailList)}";
                }
            }

            if (!productInfo.ProductID.Contains("digi"))
            {
                if (!validEmails.ApproverEmailList.Intersect(arrayApproverEmails).Any())
                {
                    return $"Sectigo Approver Email must be one of the following {string.Join(",", validEmails.ApproverEmailList)}";
                }
            }

            return "";
        }

        /// <summary>
        /// Determines whether automated DNS (CNAME) domain control validation should be used for
        /// this enrollment. Enabled by the CA-connection <c>DnsValidationEnabled</c> flag, or
        /// per-template via the "CName Auth Domain Validation" parameter.
        /// </summary>
        private bool ResolveUseDnsValidation(EnrollmentProductInfo productInfo)
        {
            if (_config.DnsValidationEnabled) return true;

            if (productInfo?.ProductParameters != null &&
                productInfo.ProductParameters.TryGetValue("CName Auth Domain Validation", out var flag))
            {
                return string.Equals(flag, "True", StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        /// <summary>
        /// Publishes the CNAME validation record(s) SSL Store returned for the order using the DNS
        /// provider plugin resolved by the AnyCA Gateway, then verifies public DNS propagation.
        /// Returns an empty string on success or an error message on failure. Propagation is
        /// best-effort: SSL Store polls DNS on its own schedule, so a not-yet-propagated record is
        /// logged as a warning rather than failing the enrollment.
        /// </summary>
        private async Task<string> StageDnsValidationAsync(INewOrderResponse response, string cnDomain)
        {
            using var flow = new FlowLogger(_logger, "StageDnsValidation");

            if (_validatorFactory == null)
            {
                flow.Fail("CheckValidatorFactory", "IDomainValidatorFactory not provided by gateway");
                _logger.LogError("DNS validation enabled but the AnyCA Gateway did not inject an IDomainValidatorFactory.");
                return "DNS domain control validation is enabled but the AnyCA Gateway did not provide an " +
                       "IDomainValidatorFactory. Ensure the gateway version supports DNS provider plugins.";
            }

            var records = CollectDnsRecords(response, cnDomain);
            flow.Step("CollectDnsRecords", $"{records.Count} record(s)");
            if (records.Count == 0)
            {
                flow.Skip("PublishRecords", "no CNAME records returned by SSL Store");
                _logger.LogWarning("DNS validation enabled but SSL Store returned no CNAME validation records to publish.");
                return "";
            }

            _logger.LogInformation(
                "Staging {Count} DNS validation record(s) via validation type '{ValidationType}' (verification server: {Server}, {Attempts} attempt(s) x {Delay}s).",
                records.Count, _config.DnsValidationType,
                string.IsNullOrEmpty(_config.DnsVerificationServer) ? "public resolvers" : _config.DnsVerificationServer,
                _config.DnsPropagationMaxAttempts, _config.DnsPropagationDelaySeconds);

            var verifier = new DnsVerificationHelper(_config.DnsVerificationServer, _config.DnsPropagationMaxAttempts, _config.DnsPropagationDelaySeconds);

            foreach (var (domain, recordName, recordValue) in records)
            {
                _logger.LogInformation($"Staging CNAME validation record for {domain}: {recordName} -> {recordValue}");

                IDomainValidator validator;
                try
                {
                    validator = _validatorFactory.ResolveDomainValidator(domain, _config.DnsValidationType);
                    flow.Step($"ResolveValidator[{domain}]", validator != null ? validator.GetType().Name : "null");
                }
                catch (Exception ex)
                {
                    flow.Fail($"ResolveValidator[{domain}]", ex.Message);
                    _logger.LogError(ex, "Failed to resolve DNS provider plugin for '{Domain}' (validation type '{ValidationType}')", domain, _config.DnsValidationType);
                    return $"Failed to resolve DNS provider plugin for '{domain}' (validation type '{_config.DnsValidationType}'): {ex.Message}";
                }

                if (validator == null)
                {
                    flow.Fail($"ResolveValidator[{domain}]", "no validator resolved");
                    _logger.LogError("No DNS provider plugin resolved for '{Domain}' (validation type '{ValidationType}').", domain, _config.DnsValidationType);
                    return $"No DNS provider plugin resolved for '{domain}' (validation type '{_config.DnsValidationType}'). " +
                           "Ensure a DNS provider plugin is deployed and configured for the zone that hosts this domain.";
                }

                DomainValidationResult result = null;
                await flow.StepAsync($"PublishRecord[{recordName}]",
                    async () => result = await validator.StageValidation(recordName, recordValue, CancellationToken.None));
                if (result == null || !result.Success)
                {
                    var msg = result?.ErrorMessage ?? "unknown error";
                    flow.Fail($"PublishRecord[{recordName}]", msg);
                    _logger.LogError("Failed to publish DNS validation record {RecordName} for '{Domain}': {Message}", recordName, domain, msg);
                    return $"Failed to publish DNS validation record for '{domain}': {msg}";
                }
                _logger.LogInformation("Published DNS validation record {RecordName} for '{Domain}' via {Validator}.",
                    recordName, domain, validator.GetType().Name);

                var propagated = false;
                await flow.StepAsync($"VerifyPropagation[{recordName}]",
                    async () => propagated = await verifier.WaitForDnsPropagationAsync(recordName, recordValue, QueryType.CNAME, 3));
                if (!propagated)
                {
                    flow.Skip($"VerifyPropagation[{recordName}]", "not yet confirmed (best-effort)");
                    _logger.LogWarning($"CNAME record {recordName} for '{domain}' was not yet confirmed across public resolvers. " +
                                       "SSL Store will re-check on its own schedule.");
                }
                else
                {
                    _logger.LogInformation("CNAME record {RecordName} for '{Domain}' confirmed propagated.", recordName, domain);
                }
            }

            return "";
        }

        /// <summary>
        /// Best-effort removal of the DNS validation record(s) once an order has been issued.
        /// Called during GetSingleRecord/Synchronize when the order first reports Active. Any failure
        /// is logged and swallowed so it never affects sync or record retrieval.
        /// </summary>
        private async Task CleanupDnsValidationAsync(INewOrderResponse response)
        {
            if (_validatorFactory == null || !_config.DnsValidationEnabled || response == null)
            {
                _logger.LogTrace("Skipping DNS validation cleanup (factory available={HasFactory}, DnsValidationEnabled={Enabled}, response null={NullResponse}).",
                    _validatorFactory != null, _config.DnsValidationEnabled, response == null);
                return;
            }

            var records = CollectDnsRecords(response, response.CommonName ?? "");
            if (records.Count == 0)
            {
                _logger.LogTrace("No DNS validation records to clean up for this order.");
                return;
            }

            _logger.LogInformation("Best-effort cleanup of {Count} DNS validation record(s).", records.Count);
            foreach (var (domain, recordName, _) in records)
            {
                try
                {
                    var validator = _validatorFactory.ResolveDomainValidator(domain, _config.DnsValidationType);
                    if (validator == null)
                    {
                        _logger.LogTrace("No validator resolved for '{Domain}' during cleanup; skipping record {RecordName}.", domain, recordName);
                        continue;
                    }

                    var result = await validator.CleanupValidation(recordName, CancellationToken.None);
                    if (result != null && !result.Success)
                        _logger.LogWarning($"Cleanup of DNS validation record {recordName} for '{domain}' reported failure: {result.ErrorMessage}");
                    else
                        _logger.LogInformation("Cleaned up DNS validation record {RecordName} for '{Domain}'.", recordName, domain);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Best-effort cleanup of DNS validation record {RecordName} for '{Domain}' failed.", recordName, domain);
                }
            }
        }

        /// <summary>
        /// Collects the CNAME validation records SSL Store expects to be published for an order:
        /// the order-level record (<c>CNAMEAuthName</c>/<c>CNAMEAuthValue</c>) plus any per-domain
        /// records carried in the order's DomainAuthVettingStatus. De-duplicated by record name.
        /// </summary>
        private static List<(string domain, string recordName, string recordValue)> CollectDnsRecords(INewOrderResponse response, string cnDomain)
        {
            var records = new List<(string, string, string)>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (!string.IsNullOrEmpty(response?.CnameAuthName) && !string.IsNullOrEmpty(response.CnameAuthValue) &&
                seen.Add(response.CnameAuthName))
            {
                records.Add((cnDomain, response.CnameAuthName, response.CnameAuthValue));
            }

            var vetting = response?.OrderStatus?.DomainAuthVettingStatus;
            if (vetting != null)
            {
                foreach (var v in vetting)
                {
                    if (!string.IsNullOrEmpty(v.DnsName) && !string.IsNullOrEmpty(v.DnsEntry) && seen.Add(v.DnsName))
                    {
                        records.Add((string.IsNullOrEmpty(v.Domain) ? cnDomain : v.Domain, v.DnsName, v.DnsEntry));
                    }
                }
            }

            return records;
        }
    }
}
