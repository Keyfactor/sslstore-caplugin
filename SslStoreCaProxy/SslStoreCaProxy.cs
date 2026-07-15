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

        /// <summary>
        /// Validation type string passed to <see cref="IDomainValidatorFactory.ResolveDomainValidator"/>.
        /// SSL Store domain control validation always publishes a CNAME record, so we resolve a DNS
        /// provider that advertises the "cname" validation type (e.g. Ns1CnameDomainValidator). This is
        /// intrinsic to the CA — it is not operator-configurable. Which validator actually handles a
        /// given domain is chosen via the AnyCA Gateway's Domain Validation mapping, not here.
        /// </summary>
        private const string DnsValidationType = "cname";

        /// <summary>Seconds between polls while waiting for SSL Store to issue a DNS-validated order.</summary>
        private const int DcvPollIntervalSeconds = 15;

        // Guardrails so a mis-typed CA-connection value cannot make enrollment block for an
        // unreasonable time or spin uselessly. Values outside these bounds are clamped at Initialize.
        private const int MinRenewalWindowDays = 1;
        private const int MaxRenewalWindowDays = 3650;
        private const int MaxDnsPropagationMaxAttempts = 30;
        private const int MaxDnsPropagationDelaySeconds = 120;
        private const int MaxDcvPollTimeoutSeconds = 600;
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
                    if (_config == null)
                        throw new InvalidOperationException("CA connection data could not be deserialized into a configuration object.");

                    PartnerCode = _config.PartnerCode;
                    AuthenticationToken = _config.AuthToken;
                    PageSize = _config.PageSize > 0 ? _config.PageSize : SslStoreCAPluginConfig.DefaultPageSize;
                    RenewalWindow = Clamp(_config.RenewalWindow > 0 ? _config.RenewalWindow : 30, MinRenewalWindowDays, MaxRenewalWindowDays, "RenewalWindow");

                    // Clamp DNS/DCV timing so a bad value can't make enrollment block forever or spin.
                    _config.DnsPropagationMaxAttempts = Clamp(_config.DnsPropagationMaxAttempts > 0 ? _config.DnsPropagationMaxAttempts : 3, 1, MaxDnsPropagationMaxAttempts, "DnsPropagationMaxAttempts");
                    _config.DnsPropagationDelaySeconds = Clamp(_config.DnsPropagationDelaySeconds > 0 ? _config.DnsPropagationDelaySeconds : 10, 1, MaxDnsPropagationDelaySeconds, "DnsPropagationDelaySeconds");
                    _config.DcvPollTimeoutSeconds = Clamp(_config.DcvPollTimeoutSeconds, 0, MaxDcvPollTimeoutSeconds, "DcvPollTimeoutSeconds");
                }, $"PageSize={PageSize}, RenewalWindow={RenewalWindow}");

                flow.Step("CreateRequestManager", () => _requestManager = new RequestManager(this));

                _logger.LogInformation(
                    "SslStore CAPlugin initialized. Enabled={Enabled}, SSLStoreURL={Url}, PartnerCode set={HasPartner}, AuthToken set={HasToken}, PageSize={PageSize}, RenewalWindow={RenewalWindow}, DnsValidationEnabled={DnsEnabled}, DnsValidationType={DnsType}, DnsVerificationServer={DnsServer}, DnsPropagationMaxAttempts={DnsAttempts}, DnsPropagationDelaySeconds={DnsDelay}, DcvPollTimeoutSeconds={DcvPoll}, DomainValidatorFactory available={HasFactory}",
                    _config.Enabled, _config.SSLStoreURL, !string.IsNullOrEmpty(_config.PartnerCode), !string.IsNullOrEmpty(_config.AuthToken),
                    PageSize, RenewalWindow, _config.DnsValidationEnabled, DnsValidationType,
                    string.IsNullOrEmpty(_config.DnsVerificationServer) ? "(public resolvers)" : _config.DnsVerificationServer,
                    _config.DnsPropagationMaxAttempts, _config.DnsPropagationDelaySeconds, _config.DcvPollTimeoutSeconds, _validatorFactory != null);
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

            if (productInfo == null)
            {
                flow.Fail("ValidateInputs", "productInfo is null");
                _logger.LogError("Enroll called with null productInfo.");
                return new EnrollmentResult { Status = (int)EndEntityStatus.FAILED, StatusMessage = "Enrollment product information was not provided." };
            }
            // ProductParameters is dereferenced throughout; guarantee a non-null map.
            var productParameters = productInfo.ProductParameters ?? new Dictionary<string, string>();

            var client = new SslStoreClient(Config);

            try
            {
                INewOrderResponse enrollmentResponse = null;

                if (enrollmentType == EnrollmentType.New)
                {
                    flow.Branch("NewEnrollment");
                    _logger.LogTrace("Entering New Enrollment");

                    if (!productParameters.ContainsKey("PriorCertSN"))
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
                            if (productParameters.ContainsKey("Approver Email"))
                            {
                                _logger.LogTrace($"Approver Email {productParameters["Approver Email"]}");
                                arrayApproverEmails = productParameters["Approver Email"].Split(new char[] { ',' });
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

                            // The CNAME is published; poll SSL Store for issuance and, if it issues within the
                            // configured window, return the certificate directly from this enrollment call
                            // (ACME-style). Otherwise fall through to a pending result and let CA sync finish it.
                            if (!string.IsNullOrEmpty(enrollmentResponse.TheSslStoreOrderId) && !string.IsNullOrEmpty(enrollmentResponse.PartnerOrderId))
                            {
                                var compositeId = BuildCompositeRequestId(enrollmentResponse.TheSslStoreOrderId, enrollmentResponse.PartnerOrderId);
                                EnrollmentResult issuedResult = null;
                                await flow.StepAsync("PollForIssuance",
                                    async () => issuedResult = await TryPollForIssuedCertAsync(compositeId));
                                if (issuedResult != null)
                                {
                                    flow.Step("PollResult", "issued during poll window");
                                    flow.EndBranch();
                                    return issuedResult;
                                }
                                flow.Skip("PollResult", "not issued within poll window; returning pending");
                            }
                            else
                            {
                                flow.Skip("PollForIssuance", "SSL Store did not return both order IDs; cannot poll");
                                _logger.LogWarning("Cannot poll for issuance: SSL Store response missing TheSslStoreOrderId/PartnerOrderId.");
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

                    if (!productParameters.TryGetValue("PriorCertSN", out var sn) || string.IsNullOrEmpty(sn))
                    {
                        flow.Fail("ValidatePriorSN", "PriorCertSN missing");
                        _logger.LogError("Renew/Reissue enrollment is missing the required PriorCertSN parameter.");
                        return new EnrollmentResult { Status = (int)EndEntityStatus.FAILED, StatusMessage = "Renewal/reissue requires the prior certificate serial number (PriorCertSN)." };
                    }
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
        /// Clamps a configuration value into [min, max], logging a warning when the supplied value
        /// was out of range so operators can see their setting was overridden.
        /// </summary>
        private static int Clamp(int value, int min, int max, string name)
        {
            if (value < min)
            {
                _logger.LogWarning("Config value {Name}={Value} is below the minimum {Min}; using {Min}.", name, value, min);
                return min;
            }
            if (value > max)
            {
                _logger.LogWarning("Config value {Name}={Value} is above the maximum {Max}; using {Max}.", name, value, max);
                return max;
            }
            return value;
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

                var isIssued = certStatus == (int)EndEntityStatus.GENERATED;
                var isRevoked = certStatus == (int)EndEntityStatus.REVOKED;

                if (isIssued || isRevoked)
                {
                    // Download the certificate for both issued and revoked orders so a valid cert is
                    // always returned when one exists. A revoked order that was never issued yields no
                    // content (empty) rather than a corrupt/empty certificate handle.
                    flow.Branch(isIssued ? "DownloadIssuedCert" : "DownloadRevokedCert");
                    await flow.StepAsync("DownloadCertificate",
                        async () => certificate = await DownloadLeafCertificateAsync(
                            client, sslStoreOrderId ?? orderStatusResponse.TheSslStoreOrderId, caRequestId));

                    if (isRevoked && string.IsNullOrEmpty(certificate))
                        _logger.LogWarning("Revoked order '{CaRequestId}' has no downloadable certificate.", caRequestId);

                    if (isIssued)
                    {
                        // Order is issued - best-effort cleanup of any DNS validation records we published.
                        await flow.StepAsync("CleanupDnsValidation",
                            async () => await CleanupDnsValidationAsync(orderStatusResponse));
                    }
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

                        var isIssued = certStatus == (int)EndEntityStatus.GENERATED;
                        var isRevoked = certStatus == (int)EndEntityStatus.REVOKED;

                        if (isIssued || isRevoked)
                        {
                            // Download the certificate for both issued and revoked (Cancelled) orders so
                            // the gateway always stores valid DER. Revoked orders that were never issued
                            // return no content and are skipped below — storing an empty certificate makes
                            // the gateway's certificate search fail with "m_safeCertContext is an invalid handle".
                            fileContent = await DownloadLeafCertificateAsync(client, theSslStoreOrderId, compositeId);

                            if (isIssued)
                            {
                                // Order is issued - best-effort cleanup of any DNS validation records we published.
                                await CleanupDnsValidationAsync(orderStatusResponse);
                            }
                        }

                        if ((isIssued || isRevoked) && fileContent.Length > 0)
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
                            if (isRevoked)
                                _logger.LogWarning("Skipping revoked order {CompositeId} with no downloadable certificate (nothing to store).", compositeId);
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

        /// <summary>
        /// Downloads the issued certificate for an order and returns the base64-encoded end-entity
        /// certificate, or an empty string if the download reported an error or returned no content.
        /// Used for both issued and revoked orders so the gateway always stores valid certificate
        /// bytes; callers must treat an empty result as "no certificate available".
        /// </summary>
        private async Task<string> DownloadLeafCertificateAsync(SslStoreClient client, string theSslStoreOrderId, string compositeId)
        {
            var downloadCertificateRequest = _requestManager.GetCertificateRequestBySslStoreId(theSslStoreOrderId);
            var certResponse = await client.SubmitDownloadCertificateAsync(downloadCertificateRequest);
            if (certResponse == null || certResponse.AuthResponse.IsError)
            {
                _logger.LogWarning("Certificate download reported an error for order {CompositeId}.", compositeId);
                return string.Empty;
            }

            var fullChain = string.Join("\n", certResponse.Certificates.Select(c => c.FileContent));
            if (string.IsNullOrWhiteSpace(fullChain))
            {
                _logger.LogWarning("Certificate download returned no content for order {CompositeId}.", compositeId);
                return string.Empty;
            }

            var endEntityCert = X509Utilities.ExtractEndEntityCertificateContents(fullChain, null);
            return Convert.ToBase64String(endEntityCert.RawData);
        }

        /// <summary>
        /// After a DNS-validated order's CNAME is published, polls SSL Store (via <see cref="GetSingleRecord"/>)
        /// for up to <c>DcvPollTimeoutSeconds</c> for the certificate to be issued. Returns a GENERATED
        /// <see cref="EnrollmentResult"/> carrying the issued leaf certificate if it issues within the window,
        /// or <c>null</c> if the window expires (caller then returns its pending/EXTERNALVALIDATION result).
        /// No-op (returns null) when polling is disabled or the request ID is missing.
        /// </summary>
        private async Task<EnrollmentResult> TryPollForIssuedCertAsync(string caRequestId)
        {
            if (_config.DcvPollTimeoutSeconds <= 0)
            {
                _logger.LogTrace("Issuance polling disabled (DcvPollTimeoutSeconds=0); returning pending.");
                return null;
            }

            if (string.IsNullOrEmpty(caRequestId))
            {
                _logger.LogWarning("No CARequestID available to poll for issuance; returning pending.");
                return null;
            }

            var deadline = DateTime.UtcNow.AddSeconds(_config.DcvPollTimeoutSeconds);
            var interval = TimeSpan.FromSeconds(DcvPollIntervalSeconds);
            _logger.LogInformation("Polling SSL Store for issuance of '{CaRequestId}' for up to {Seconds}s (interval {Interval}s).",
                caRequestId, _config.DcvPollTimeoutSeconds, DcvPollIntervalSeconds);

            var attempt = 0;
            while (DateTime.UtcNow < deadline)
            {
                attempt++;
                AnyCAPluginCertificate record = null;
                try
                {
                    record = await GetSingleRecord(caRequestId);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Issuance poll attempt {Attempt} for '{CaRequestId}' threw; will retry.", attempt, caRequestId);
                }

                if (record != null && record.Status == (int)EndEntityStatus.GENERATED && !string.IsNullOrEmpty(record.Certificate))
                {
                    _logger.LogInformation("Order '{CaRequestId}' issued after {Attempt} poll(s); returning certificate directly.", caRequestId, attempt);
                    return new EnrollmentResult
                    {
                        Status = (int)EndEntityStatus.GENERATED,
                        CARequestID = caRequestId,
                        Certificate = record.Certificate,
                        StatusMessage = $"Certificate issued and retrieved for order {caRequestId}."
                    };
                }

                _logger.LogTrace("Issuance poll attempt {Attempt} for '{CaRequestId}': status={Status}, cert={CertState}.",
                    attempt, caRequestId, record?.Status, string.IsNullOrEmpty(record?.Certificate) ? "empty" : "present");

                // Don't sleep past the deadline.
                if (DateTime.UtcNow.Add(interval) >= deadline)
                    break;

                await Task.Delay(interval);
            }

            _logger.LogInformation("Order '{CaRequestId}' not issued within {Seconds}s after {Attempts} attempt(s); returning pending.",
                caRequestId, _config.DcvPollTimeoutSeconds, attempt);
            return null;
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
                // The parameter is a Boolean toggle but arrives as a string ("true"/"false").
                // bool.TryParse is case-insensitive; also accept the legacy "True"/"False" text.
                return bool.TryParse(flag?.Trim(), out var parsed) && parsed;
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
                records.Count, DnsValidationType,
                string.IsNullOrEmpty(_config.DnsVerificationServer) ? "public resolvers" : _config.DnsVerificationServer,
                _config.DnsPropagationMaxAttempts, _config.DnsPropagationDelaySeconds);

            var verifier = new DnsVerificationHelper(_config.DnsVerificationServer, _config.DnsPropagationMaxAttempts, _config.DnsPropagationDelaySeconds);

            foreach (var (domain, recordName, recordValue) in records)
            {
                _logger.LogInformation($"Staging CNAME validation record for {domain}: {recordName} -> {recordValue}");

                IDomainValidator validator;
                try
                {
                    validator = _validatorFactory.ResolveDomainValidator(domain, DnsValidationType);
                    flow.Step($"ResolveValidator[{domain}]", validator != null ? validator.GetType().Name : "null");
                }
                catch (Exception ex)
                {
                    flow.Fail($"ResolveValidator[{domain}]", ex.Message);
                    _logger.LogError(ex, "Failed to resolve DNS provider plugin for '{Domain}' (validation type '{ValidationType}')", domain, DnsValidationType);
                    return $"Failed to resolve DNS provider plugin for '{domain}' (validation type '{DnsValidationType}'): {ex.Message}";
                }

                if (validator == null)
                {
                    flow.Fail($"ResolveValidator[{domain}]", "no validator resolved");
                    _logger.LogError("No DNS provider plugin resolved for '{Domain}' (validation type '{ValidationType}').", domain, DnsValidationType);
                    return $"No DNS provider plugin resolved for '{domain}' (validation type '{DnsValidationType}'). " +
                           "Ensure a DNS provider plugin is deployed and mapped to this domain in the gateway's Domain Validation configuration.";
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

                // Propagation verification is best-effort: the record is already published, and SSL Store
                // re-checks DNS on its own schedule. A verification failure (or an unexpected error in the
                // DNS client) must never fail an enrollment whose record was successfully published.
                var propagated = false;
                try
                {
                    await flow.StepAsync($"VerifyPropagation[{recordName}]",
                        async () => propagated = await verifier.WaitForDnsPropagationAsync(recordName, recordValue, QueryType.CNAME, 3));
                }
                catch (Exception ex)
                {
                    flow.Skip($"VerifyPropagation[{recordName}]", $"verification error (best-effort): {ex.Message}");
                    _logger.LogWarning(ex, "DNS propagation verification for {RecordName} ('{Domain}') threw; continuing (best-effort).", recordName, domain);
                }

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
                    var validator = _validatorFactory.ResolveDomainValidator(domain, DnsValidationType);
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
