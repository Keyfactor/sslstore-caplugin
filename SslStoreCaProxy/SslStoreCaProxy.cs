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

namespace Keyfactor.AnyGateway.SslStore
{
    public class SslStoreCaProxy : IAnyCAPlugin
    {
        private static readonly ILogger _logger = LogHandler.GetClassLogger<SslStoreCaProxy>();
        private RequestManager _requestManager;
        private IAnyCAPluginConfigProvider Config { get; set; }
        private ICertificateDataReader _certDataReader;
        private SslStoreCAPluginConfig.Config _config;

        public string PartnerCode { get; set; }
        public string AuthenticationToken { get; set; }
        public int PageSize { get; set; }

        public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
        {
            _logger.MethodEntry();
            try
            {
                _certDataReader = certificateDataReader;
                Config = configProvider;
                var rawData = JsonConvert.SerializeObject(configProvider.CAConnectionData);
                _config = JsonConvert.DeserializeObject<SslStoreCAPluginConfig.Config>(rawData);

                PartnerCode = _config.PartnerCode;
                AuthenticationToken = _config.AuthToken;
                PageSize = _config.PageSize > 0 ? _config.PageSize : SslStoreCAPluginConfig.DefaultPageSize;

                _requestManager = new RequestManager(this);

                _logger.LogTrace($"Initialize - Enabled: {_config.Enabled}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to initialize SslStore CAPlugin: {ex}");
                throw;
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
            var revokeOrderRequest = _requestManager.GetRevokeOrderRequest(caRequestId.Split('-')[0]);
            _logger.LogTrace($"Revoke Request JSON {JsonConvert.SerializeObject(revokeOrderRequest)}");
            try
            {
                var client = new SslStoreClient(Config);
                var requestResponse = await client.SubmitRevokeCertificateAsync(revokeOrderRequest);

                _logger.LogTrace($"Revoke Response JSON {JsonConvert.SerializeObject(requestResponse)}");

                if (requestResponse.AuthResponse.IsError)
                {
                    _logger.LogError("Revoke Error Occurred");
                    _logger.MethodExit();
                    return (int)EndEntityStatus.FAILED;
                }

                _logger.MethodExit();
                return (int)EndEntityStatus.REVOKED;
            }
            catch (Exception e)
            {
                _logger.LogError($"An Error has occurred during the revoke process {e.Message}");
                return (int)EndEntityStatus.FAILED;
            }
        }

        public async Task<EnrollmentResult> Enroll(string csr, string subject, Dictionary<string, string[]> san,
            EnrollmentProductInfo productInfo, RequestFormat requestFormat, EnrollmentType enrollmentType)
        {
            _logger.MethodEntry();
            var client = new SslStoreClient(Config);

            try
            {
                INewOrderResponse enrollmentResponse = null;

                if (enrollmentType == EnrollmentType.New)
                {
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

                        var count = 1;
                        foreach (var domain in allDomains)
                        {
                            var emailApproverRequest = _requestManager.GetEmailApproverListRequest(productInfo.ProductID, domain);
                            _logger.LogTrace($"Email Approver Request JSON {JsonConvert.SerializeObject(emailApproverRequest)}");

                            var emailApproverResponse = await client.SubmitEmailApproverRequestAsync(emailApproverRequest);
                            _logger.LogTrace($"Email Approver Response JSON {JsonConvert.SerializeObject(emailApproverResponse)}");

                            var emailValidation = ValidateEmails(emailApproverResponse, arrayApproverEmails, productInfo, count);
                            _logger.LogTrace($"Email Validation Result {emailValidation}");

                            if (emailValidation.Length > 0)
                            {
                                return new EnrollmentResult
                                {
                                    Status = (int)EndEntityStatus.FAILED,
                                    StatusMessage = emailValidation
                                };
                            }
                            count++;
                        }

                        var enrollmentRequest = _requestManager.GetEnrollmentRequest(csr, subject, san, productInfo, Config, false);
                        _logger.LogTrace($"enrollmentRequest JSON {JsonConvert.SerializeObject(enrollmentRequest)}");

                        enrollmentResponse = await client.SubmitNewOrderRequestAsync(enrollmentRequest);
                        _logger.LogTrace($"enrollmentResponse JSON {JsonConvert.SerializeObject(enrollmentResponse)}");
                    }
                    else
                    {
                        return new EnrollmentResult
                        {
                            Status = (int)EndEntityStatus.FAILED,
                            StatusMessage = "You cannot renew an expired cert please perform a new enrollment."
                        };
                    }
                }
                else if (enrollmentType == EnrollmentType.RenewOrReissue)
                {
                    _logger.LogTrace("Entering Renew/Reissue Logic...");

                    var sn = productInfo.ProductParameters["PriorCertSN"];
                    _logger.LogTrace($"Prior Cert Serial Number: {sn}");

                    var caRequestId = await _certDataReader.GetRequestIDBySerialNumber(sn);
                    _logger.LogTrace($"Prior CA Request ID: {caRequestId}");

                    var orderId = caRequestId.Split('-')[0];
                    var orderStatusRequest = _requestManager.GetOrderStatusRequest(orderId);
                    _logger.LogTrace($"orderStatusRequest JSON {JsonConvert.SerializeObject(orderStatusRequest)}");

                    var orderStatusResponse = await client.SubmitOrderStatusRequestAsync(orderStatusRequest);
                    _logger.LogTrace($"orderStatusResponse JSON {JsonConvert.SerializeObject(orderStatusResponse)}");

                    // Try renewal first, fall back to reissue
                    var renewRequest = _requestManager.GetRenewalRequest(orderStatusResponse, csr);
                    _logger.LogTrace($"renewRequest JSON {JsonConvert.SerializeObject(renewRequest)}");

                    enrollmentResponse = await client.SubmitRenewRequestAsync(renewRequest);
                    _logger.LogTrace($"enrollmentResponse JSON {JsonConvert.SerializeObject(enrollmentResponse)}");

                    if (enrollmentResponse != null && enrollmentResponse.AuthResponse != null && enrollmentResponse.AuthResponse.IsError)
                    {
                        _logger.LogTrace("Renewal failed, attempting reissue...");
                        var reIssueRequest = _requestManager.GetReIssueRequest(orderStatusResponse, csr, false);
                        _logger.LogTrace($"reIssueRequest JSON {JsonConvert.SerializeObject(reIssueRequest)}");

                        enrollmentResponse = await client.SubmitReIssueRequestAsync(reIssueRequest);
                        _logger.LogTrace($"reissue enrollmentResponse JSON {JsonConvert.SerializeObject(enrollmentResponse)}");
                    }
                }

                return GetEnrollmentResult(enrollmentResponse);
            }
            finally
            {
                _logger.MethodExit();
            }
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

            _logger.MethodExit();
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.GENERATED,
                StatusMessage = $"Order Successfully Created With Order Number {newOrderResponse?.TheSslStoreOrderId}"
            };
        }

        public async Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestId)
        {
            _logger.MethodEntry();

            var client = new SslStoreClient(Config);
            var orderStatusRequest = _requestManager.GetOrderStatusRequest(caRequestId);
            _logger.LogTrace($"orderStatusRequest JSON {JsonConvert.SerializeObject(orderStatusRequest)}");

            var certResponse = await client.SubmitOrderStatusRequestAsync(orderStatusRequest);
            _logger.LogTrace($"certResponse JSON {JsonConvert.SerializeObject(certResponse)}");

            _logger.MethodExit();
            return new AnyCAPluginCertificate
            {
                CARequestID = caRequestId,
                Certificate = string.Empty,
                Status = _requestManager.MapReturnStatus(certResponse?.OrderStatus.MajorStatus)
            };
        }

        public async Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer,
            DateTime? lastSync, bool fullSync, CancellationToken cancelToken)
        {
            _logger.MethodEntry();

            try
            {
                var client = new SslStoreClient(Config);
                var certs = new BlockingCollection<INewOrderResponse>(100);
                _ = client.SubmitQueryOrderRequestAsync(certs, cancelToken, _requestManager);

                foreach (var currentResponseItem in certs.GetConsumingEnumerable(cancelToken))
                {
                    if (cancelToken.IsCancellationRequested)
                    {
                        _logger.LogError("Synchronize was canceled.");
                        break;
                    }

                    try
                    {
                        _logger.LogTrace($"Took Certificate ID {currentResponseItem?.TheSslStoreOrderId} from Queue");

                        var orderStatusRequest = _requestManager.GetOrderStatusRequest(currentResponseItem?.TheSslStoreOrderId);
                        var orderStatusResponse = await client.SubmitOrderStatusRequestAsync(orderStatusRequest);

                        var fileContent = "";
                        var certStatus = _requestManager.MapReturnStatus(orderStatusResponse.OrderStatus.MajorStatus);

                        if (certStatus == (int)EndEntityStatus.GENERATED)
                        {
                            var downloadCertificateRequest = _requestManager.GetCertificateRequest(orderStatusResponse.TheSslStoreOrderId);
                            var certResponse = await client.SubmitDownloadCertificateAsync(downloadCertificateRequest);
                            if (!certResponse.AuthResponse.IsError)
                            {
                                fileContent = _requestManager.GetCertificateContent(certResponse.Certificates, orderStatusResponse.CommonName);
                            }
                        }

                        if ((certStatus == (int)EndEntityStatus.GENERATED && fileContent.Length > 0) ||
                            certStatus == (int)EndEntityStatus.REVOKED)
                        {
                            string serialNumber = "";
                            if (fileContent.Length > 0)
                            {
                                var cert = new X509Certificate2(Encoding.UTF8.GetBytes(fileContent));
                                serialNumber = cert.SerialNumber;
                            }

                            blockingBuffer.Add(new AnyCAPluginCertificate
                            {
                                CARequestID = $"{orderStatusResponse.TheSslStoreOrderId}-{serialNumber}",
                                Certificate = fileContent,
                                Status = certStatus,
                                ProductID = $"{orderStatusResponse.ProductCode}"
                            }, cancelToken);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        _logger.LogError("Synchronize was canceled.");
                        break;
                    }
                }
            }
            catch (AggregateException)
            {
                _logger.LogError("SslStore Synchronize Task failed!");
                throw;
            }

            _logger.MethodExit();
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
    }
}
