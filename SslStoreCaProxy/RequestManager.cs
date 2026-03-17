using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.AnyGateway.SslStore.Client.Models;
using Keyfactor.AnyGateway.SslStore.Interfaces;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Keyfactor.AnyGateway.SslStore
{
    public class RequestManager : IRequestManager
    {
        private static readonly ILogger _logger = LogHandler.GetClassLogger<RequestManager>();
        private readonly SslStoreCaProxy _sslStoreCaProxy;

        public RequestManager(SslStoreCaProxy sslStoreCaProxy)
        {
            _sslStoreCaProxy = sslStoreCaProxy;
        }

        public NewOrderRequest GetEnrollmentRequest(string csr, string subject, Dictionary<string, string[]> san,
            EnrollmentProductInfo productInfo, IAnyCAPluginConfigProvider configProvider, bool isRenewalOrder)
        {
            var pemCsr = ConvertCsrToPem(csr);

            var sampleRequest = JsonConvert.SerializeObject(configProvider.CAConnectionData["SampleRequest"]);

            var settings = new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore,
                MissingMemberHandling = MissingMemberHandling.Ignore
            };
            var request = BuildNewOrderRequest(productInfo,
                JsonConvert.DeserializeObject<TemplateNewOrderRequest>(sampleRequest, settings), pemCsr, subject, san, isRenewalOrder);

            return request;
        }

        private string ConvertCsrToPem(string csr)
        {
            try
            {
                var csrBytes = Convert.FromBase64String(csr);
                var base64 = Convert.ToBase64String(csrBytes);
                var sb = new StringBuilder();
                sb.AppendLine("-----BEGIN CERTIFICATE REQUEST-----");
                for (int i = 0; i < base64.Length; i += 64)
                {
                    sb.AppendLine(base64.Substring(i, Math.Min(64, base64.Length - i)));
                }
                sb.AppendLine("-----END CERTIFICATE REQUEST-----");
                return sb.ToString();
            }
            catch
            {
                return csr;
            }
        }

        public EmailApproverRequest GetEmailApproverListRequest(string productId, string productName)
        {
            return new EmailApproverRequest()
            {
                AuthRequest = GetAuthRequest(),
                ProductCode = productId,
                DomainName = productName
            };
        }

        public OrganizationListRequest GetOrganizationListRequest()
        {
            return new OrganizationListRequest()
            {
                PartnerCode = _sslStoreCaProxy.PartnerCode,
                AuthToken = _sslStoreCaProxy.AuthenticationToken
            };
        }

        public AuthRequest GetAuthRequest()
        {
            return new AuthRequest
            {
                PartnerCode = _sslStoreCaProxy.PartnerCode,
                AuthToken = _sslStoreCaProxy.AuthenticationToken
            };
        }

        public ReIssueRequest GetReIssueRequest(INewOrderResponse orderData, string csr, bool isRenewal)
        {
            return new ReIssueRequest
            {
                AuthRequest = GetAuthRequest(),
                TheSslStoreOrderId = orderData.TheSslStoreOrderId,
                Csr = csr,
                IsRenewalOrder = isRenewal,
                IsWildCard = orderData.ProductCode.Contains("wc") || orderData.ProductCode.Contains("wildcard"),
                ReissueEmail = orderData.AdminContact.Email,
                ApproverEmails = orderData.ApproverEmail,
                PreferEnrollmentLink = false,
                FileAuthDvIndicator = orderData.OrderStatus.DomainAuthVettingStatus == null ? false : orderData.OrderStatus.DomainAuthVettingStatus.Exists(x => x.FileName != null),
                CNameAuthDvIndicator = orderData.OrderStatus.DomainAuthVettingStatus == null ? false : orderData.OrderStatus.DomainAuthVettingStatus.Exists(x => x.DnsName != null),
                WebServerType = orderData.WebServerType
            };
        }

        public AdminContact GetAdminContact(EnrollmentProductInfo productInfo)
        {
            return new AdminContact
            {
                FirstName = productInfo.ProductParameters["Admin Contact - First Name"],
                LastName = productInfo.ProductParameters["Admin Contact - Last Name"],
                Phone = productInfo.ProductParameters["Admin Contact - Phone"],
                Email = productInfo.ProductParameters["Admin Contact - Email"],
                OrganizationName = productInfo.ProductParameters["Admin Contact - Organization Name"],
                AddressLine1 = productInfo.ProductParameters["Admin Contact - Address"],
                City = productInfo.ProductParameters["Admin Contact - City"],
                Region = productInfo.ProductParameters["Admin Contact - Region"],
                PostalCode = productInfo.ProductParameters["Admin Contact - Postal Code"],
                Country = productInfo.ProductParameters["Admin Contact - Country"]
            };
        }

        public TechnicalContact GetTechnicalContact(EnrollmentProductInfo productInfo)
        {
            return new TechnicalContact
            {
                FirstName = productInfo.ProductParameters["Technical Contact - First Name"],
                LastName = productInfo.ProductParameters["Technical Contact - Last Name"],
                Phone = productInfo.ProductParameters["Technical Contact - Phone"],
                Email = productInfo.ProductParameters["Technical Contact - Email"],
                OrganizationName = productInfo.ProductParameters["Technical Contact - Organization Name"],
                AddressLine1 = productInfo.ProductParameters["Technical Contact - Address"],
                City = productInfo.ProductParameters["Technical Contact - City"],
                Region = productInfo.ProductParameters["Technical Contact - Region"],
                PostalCode = productInfo.ProductParameters["Technical Contact - Postal Code"],
                Country = productInfo.ProductParameters["Technical Contact - Country"]
            };
        }

        public DownloadCertificateRequest GetCertificateRequest(string theSslStoreOrderId)
        {
            return new DownloadCertificateRequest
            {
                AuthRequest = GetAuthRequest(),
                TheSslStoreOrderId = theSslStoreOrderId
            };
        }

        public RevokeOrderRequest GetRevokeOrderRequest(string theSslStoreOrderId)
        {
            return new RevokeOrderRequest
            {
                AuthRequest = GetAuthRequest(),
                TheSslStoreOrderId = theSslStoreOrderId
            };
        }

        public int GetClientPageSize(IAnyCAPluginConfigProvider config)
        {
            if (config.CAConnectionData.ContainsKey(Constants.PageSize))
                return int.Parse(config.CAConnectionData[Constants.PageSize].ToString());
            return Constants.DefaultPageSize;
        }

        public QueryOrderRequest GetQueryOrderRequest(int pageSize, int pageNumber)
        {
            return new QueryOrderRequest
            {
                AuthRequest = GetAuthRequest(),
                PageSize = pageSize,
                PageNumber = pageNumber
            };
        }

        public OrderStatusRequest GetOrderStatusRequest(string theSslStoreId)
        {
            return new OrderStatusRequest
            {
                AuthRequest = GetAuthRequest(),
                TheSslStoreOrderId = theSslStoreId
            };
        }

        public int MapReturnStatus(string sslStoreStatus)
        {
            switch (sslStoreStatus)
            {
                case "Active":
                    return (int)EndEntityStatus.GENERATED;
                case "Initial":
                case "Pending":
                    return (int)EndEntityStatus.INPROCESS;
                case "Cancelled":
                    return (int)EndEntityStatus.REVOKED;
                default:
                    return (int)EndEntityStatus.FAILED;
            }
        }

        public NewOrderRequest GetRenewalRequest(INewOrderResponse orderData, string csr)
        {
            return new NewOrderRequest
            {
                AuthRequest = GetAuthRequest(),
                RelatedTheSslStoreOrderId = orderData.TheSslStoreOrderId,
                ProductCode = orderData.ProductCode,
                AdminContact = GetAdminContact(orderData),
                TechnicalContact = GetTechnicalContact(orderData),
                ApproverEmail = orderData.ApproverEmail,
                SignatureHashAlgorithm = orderData.SignatureHashAlgorithm,
                WebServerType = orderData.WebServerType,
                ValidityPeriod = orderData.Validity,
                ServerCount = orderData.ServerCount,
                IsRenewalOrder = true,
                FileAuthDvIndicator = orderData.OrderStatus?.DomainAuthVettingStatus?.Exists(x => x.FileName != null),
                CnameAuthDvIndicator = orderData.OrderStatus?.DomainAuthVettingStatus?.Exists(x => x.DnsName != null),
                Csr = csr
            };
        }

        public AdminContact GetAdminContact(INewOrderResponse productInfo)
        {
            return new AdminContact
            {
                FirstName = productInfo.AdminContact.FirstName,
                LastName = productInfo.AdminContact.LastName,
                Phone = productInfo.AdminContact.Phone,
                Email = productInfo.AdminContact.Email
            };
        }

        public TechnicalContact GetTechnicalContact(INewOrderResponse productInfo)
        {
            return new TechnicalContact
            {
                FirstName = productInfo.AdminContact.FirstName,
                LastName = productInfo.AdminContact.LastName,
                Phone = productInfo.AdminContact.Phone,
                Email = productInfo.AdminContact.Email
            };
        }

        private NewOrderRequest BuildNewOrderRequest(EnrollmentProductInfo productInfo,
            TemplateNewOrderRequest newOrderRequest, string csr, string subject, Dictionary<string, string[]> san, bool isRenewal)
        {
            var customOrderId = Guid.NewGuid().ToString();
            productInfo.ProductParameters.Add("CustomOrderId", customOrderId);

            // Extract domain name from CSR subject CN
            var domainName = subject?.Split(',')
                .Select(p => p.Trim())
                .Where(p => p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                .Select(p => p.Substring(3))
                .FirstOrDefault() ?? "";

            // Extract DNS SANs from Keyfactor san parameter
            var dnsNames = san != null && san.ContainsKey("dns") ? san["dns"] : Array.Empty<string>();

            var request =
                new JObject(
                    new JObject(
                        new JProperty("AuthRequest",
                            new JObject(new JProperty("PartnerCode", _sslStoreCaProxy.PartnerCode),
                                new JProperty("AuthToken", _sslStoreCaProxy.AuthenticationToken))),
                        new JProperty("ProductCode", productInfo.ProductID.Replace("-EO", "")),
                        new JProperty("CustomOrderId", customOrderId),
                        new JProperty("TSSOrganizationId", productInfo.ProductParameters.ContainsKey("Organization ID") ? ExtractOrgId(productInfo.ProductParameters["Organization ID"]) : null),
                        new JProperty("OrganizationInfo",
                            new JObject(
                                CreatePropertyFromTemplate("$.OrganizationInfo.OrganizationName", productInfo,
                                    newOrderRequest),
                                CreatePropertyFromTemplate("$.OrganizationInfo.RegistrationNumber", productInfo,
                                    newOrderRequest),
                                CreatePropertyFromTemplate("$.OrganizationInfo.JurisdictionCountry", productInfo,
                                    newOrderRequest),
                                new JProperty("OrganizationAddress",
                                    new JObject(
                                        CreatePropertyFromTemplate(
                                            "$.OrganizationInfo.OrganizationAddress.AddressLine1", productInfo,
                                            newOrderRequest),
                                        CreatePropertyFromTemplate("$.OrganizationInfo.OrganizationAddress.Region",
                                            productInfo, newOrderRequest),
                                        CreatePropertyFromTemplate("$.OrganizationInfo.OrganizationAddress.PostalCode",
                                            productInfo, newOrderRequest),
                                        CreatePropertyFromTemplate("$.OrganizationInfo.OrganizationAddress.Country",
                                            productInfo, newOrderRequest),
                                        CreatePropertyFromTemplate("$.OrganizationInfo.OrganizationAddress.Phone",
                                            productInfo, newOrderRequest),
                                        CreatePropertyFromTemplate(
                                            "$.OrganizationInfo.OrganizationAddress.LocalityName", productInfo,
                                            newOrderRequest))))),
                        new JProperty("ValidityPeriod", ConvertDaysToMonths(productInfo)),
                        new JProperty("ServerCount", 1),
                        new JProperty("CSR", csr),
                        new JProperty("DomainName", domainName),
                        new JProperty("WebServerType", "Other"),
                        new JProperty("DNSNames", new JArray(dnsNames)),
                        new JProperty("isCUOrder", false),
                        CreatePropertyFromTemplate("$.AutoWWW", productInfo, newOrderRequest),
                        new JProperty("IsRenewalOrder", isRenewal),
                        new JProperty("isTrialOrder", false),
                        new JProperty("AdminContact",
                            new JObject(
                                CreatePropertyFromTemplate("$.AdminContact.FirstName", productInfo, newOrderRequest),
                                CreatePropertyFromTemplate("$.AdminContact.LastName", productInfo, newOrderRequest),
                                CreatePropertyFromTemplate("$.AdminContact.Phone", productInfo, newOrderRequest),
                                CreatePropertyFromTemplate("$.AdminContact.Email", productInfo, newOrderRequest),
                                CreatePropertyFromTemplate("$.AdminContact.Title", productInfo, newOrderRequest),
                                CreatePropertyFromTemplate("$.AdminContact.OrganizationName", productInfo,
                                    newOrderRequest),
                                CreatePropertyFromTemplate("$.AdminContact.AddressLine1", productInfo, newOrderRequest),
                                CreatePropertyFromTemplate("$.AdminContact.City", productInfo, newOrderRequest),
                                CreatePropertyFromTemplate("$.AdminContact.Region", productInfo, newOrderRequest),
                                CreatePropertyFromTemplate("$.AdminContact.PostalCode", productInfo, newOrderRequest),
                                CreatePropertyFromTemplate("$.AdminContact.Country", productInfo, newOrderRequest)
                            )),
                        new JProperty("TechnicalContact",
                            new JObject(
                                CreatePropertyFromTemplate("$.TechnicalContact.FirstName", productInfo,
                                    newOrderRequest),
                                CreatePropertyFromTemplate("$.TechnicalContact.LastName", productInfo, newOrderRequest),
                                CreatePropertyFromTemplate("$.TechnicalContact.Phone", productInfo, newOrderRequest),
                                CreatePropertyFromTemplate("$.TechnicalContact.Email", productInfo, newOrderRequest),
                                CreatePropertyFromTemplate("$.TechnicalContact.Title", productInfo, newOrderRequest),
                                CreatePropertyFromTemplate("$.TechnicalContact.OrganizationName", productInfo,
                                    newOrderRequest),
                                CreatePropertyFromTemplate("$.TechnicalContact.AddressLine1", productInfo,
                                    newOrderRequest),
                                CreatePropertyFromTemplate("$.TechnicalContact.City", productInfo, newOrderRequest),
                                CreatePropertyFromTemplate("$.TechnicalContact.Region", productInfo, newOrderRequest),
                                CreatePropertyFromTemplate("$.TechnicalContact.PostalCode", productInfo,
                                    newOrderRequest),
                                CreatePropertyFromTemplate("$.TechnicalContact.Country", productInfo, newOrderRequest)
                            )),
                        CreatePropertyFromTemplate("$.ApproverEmail", productInfo, newOrderRequest),
                        new JProperty("FileAuthDVIndicator", false),
                        new JProperty("CNAMEAuthDVIndicator", false),
                        new JProperty("SignatureHashAlgorithm", "PREFER_SHA2")));

            return request.ToObject<NewOrderRequest>();
        }

        public string GetCertificateContent(List<Certificate> certificates, string commonName)
        {
            foreach (var c in certificates)
            {
                var cert = new X509Certificate2(Encoding.UTF8.GetBytes(c.FileContent));
                if (cert.SubjectName.Name != null && cert.SubjectName.Name.Contains(commonName)) return c.FileContent;
            }

            return "";
        }

        private JArray CreateJArrayFromCommaSeparatedList(string csList)
        {
            var ja = new JArray();
            foreach (var i in csList.Split(',')) ja.Add(i);
            return ja;
        }

        private JProperty CreatePropertyFromTemplate(string propertyPath, EnrollmentProductInfo productInfo,
            TemplateNewOrderRequest newOrderRequest, bool isArray = false)
        {
            var template = (JObject)JToken.FromObject(newOrderRequest);
            var requiredForProducts =
                new JArray(template.SelectTokens(propertyPath + ".FieldData.RequiredForProducts"));
            var enrollmentFieldName = template.SelectToken(propertyPath + ".FieldData.EnrollmentFieldMapping");

            if (requiredForProducts.Count > 0)
            {
                if (requiredForProducts[0].Any(i => i.Value<string>() == "All") ||
                    requiredForProducts[0].Any(i => i.Value<string>() == productInfo.ProductID))
                    if (enrollmentFieldName != null && enrollmentFieldName.Value<string>() != "None")
                    {
                        if (productInfo.ProductParameters.ContainsKey(enrollmentFieldName.Value<string>()))
                        {
                            var enrollmentFieldValue =
                                productInfo.ProductParameters[enrollmentFieldName.Value<string>()];
                            if (isArray == false)
                                return new JProperty(propertyPath.Substring(propertyPath.LastIndexOf('.') + 1),
                                    enrollmentFieldValue);
                            return new JProperty(propertyPath.Substring(propertyPath.LastIndexOf('.') + 1),
                                CreateJArrayFromCommaSeparatedList(enrollmentFieldValue));
                        }

                        _logger.LogError(
                            $"Enrollment Field is required in the config settings but missing from the request or names do not match.: {enrollmentFieldName.Value<string>()}");
                    }
            }
            else
            {
                _logger.LogError($"Enrollment Field is in the request but missing from config settings: {propertyPath}");
            }

            return new JProperty(propertyPath.Substring(propertyPath.LastIndexOf('.') + 1), null);
        }

        private long ConvertDaysToMonths(EnrollmentProductInfo productInfo)
        {
            if (productInfo.ProductParameters.ContainsKey("Validity Period (In Days)") &&
                long.TryParse(productInfo.ProductParameters["Validity Period (In Days)"], out var days))
            {
                // Convert days to months, rounding up so short-lived certs (e.g. 90 days) get at least 1 month
                var months = (long)Math.Ceiling(days / 30.0);
                _logger.LogTrace($"Validity conversion: {days} days -> {months} months");
                return months;
            }

            _logger.LogWarning("Validity Period (In Days) not found or invalid, defaulting to 12 months");
            return 12;
        }

        private string ExtractOrgId(string organization)
        {
            if (organization != null)
            {
                Regex pattern = new Regex(@"(\([^0-9]*\d+[^0-9]*\))");
                Match match = pattern.Match(organization);
                return match.Value.Replace("(", "").Replace(")", "");
            }
            else
            {
                return null;
            }
        }
    }
}
