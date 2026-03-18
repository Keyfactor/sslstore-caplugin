using System;
using System.Collections.Generic;
using System.Linq;
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
            return BuildNewOrderRequest(productInfo, pemCsr, subject, san, isRenewalOrder);
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
                    return (int)EndEntityStatus.EXTERNALVALIDATION;
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
            string csr, string subject, Dictionary<string, string[]> san, bool isRenewal)
        {
            var p = productInfo.ProductParameters;

            // Extract domain name from CSR subject CN
            var domainName = subject?.Split(',')
                .Select(part => part.Trim())
                .Where(part => part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                .Select(part => part.Substring(3))
                .FirstOrDefault() ?? "";

            // Extract DNS SANs from Keyfactor san parameter
            var dnsNames = san != null && san.ContainsKey("dns") ? san["dns"].ToList() : new List<string>();

            return new NewOrderRequest
            {
                AuthRequest = GetAuthRequest(),
                ProductCode = productInfo.ProductID.Replace("-EO", ""),
                CustomOrderId = Guid.NewGuid().ToString(),
                TssOrganizationId = p.ContainsKey("Organization ID") ? long.TryParse(ExtractOrgId(p["Organization ID"]), out var orgId) ? orgId : 0 : 0,
                OrganizationInfo = new OrganizationInfo
                {
                    OrganizationName = GetParam(p, "Organization Name"),
                    JurisdictionCountry = GetParam(p, "Organization Jurisdiction Country"),
                    OrganizationAddress = new OrganizationAddress
                    {
                        AddressLine1 = GetParam(p, "Organization Address"),
                        Region = GetParam(p, "Organization Region") ?? GetParam(p, "Organization State/Province"),
                        PostalCode = GetParam(p, "Organization Postal Code"),
                        Country = GetParam(p, "Organization Country"),
                        Phone = GetParam(p, "Organization Phone"),
                        LocalityName = GetParam(p, "Organization City")
                    }
                },
                ValidityPeriod = ConvertDaysToMonths(productInfo),
                ServerCount = 1,
                Csr = csr,
                DomainName = domainName,
                WebServerType = GetParam(p, "Web Server Type") ?? "Other",
                DnsNames = dnsNames,
                IsCuOrder = false,
                IsRenewalOrder = isRenewal,
                IsTrialOrder = false,
                AdminContact = new AdminContact
                {
                    FirstName = GetParam(p, "Admin Contact - First Name"),
                    LastName = GetParam(p, "Admin Contact - Last Name"),
                    Phone = GetParam(p, "Admin Contact - Phone"),
                    Email = GetParam(p, "Admin Contact - Email"),
                    Title = GetParam(p, "Admin Contact - Title"),
                    OrganizationName = GetParam(p, "Admin Contact - Organization Name"),
                    AddressLine1 = GetParam(p, "Admin Contact - Address"),
                    City = GetParam(p, "Admin Contact - City"),
                    Region = GetParam(p, "Admin Contact - Region"),
                    PostalCode = GetParam(p, "Admin Contact - Postal Code"),
                    Country = GetParam(p, "Admin Contact - Country")
                },
                TechnicalContact = new TechnicalContact
                {
                    FirstName = GetParam(p, "Technical Contact - First Name"),
                    LastName = GetParam(p, "Technical Contact - Last Name"),
                    Phone = GetParam(p, "Technical Contact - Phone"),
                    Email = GetParam(p, "Technical Contact - Email"),
                    Title = GetParam(p, "Technical Contact - Title"),
                    OrganizationName = GetParam(p, "Technical Contact - Organization Name"),
                    AddressLine1 = GetParam(p, "Technical Contact - Address"),
                    City = GetParam(p, "Technical Contact - City"),
                    Region = GetParam(p, "Technical Contact - Region"),
                    PostalCode = GetParam(p, "Technical Contact - Postal Code"),
                    Country = GetParam(p, "Technical Contact - Country")
                },
                ApproverEmail = GetParam(p, "Approver Email"),
                FileAuthDvIndicator = false,
                CnameAuthDvIndicator = false,
                SignatureHashAlgorithm = GetParam(p, "Signature Hash Algorithm") ?? "PREFER_SHA2"
            };
        }

        private static string GetParam(Dictionary<string, string> parameters, string key)
        {
            return parameters.ContainsKey(key) ? parameters[key] : null;
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

        private long ConvertDaysToMonths(EnrollmentProductInfo productInfo)
        {
            if (productInfo.ProductParameters.ContainsKey("Validity Period (In Days)") &&
                long.TryParse(productInfo.ProductParameters["Validity Period (In Days)"], out var days))
            {
                // Round to nearest standard month value (30.44 days/month average)
                // SSL Store only accepts specific values like 1, 3, 6, 12, 24, 36, etc.
                var months = Math.Max(1, (long)Math.Round(days / 30.44));
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
