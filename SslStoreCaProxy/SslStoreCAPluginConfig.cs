using Keyfactor.AnyGateway.Extensions;
using System.Collections.Generic;

namespace Keyfactor.AnyGateway.SslStore
{
    public class SslStoreCAPluginConfig
    {
        public const int DefaultPageSize = 100;

        public class ConfigConstants
        {
            public static string SSLStoreURL = "SSLStoreURL";
            public static string PartnerCode = "PartnerCode";
            public static string AuthToken = "AuthToken";
            public static string PageSize = "PageSize";
            public static string Enabled = "Enabled";
            public static string RenewalWindow = "RenewalWindow";
        }

        public class Config
        {
            public string SSLStoreURL { get; set; }
            public string PartnerCode { get; set; }
            public string AuthToken { get; set; }
            public int PageSize { get; set; } = DefaultPageSize;
            public bool Enabled { get; set; }
            public int RenewalWindow { get; set; } = 30;
        }

        public static Dictionary<string, PropertyConfigInfo> GetPluginAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>()
            {
                [ConfigConstants.SSLStoreURL] = new PropertyConfigInfo()
                {
                    Comments = "The Base URL for the SSL Store API endpoint (e.g. https://sandbox-wbapi.thesslstore.com).",
                    Hidden = false,
                    DefaultValue = "https://sandbox-wbapi.thesslstore.com",
                    Type = "String"
                },
                [ConfigConstants.PartnerCode] = new PropertyConfigInfo()
                {
                    Comments = "The Partner Code obtained from SSL Store.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [ConfigConstants.AuthToken] = new PropertyConfigInfo()
                {
                    Comments = "The Authentication Token obtained from SSL Store.",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "Secret"
                },
                [ConfigConstants.PageSize] = new PropertyConfigInfo()
                {
                    Comments = "The number of records to return per page during synchronization.",
                    Hidden = false,
                    DefaultValue = DefaultPageSize,
                    Type = "Number"
                },
                [ConfigConstants.Enabled] = new PropertyConfigInfo()
                {
                    Comments = "Flag to Enable or Disable the CA connector.",
                    Hidden = false,
                    DefaultValue = true,
                    Type = "Bool"
                },
                [ConfigConstants.RenewalWindow] = new PropertyConfigInfo()
                {
                    Comments = "Number of days before order expiry to trigger a renewal instead of a reissue.",
                    Hidden = false,
                    DefaultValue = 30,
                    Type = "Number"
                }
            };
        }

        public static Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>()
            {
                ["Approver Email"] = new PropertyConfigInfo()
                {
                    Comments = "Comma-separated approver email address(es) for domain validation.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Validity Period (In Days)"] = new PropertyConfigInfo()
                {
                    Comments = "Certificate validity period in days (e.g. 90, 365, 730).",
                    Hidden = false,
                    DefaultValue = "365",
                    Type = "String"
                },
                ["Admin Contact - First Name"] = new PropertyConfigInfo()
                {
                    Comments = "Administrative contact first name.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Admin Contact - Last Name"] = new PropertyConfigInfo()
                {
                    Comments = "Administrative contact last name.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Admin Contact - Phone"] = new PropertyConfigInfo()
                {
                    Comments = "Administrative contact phone number.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Admin Contact - Email"] = new PropertyConfigInfo()
                {
                    Comments = "Administrative contact email address.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Admin Contact - Title"] = new PropertyConfigInfo()
                {
                    Comments = "Administrative contact job title.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Admin Contact - Organization Name"] = new PropertyConfigInfo()
                {
                    Comments = "Administrative contact organization name.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Admin Contact - Address"] = new PropertyConfigInfo()
                {
                    Comments = "Administrative contact street address.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Admin Contact - City"] = new PropertyConfigInfo()
                {
                    Comments = "Administrative contact city.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Admin Contact - Region"] = new PropertyConfigInfo()
                {
                    Comments = "Administrative contact state/province/region.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Admin Contact - Postal Code"] = new PropertyConfigInfo()
                {
                    Comments = "Administrative contact postal/zip code.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Admin Contact - Country"] = new PropertyConfigInfo()
                {
                    Comments = "Administrative contact two-letter country code (e.g. US).",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Technical Contact - First Name"] = new PropertyConfigInfo()
                {
                    Comments = "Technical contact first name.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Technical Contact - Last Name"] = new PropertyConfigInfo()
                {
                    Comments = "Technical contact last name.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Technical Contact - Phone"] = new PropertyConfigInfo()
                {
                    Comments = "Technical contact phone number.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Technical Contact - Email"] = new PropertyConfigInfo()
                {
                    Comments = "Technical contact email address.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Technical Contact - Organization Name"] = new PropertyConfigInfo()
                {
                    Comments = "Technical contact organization name.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Technical Contact - Address"] = new PropertyConfigInfo()
                {
                    Comments = "Technical contact street address.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Technical Contact - City"] = new PropertyConfigInfo()
                {
                    Comments = "Technical contact city.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Technical Contact - Region"] = new PropertyConfigInfo()
                {
                    Comments = "Technical contact state/province/region.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Technical Contact - Postal Code"] = new PropertyConfigInfo()
                {
                    Comments = "Technical contact postal/zip code.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Technical Contact - Country"] = new PropertyConfigInfo()
                {
                    Comments = "Technical contact two-letter country code (e.g. US).",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Organization Name"] = new PropertyConfigInfo()
                {
                    Comments = "Organization name for the certificate.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Organization Address"] = new PropertyConfigInfo()
                {
                    Comments = "Organization street address.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Organization City"] = new PropertyConfigInfo()
                {
                    Comments = "Organization city.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Organization Region"] = new PropertyConfigInfo()
                {
                    Comments = "Organization state/province/region.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Organization State/Province"] = new PropertyConfigInfo()
                {
                    Comments = "Organization state or province.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Organization Postal Code"] = new PropertyConfigInfo()
                {
                    Comments = "Organization postal/zip code.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Organization Country"] = new PropertyConfigInfo()
                {
                    Comments = "Organization two-letter country code (e.g. US).",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Organization Phone"] = new PropertyConfigInfo()
                {
                    Comments = "Organization phone number.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Organization Jurisdiction Country"] = new PropertyConfigInfo()
                {
                    Comments = "Jurisdiction country code for EV certificates.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Organization ID"] = new PropertyConfigInfo()
                {
                    Comments = "DigiCert organization ID for EO (Enterprise Organization) products.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Server Count"] = new PropertyConfigInfo()
                {
                    Comments = "Number of server licenses for the certificate.",
                    Hidden = false,
                    DefaultValue = "1",
                    Type = "String"
                },
                ["Web Server Type"] = new PropertyConfigInfo()
                {
                    Comments = "Web server type (e.g. apacheopenssl, iis, tomcat, Other).",
                    Hidden = false,
                    DefaultValue = "Other",
                    Type = "String"
                },
                ["Signature Hash Algorithm"] = new PropertyConfigInfo()
                {
                    Comments = "Signature hash algorithm (PREFER_SHA2, REQUIRE_SHA2, PREFER_SHA1).",
                    Hidden = false,
                    DefaultValue = "PREFER_SHA2",
                    Type = "String"
                },
                ["File Auth Domain Validation"] = new PropertyConfigInfo()
                {
                    Comments = "Use file-based domain validation (True/False).",
                    Hidden = false,
                    DefaultValue = "False",
                    Type = "String"
                },
                ["CName Auth Domain Validation"] = new PropertyConfigInfo()
                {
                    Comments = "Use CNAME-based domain validation (True/False).",
                    Hidden = false,
                    DefaultValue = "False",
                    Type = "String"
                },
                ["Is CU Order?"] = new PropertyConfigInfo()
                {
                    Comments = "Is this a CU (Customer) order (True/False).",
                    Hidden = false,
                    DefaultValue = "False",
                    Type = "String"
                },
                ["Is Renewal Order?"] = new PropertyConfigInfo()
                {
                    Comments = "Is this a renewal order (True/False).",
                    Hidden = false,
                    DefaultValue = "False",
                    Type = "String"
                },
                ["Is Trial Order?"] = new PropertyConfigInfo()
                {
                    Comments = "Is this a trial order (True/False).",
                    Hidden = false,
                    DefaultValue = "False",
                    Type = "String"
                }
            };
        }
    }
}
