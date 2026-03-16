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
        }

        public class Config
        {
            public string SSLStoreURL { get; set; }
            public string PartnerCode { get; set; }
            public string AuthToken { get; set; }
            public int PageSize { get; set; } = DefaultPageSize;
            public bool Enabled { get; set; }
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
                }
            };
        }

        public static Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>()
            {
            };
        }
    }
}
