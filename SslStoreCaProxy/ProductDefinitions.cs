using System.Collections.Generic;
using System.Linq;
using Keyfactor.AnyGateway.SslStore.Client.Models;

namespace Keyfactor.AnyGateway.SslStore
{
    /// <summary>
    /// Static registry of all SSL Store products and their enrollment fields.
    /// Template-level properties (Id, OID, KeySize, etc.) are configured in Keyfactor Command.
    /// </summary>
    public static class ProductDefinitions
    {
        private static int _nextFieldId = 1;

        #region Shared Option Lists

        private static readonly List<string> ValidityStandard = new List<string> { "12", "24", "36", "48", "60" };
        private static readonly List<string> ValidityExtended = new List<string> { "6", "12", "24", "36", "48", "60" };
        private static readonly List<string> ValidityDigicert = new List<string> { "12", "24", "36", "48", "60", "72" };

        private static readonly List<string> BoolOptions = new List<string> { "False", "True" };

        private static readonly List<string> CountryCodes = new List<string>
        {
            "US","AF","AX","AL","DZ","AS","AD","AO","AI","AQ","AG","AR","AM","AW","AU","AT","AZ",
            "BS","BH","BD","BB","BY","BE","BZ","BJ","BM","BT","BO","BQ","BA","BW","BV","BR","IO",
            "BN","BG","BF","BI","CV","KH","CM","CA","KY","CF","TD","CL","CN","CX","CC","CO","KM",
            "CG","CD","CK","CR","CI","HR","CU","CW","CY","CZ","DK","DJ","DM","DO","EC","EG","SV",
            "GQ","ER","EE","SZ","ET","FK","FO","FJ","FI","FR","GF","PF","TF","GA","GM","GE","DE",
            "GH","GI","GR","GL","GD","GP","GU","GT","GG","GN","GW","GY","HT","HM","VA","HN","HK",
            "HU","IS","IN","ID","IR","IQ","IE","IM","IL","IT","JM","JP","JE","JO","KZ","KE","KI",
            "KP","KR","KW","KG","LA","LV","LB","LS","LR","LY","LI","LT","LU","MO","MG","MW","MY",
            "MV","ML","MT","MH","MQ","MR","MU","YT","MX","FM","MD","MC","MN","ME","MS","MA","MZ",
            "MM","NA","NR","NP","NL","NC","NZ","NI","NE","NG","NU","NF","MK","MP","NO","OM","PK",
            "PW","PS","PA","PG","PY","PE","PH","PN","PL","PT","PR","QA","RE","RO","RU","RW","BL",
            "SH","KN","LC","MF","PM","VC","WS","SM","ST","SA","SN","RS","SC","SL","SG","SX","SK",
            "SI","SB","SO","ZA","GS","SS","ES","LK","SD","SR","SJ","SE","CH","SY","TW","TJ","TZ",
            "TH","TL","TG","TK","TO","TT","TN","TR","TM","TC","TV","UG","UA","AE","GB","UM","UY",
            "UZ","VU","VE","VN","VG","VI","WF","EH","YE","ZM","ZW"
        };

        private static readonly List<string> SignatureHashAlgorithms = new List<string>
        {
            "PREFER_SHA2", "REQUIRE_SHA2", "PREFER_SHA1", ""
        };

        private static readonly List<string> WebServerTypes = new List<string>
        {
            "aol","apachessl","apacheraven","apachessleay","iis","iis4","iis5","c2net","Ibmhttp",
            "Ibminternet","Iplanet","Dominogo4625","Dominogo4626","Domino","Netscape",
            "NetscapeFastTrack","zeusv3","Other","apacheopenssl","apache2","apacheapachessl",
            "cobaltseries","covalentserver","cpanel","ensim","hsphere","ipswitch","plesk","tomcat",
            "WebLogic","website","webstar","sapwebserver","webten","redhat","reven","r3ssl","quid",
            "oracle","javawebserver","cisco3000","citrix"
        };

        #endregion

        #region Enrollment Field Builders

        private static EnrollmentField TextField(string name)
        {
            return new EnrollmentField { Id = _nextFieldId++, Name = name, Options = new List<string> { "" }, DataType = 1 };
        }

        private static EnrollmentField DropdownField(string name, List<string> options)
        {
            return new EnrollmentField { Id = _nextFieldId++, Name = name, Options = new List<string>(options), DataType = 2 };
        }

        // Group 1: Legacy Full (36 fields) - comodossl, comodoevssl, etc.
        private static List<EnrollmentField> LegacyFullFields(List<string> validity)
        {
            return new List<EnrollmentField>
            {
                DropdownField("Is CU Order?", BoolOptions),
                DropdownField("Is Renewal Order?", BoolOptions),
                DropdownField("Is Trial Order?", BoolOptions),
                TextField("Admin Contact - First Name"),
                TextField("Admin Contact - Last Name"),
                TextField("Admin Contact - Phone"),
                TextField("Admin Contact - Email"),
                TextField("Admin Contact - Organization Name"),
                TextField("Admin Contact - Address"),
                TextField("Admin Contact - City"),
                TextField("Admin Contact - Region"),
                TextField("Admin Contact - Postal Code"),
                DropdownField("Admin Contact - Country", CountryCodes),
                TextField("Technical Contact - First Name"),
                TextField("Technical Contact - Last Name"),
                TextField("Technical Contact - Phone"),
                TextField("Technical Contact - Email"),
                TextField("Technical Contact - Organization Name"),
                TextField("Technical Contact - Address"),
                TextField("Technical Contact - City"),
                TextField("Technical Contact - Region"),
                TextField("Technical Contact - Postal Code"),
                DropdownField("Technical Contact - Country", CountryCodes),
                TextField("Approver Email"),
                DropdownField("File Auth Domain Validation", BoolOptions),
                DropdownField("CName Auth Domain Validation", BoolOptions),
                DropdownField("Signature Hash Algorithm", SignatureHashAlgorithms),
                DropdownField("Web Server Type", WebServerTypes),
                TextField("Server Count"),
                DropdownField("Validity Period (In Months)", validity),
                TextField("Organization Name"),
                TextField("Organization Address"),
                TextField("Organization Region"),
                TextField("Organization Postal Code"),
                TextField("Organization Country"),
                TextField("Organization Phone")
            };
        }

        // Group 1b: Legacy Full + DNS Names + Jurisdiction (38 fields) - digi_quickssl_md
        private static List<EnrollmentField> LegacyFullDnsJurisdictionFields(List<string> validity)
        {
            var fields = new List<EnrollmentField> { TextField("DNS Names Comma Separated") };
            fields.AddRange(LegacyFullFields(validity));
            // Insert Jurisdiction Country before Organization Phone (at the end)
            fields.Insert(fields.Count - 1, DropdownField("Organization Jurisdiction Country", CountryCodes));
            return fields;
        }

        // Group 2: EO Minimal (3 fields) - digi_*-EO products, digi_securesite_pro_flex
        private static List<EnrollmentField> EoMinimalFields()
        {
            return new List<EnrollmentField>
            {
                TextField("DNS Names Comma Separated"),
                DropdownField("Validity Period (In Months)", ValidityDigicert),
                DropdownField("Organization ID", new List<string>())
            };
        }

        // Group 3: Sectigo/Comodo OV (9 fields) - instantssl, comodopremiumssl, etc.
        private static List<EnrollmentField> SectigoOvFields()
        {
            return new List<EnrollmentField>
            {
                TextField("Admin Contact - Email"),
                TextField("Approver Email"),
                DropdownField("Validity Period (In Months)", ValidityStandard),
                TextField("Organization Name"),
                TextField("Organization Address"),
                TextField("Organization State/Province"),
                TextField("Organization Postal Code"),
                DropdownField("Organization Country", CountryCodes),
                TextField("Organization Phone")
            };
        }

        // Group 4: DigiCert OV Flex (14 fields) - digi_securesite_flex, digi_sslwebserver_flex, etc.
        private static List<EnrollmentField> DigiCertOvFlexFields()
        {
            return new List<EnrollmentField>
            {
                TextField("DNS Names Comma Separated"),
                TextField("Admin Contact - First Name"),
                TextField("Admin Contact - Last Name"),
                TextField("Admin Contact - Phone"),
                TextField("Admin Contact - Email"),
                TextField("Approver Email"),
                DropdownField("Validity Period (In Months)", ValidityDigicert),
                TextField("Organization Name"),
                TextField("Organization Address"),
                TextField("Organization City"),
                TextField("Organization State/Province"),
                TextField("Organization Postal Code"),
                DropdownField("Organization Country", CountryCodes),
                TextField("Organization Phone")
            };
        }

        // Group 5: DV Minimal (3 fields) - positivessl, sectigossl, etc.
        private static List<EnrollmentField> DvMinimalFields()
        {
            return new List<EnrollmentField>
            {
                TextField("Admin Contact - Email"),
                TextField("Approver Email"),
                DropdownField("Validity Period (In Months)", ValidityStandard)
            };
        }

        // Group 6: DigiCert EV Flex (15 fields) - digi_securesite_ev_flex, digi_ssl_ev_basic, etc.
        private static List<EnrollmentField> DigiCertEvFlexFields(string regionFieldName = "Organization State/Province")
        {
            return new List<EnrollmentField>
            {
                TextField("DNS Names Comma Separated"),
                TextField("Admin Contact - First Name"),
                TextField("Admin Contact - Last Name"),
                TextField("Admin Contact - Phone"),
                TextField("Admin Contact - Email"),
                TextField("Admin Contact - Title"),
                TextField("Approver Email"),
                DropdownField("Validity Period (In Months)", ValidityDigicert),
                TextField("Organization Name"),
                TextField("Organization Address"),
                TextField("Organization City"),
                TextField(regionFieldName),
                TextField("Organization Postal Code"),
                DropdownField("Organization Country", CountryCodes),
                TextField("Organization Phone")
            };
        }

        // Group 7: DV MDC (4 fields) - positivemdcssl, sectigodvucc, etc.
        private static List<EnrollmentField> DvMdcFields()
        {
            return new List<EnrollmentField>
            {
                TextField("DNS Names Comma Separated"),
                TextField("Admin Contact - Email"),
                TextField("Approver Email"),
                DropdownField("Validity Period (In Months)", ValidityStandard)
            };
        }

        // Group 8: DigiCert DV RapidSSL (3 fields) - digi_rapidssl, digi_rapidssl_wc
        private static List<EnrollmentField> DigiCertDvRapidSslFields()
        {
            return new List<EnrollmentField>
            {
                TextField("Technical Contact - Email"),
                TextField("Approver Email"),
                DropdownField("Validity Period (In Months)", ValidityDigicert)
            };
        }

        // Group 9: DigiCert DV GeoTrust/SSL123 (4 fields) - digi_ssl_dv_geotrust_flex, digi_ssl123_flex
        private static List<EnrollmentField> DigiCertDvGeoTrustFields()
        {
            return new List<EnrollmentField>
            {
                TextField("DNS Names Comma Separated"),
                TextField("Technical Contact - Email"),
                TextField("Approver Email"),
                DropdownField("Validity Period (In Months)", ValidityDigicert)
            };
        }

        // Group 10: EV with Jurisdiction (10 fields) - enterpriseproev, positiveevssl
        private static List<EnrollmentField> EvJurisdictionFields()
        {
            return new List<EnrollmentField>
            {
                TextField("Admin Contact - Email"),
                TextField("Approver Email"),
                DropdownField("Validity Period (In Months)", ValidityStandard),
                TextField("Organization Name"),
                TextField("Organization Address"),
                TextField("Organization State/Province"),
                TextField("Organization Postal Code"),
                DropdownField("Organization Country", CountryCodes),
                DropdownField("Organization Jurisdiction Country", CountryCodes),
                TextField("Organization Phone")
            };
        }

        // Group 11: EV MDC with Jurisdiction (11 fields) - positiveevmdc, sectigoevmdc
        private static List<EnrollmentField> EvMdcJurisdictionFields()
        {
            return new List<EnrollmentField>
            {
                TextField("DNS Names Comma Separated"),
                TextField("Admin Contact - Email"),
                TextField("Approver Email"),
                DropdownField("Validity Period (In Months)", ValidityStandard),
                TextField("Organization Name"),
                TextField("Organization Address"),
                TextField("Organization State/Province"),
                TextField("Organization Postal Code"),
                DropdownField("Organization Country", CountryCodes),
                DropdownField("Organization Jurisdiction Country", CountryCodes),
                TextField("Organization Phone")
            };
        }

        // Group 11b: EV MDC with Jurisdiction (Country before Jurisdiction) - enterpriseproevmdc
        private static List<EnrollmentField> EvMdcJurisdictionAltFields()
        {
            return new List<EnrollmentField>
            {
                TextField("DNS Names Comma Separated"),
                TextField("Admin Contact - Email"),
                TextField("Approver Email"),
                DropdownField("Validity Period (In Months)", ValidityStandard),
                TextField("Organization Name"),
                TextField("Organization Address"),
                TextField("Organization State/Province"),
                TextField("Organization Postal Code"),
                DropdownField("Organization Jurisdiction Country", CountryCodes),
                DropdownField("Organization Country", CountryCodes),
                TextField("Organization Phone")
            };
        }

        // Group 12: OV MDC (10 fields) - sectigomdc, sectigomdcwildcard
        private static List<EnrollmentField> OvMdcFields()
        {
            return new List<EnrollmentField>
            {
                TextField("DNS Names Comma Separated"),
                TextField("Admin Contact - Email"),
                TextField("Approver Email"),
                DropdownField("Validity Period (In Months)", ValidityStandard),
                TextField("Organization Name"),
                TextField("Organization Address"),
                TextField("Organization State/Province"),
                TextField("Organization Postal Code"),
                DropdownField("Organization Country", CountryCodes),
                TextField("Organization Phone")
            };
        }

        // Group 15: Enterprise Pro OV (9 fields) - enterprisepro (Admin First Name instead of Email)
        private static List<EnrollmentField> EnterpriseProOvFields()
        {
            return new List<EnrollmentField>
            {
                TextField("Admin Contact - First Name"),
                TextField("Approver Email"),
                DropdownField("Validity Period (In Months)", ValidityStandard),
                TextField("Organization Name"),
                TextField("Organization Address"),
                TextField("Organization State/Province"),
                TextField("Organization Postal Code"),
                DropdownField("Organization Country", CountryCodes),
                TextField("Organization Phone")
            };
        }

        #endregion

        #region Product Registry

        private static readonly Dictionary<string, List<EnrollmentField>> _products = BuildRegistry();

        private static Dictionary<string, List<EnrollmentField>> BuildRegistry()
        {
            var registry = new Dictionary<string, List<EnrollmentField>>();

            // --- Group 1: Legacy Full (validity: 6,12,24,36,48,60) ---
            foreach (var code in new[]
            {
                "comododvucc", "comodoevcsc", "comodoevmdc", "comodoevssl", "comodomdc",
                "comodomdcwildcard", "comodopciscan", "comodossl", "comodoucc",
                "comodouccwildcard", "comodowildcard", "digi_client_premium", "digi_csc",
                "digi_csc_ev", "digi_doc_signing_ind_2000", "digi_doc_signing_ind_500",
                "digi_doc_signing_org_2000", "digi_doc_signing_org_5000",
                "elitessl", "enterprisessl", "essentialssl", "essentialwildcard",
                "hackerprooftm", "hgpcicontrolscan", "pacbasic", "pacpro", "pacenterprise"
            })
            {
                registry[code] = LegacyFullFields(ValidityExtended);
            }

            // comodocsc: Legacy Full but with standard validity (12,24,36,48,60)
            registry["comodocsc"] = LegacyFullFields(ValidityStandard);

            // --- Group 1b: Legacy Full + DNS + Jurisdiction ---
            registry["digi_quickssl_md"] = LegacyFullDnsJurisdictionFields(ValidityExtended);

            // --- Group 2: EO Minimal ---
            foreach (var code in new[]
            {
                "digi_securesite_ev_flex-EO", "digi_securesite_flex-EO",
                "digi_securesite_pro_ev_flex-EO", "digi_securesite_pro_flex",
                "digi_securesite_pro_flex-EO", "digi_ssl_basic-EO", "digi_ssl_ev_basic-EO",
                "digi_sslwebserver_ev_flex-EO", "digi_sslwebserver_flex-EO",
                "digi_truebizid_ev_flex-EO", "digi_truebizid_flex-EO"
            })
            {
                registry[code] = EoMinimalFields();
            }

            // --- Group 3: Sectigo/Comodo OV ---
            foreach (var code in new[]
            {
                "comodopremiumssl", "comodopremiumwildcard", "enterpriseprowc",
                "instantssl", "instantsslpro", "sectigoovssl", "sectigoovwildcard"
            })
            {
                registry[code] = SectigoOvFields();
            }

            // --- Group 4: DigiCert OV Flex ---
            foreach (var code in new[]
            {
                "digi_securesite_flex", "digi_ssl_basic",
                "digi_sslwebserver_flex", "digi_truebizid_flex"
            })
            {
                registry[code] = DigiCertOvFlexFields();
            }

            // --- Group 5: DV Minimal ---
            foreach (var code in new[]
            {
                "positivessl", "positivesslwildcard", "sectigoevssl",
                "sectigossl", "sectigowildcard"
            })
            {
                registry[code] = DvMinimalFields();
            }

            // --- Group 6: DigiCert EV Flex (State/Province) ---
            foreach (var code in new[]
            {
                "digi_securesite_ev_flex", "digi_ssl_ev_basic",
                "digi_sslwebserver_ev_flex", "digi_truebizid_ev_flex"
            })
            {
                registry[code] = DigiCertEvFlexFields();
            }

            // Group 6b: DigiCert EV Flex with "Organization Region" instead of "State/Province"
            registry["digi_securesite_pro_ev_flex"] = DigiCertEvFlexFields("Organization Region");

            // --- Group 7: DV MDC ---
            foreach (var code in new[]
            {
                "positivemdcssl", "positivemdcwildcard", "sectigodvucc", "sectigouccwildcard"
            })
            {
                registry[code] = DvMdcFields();
            }

            // --- Group 8: DigiCert DV RapidSSL ---
            registry["digi_rapidssl"] = DigiCertDvRapidSslFields();
            registry["digi_rapidssl_wc"] = DigiCertDvRapidSslFields();

            // --- Group 9: DigiCert DV GeoTrust/SSL123 ---
            registry["digi_ssl_dv_geotrust_flex"] = DigiCertDvGeoTrustFields();
            registry["digi_ssl123_flex"] = DigiCertDvGeoTrustFields();

            // --- Group 10: EV with Jurisdiction ---
            registry["enterpriseproev"] = EvJurisdictionFields();
            registry["positiveevssl"] = EvJurisdictionFields();

            // --- Group 11: EV MDC with Jurisdiction ---
            registry["positiveevmdc"] = EvMdcJurisdictionFields();
            registry["sectigoevmdc"] = EvMdcJurisdictionFields();

            // --- Group 11b: EV MDC Jurisdiction (alt field order) ---
            registry["enterpriseproevmdc"] = EvMdcJurisdictionAltFields();

            // --- Group 12: OV MDC ---
            registry["sectigomdc"] = OvMdcFields();
            registry["sectigomdcwildcard"] = OvMdcFields();

            // --- Group 15: Enterprise Pro OV ---
            registry["enterprisepro"] = EnterpriseProOvFields();

            return registry;
        }

        #endregion

        #region Public API

        public static List<string> GetProductIds()
        {
            return _products.Keys.ToList();
        }

        public static List<EnrollmentField> GetEnrollmentFields(string productCode)
        {
            return _products.TryGetValue(productCode, out var fields) ? fields : null;
        }

        #endregion
    }
}
