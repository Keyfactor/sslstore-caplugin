using Keyfactor.AnyGateway.SslStore.Interfaces;
using Newtonsoft.Json;

namespace Keyfactor.AnyGateway.SslStore.Client.Models
{
    public class RevokeOrderRequest : IRevokeOrderRequest
    {
        public AuthRequest AuthRequest { get; set; }
        [JsonProperty("TheSSLStoreOrderID", NullValueHandling = NullValueHandling.Ignore)] public string TheSslStoreOrderId { get; set; }
        [JsonProperty("CustomOrderID", NullValueHandling = NullValueHandling.Ignore)] public string CustomOrderId { get; set; }
        public string SerialNumber { get; set; }
    }
}
