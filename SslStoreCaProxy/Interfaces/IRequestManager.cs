using Keyfactor.AnyGateway.Extensions;
using Keyfactor.AnyGateway.SslStore.Client.Models;

namespace Keyfactor.AnyGateway.SslStore.Interfaces
{
    public interface IRequestManager
    {
        NewOrderRequest GetEnrollmentRequest(string csr, EnrollmentProductInfo productInfo,
            IAnyCAPluginConfigProvider configProvider, bool isRenewalOrder);

        AuthRequest GetAuthRequest();
        ReIssueRequest GetReIssueRequest(INewOrderResponse orderData, string csr, bool isRenewal);
        AdminContact GetAdminContact(EnrollmentProductInfo productInfo);
        TechnicalContact GetTechnicalContact(EnrollmentProductInfo productInfo);
        DownloadCertificateRequest GetCertificateRequest(string theSslStoreOrderId);
        RevokeOrderRequest GetRevokeOrderRequest(string theSslStoreOrderId);
        int GetClientPageSize(IAnyCAPluginConfigProvider config);
        QueryOrderRequest GetQueryOrderRequest(int pageSize, int pageNumber);
        OrderStatusRequest GetOrderStatusRequest(string theSslStoreId);
        int MapReturnStatus(string sslStoreStatus);
    }
}
