using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.AnyGateway.SslStore.Client.Models;
using Keyfactor.AnyGateway.SslStore.Exceptions;
using Keyfactor.AnyGateway.SslStore.Interfaces;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Keyfactor.AnyGateway.SslStore.Client
{
    public sealed class SslStoreClient : ISslStoreClient
    {
        private static readonly ILogger _logger = LogHandler.GetClassLogger<SslStoreClient>();

        // Use an explicit JsonSerializer to ensure [JsonProperty] attributes are respected,
        // regardless of the host application's global JsonConvert.DefaultSettings.
        private static readonly JsonSerializer _serializer = new JsonSerializer
        {
            ContractResolver = new DefaultContractResolver(),
            NullValueHandling = NullValueHandling.Ignore
        };

        private static string Serialize(object obj)
        {
            var sb = new StringBuilder();
            using (var sw = new System.IO.StringWriter(sb))
            using (var jw = new JsonTextWriter(sw))
            {
                _serializer.Serialize(jw, obj);
            }
            return sb.ToString();
        }

        public SslStoreClient(IAnyCAPluginConfigProvider config)
        {
            if (config.CAConnectionData.ContainsKey(Constants.SslStoreUrl))
            {
                BaseUrl = new Uri(config.CAConnectionData[Constants.SslStoreUrl].ToString());
                RestClient = ConfigureRestClient();
            }
        }

        private Uri BaseUrl { get; }
        private HttpClient RestClient { get; }
        private int PageSize { get; } = 100;

        public async Task<NewOrderResponse> SubmitNewOrderRequestAsync(NewOrderRequest newOrderRequest)
        {
            using (var resp = await RestClient.PostAsync("/rest/order/neworder", new StringContent(
                Serialize(newOrderRequest), Encoding.UTF8, "application/json")))
            {
                _logger.LogTrace(Serialize(newOrderRequest));
                resp.EnsureSuccessStatusCode();
                var enrollmentResponse =
                    JsonConvert.DeserializeObject<NewOrderResponse>(await resp.Content.ReadAsStringAsync());
                return enrollmentResponse;
            }
        }

        public async Task<EmailApproverResponse> SubmitEmailApproverRequestAsync(EmailApproverRequest newApproverRequest)
        {
            using (var resp = await RestClient.PostAsync("/rest/order/approverlist", new StringContent(
                Serialize(newApproverRequest), Encoding.UTF8, "application/json")))
            {
                _logger.LogTrace(Serialize(newApproverRequest));
                resp.EnsureSuccessStatusCode();
                var enrollmentResponse =
                    JsonConvert.DeserializeObject<EmailApproverResponse>(await resp.Content.ReadAsStringAsync());
                return enrollmentResponse;
            }
        }

        public async Task<NewOrderResponse> SubmitReIssueRequestAsync(ReIssueRequest reIssueOrderRequest)
        {
            using (var resp = await RestClient.PostAsync("/rest/order/reissue", new StringContent(
                Serialize(reIssueOrderRequest), Encoding.UTF8, "application/json")))
            {
                var orderStatusResponse =
                    JsonConvert.DeserializeObject<NewOrderResponse>(await resp.Content.ReadAsStringAsync());
                return orderStatusResponse;
            }
        }

        public async Task<NewOrderResponse> SubmitRenewRequestAsync(NewOrderRequest renewOrderRequest)
        {
            using (var resp = await RestClient.PostAsync("/rest/order/neworder", new StringContent(
                Serialize(renewOrderRequest), Encoding.UTF8, "application/json")))
            {
                _logger.LogTrace(Serialize(renewOrderRequest));
                resp.EnsureSuccessStatusCode();
                var enrollmentResponse =
                    JsonConvert.DeserializeObject<NewOrderResponse>(await resp.Content.ReadAsStringAsync());
                return enrollmentResponse;
            }
        }

        public async Task<IDownloadCertificateResponse> SubmitDownloadCertificateAsync(
            DownloadCertificateRequest downloadOrderRequest)
        {
            using (var resp = await RestClient.PostAsync("/rest/order/download", new StringContent(
                Serialize(downloadOrderRequest), Encoding.UTF8, "application/json")))
            {
                _logger.LogTrace(Serialize(downloadOrderRequest));
                resp.EnsureSuccessStatusCode();
                var downloadOrderResponse =
                    JsonConvert.DeserializeObject<DownloadCertificateResponse>(await resp.Content.ReadAsStringAsync());
                return downloadOrderResponse;
            }
        }

        public async Task SubmitQueryOrderRequestAsync(BlockingCollection<INewOrderResponse> bc, CancellationToken ct,
            RequestManager requestManager)
        {
            _logger.MethodEntry();
            try
            {
                var itemsProcessed = 0;
                var pageCounter = 0;
                var isComplete = false;
                var retryCount = 0;
                do
                {
                    pageCounter++;
                    var queryOrderRequest = requestManager.GetQueryOrderRequest(PageSize, pageCounter);
                    var batchItemsProcessed = 0;
                    using (var resp = await RestClient.PostAsync("/rest/order/query", new StringContent(
                        Serialize(queryOrderRequest), Encoding.UTF8, "application/json")))
                    {
                        if (!resp.IsSuccessStatusCode)
                        {
                            var responseMessage = resp.Content.ReadAsStringAsync().Result;
                            _logger.LogError(
                                $"Failed Request to SslStore. Retrying request. Status Code {resp.StatusCode} | Message: {responseMessage}");
                            retryCount++;
                            if (retryCount > 5)
                                throw new RetryCountExceededException(
                                    $"5 consecutive failures to {resp.RequestMessage.RequestUri}");

                            continue;
                        }

                        var batchResponse =
                            JsonConvert.DeserializeObject<List<NewOrderResponse>>(
                                await resp.Content.ReadAsStringAsync());

                        _logger.LogTrace($"Order List JSON {Serialize(batchResponse)}");

                        var batchCount = batchResponse.Count;

                        _logger.LogTrace($"Processing {batchCount} items in batch");
                        do
                        {
                            var r = batchResponse[batchItemsProcessed];
                            if (bc.TryAdd(r, 10, ct))
                            {
                                _logger.LogTrace($"Added Certificate ID {r.TheSslStoreOrderId} to Queue for processing");
                                batchItemsProcessed++;
                                itemsProcessed++;
                                _logger.LogTrace($"Processed {batchItemsProcessed} of {batchCount}");
                                _logger.LogTrace($"Total Items Processed: {itemsProcessed}");
                            }
                            else
                            {
                                _logger.LogTrace($"Adding {r} blocked. Retry");
                            }
                        } while (batchItemsProcessed < batchCount);
                    }

                    if (batchItemsProcessed < PageSize)
                        isComplete = true;
                } while (!isComplete);

                bc.CompleteAdding();
            }
            catch (OperationCanceledException cancelEx)
            {
                _logger.LogWarning($"Synchronize method was cancelled. Message: {cancelEx.Message}");
                bc.CompleteAdding();
                _logger.MethodExit();
                throw;
            }
            catch (RetryCountExceededException retryEx)
            {
                _logger.LogError($"Retries Failed: {retryEx.Message}");
                _logger.MethodExit();
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError($"HttpRequest Failed: {ex.Message}");
                _logger.MethodExit();
            }

            _logger.MethodExit();
        }

        public async Task<IOrderStatusResponse> SubmitRevokeCertificateAsync(RevokeOrderRequest revokeOrderRequest)
        {
            using (var resp = await RestClient.PostAsync("/rest/order/refundrequest", new StringContent(
                Serialize(revokeOrderRequest), Encoding.UTF8, "application/json")))
            {
                var revocationResponse =
                    JsonConvert.DeserializeObject<OrderStatusResponse>(await resp.Content.ReadAsStringAsync());
                return revocationResponse;
            }
        }

        public async Task<INewOrderResponse> SubmitOrderStatusRequestAsync(OrderStatusRequest orderStatusRequest)
        {
            using (var resp = await RestClient.PostAsync("/rest/order/status", new StringContent(
                Serialize(orderStatusRequest), Encoding.UTF8, "application/json")))
            {
                var orderStatusResponse =
                    JsonConvert.DeserializeObject<NewOrderResponse>(await resp.Content.ReadAsStringAsync());
                return orderStatusResponse;
            }
        }

        public async Task<IOrganizationResponse> SubmitOrganizationListAsync(OrganizationListRequest organizationListRequest)
        {
            using (var resp = await RestClient.PostAsync("/rest/digicert/organizationlist", new StringContent(
                Serialize(organizationListRequest), Encoding.UTF8, "application/json")))
            {
                var organizationListResponse =
                    JsonConvert.DeserializeObject<OrganizationResponse>(await resp.Content.ReadAsStringAsync());
                return organizationListResponse;
            }
        }

        private HttpClient ConfigureRestClient()
        {
            var clientHandler = new HttpClientHandler();
            var returnClient = new HttpClient(clientHandler, true) { BaseAddress = BaseUrl };
            returnClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            return returnClient;
        }
    }
}
