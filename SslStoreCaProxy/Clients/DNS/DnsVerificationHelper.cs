using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using DnsClient;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

namespace Keyfactor.AnyGateway.SslStore.Clients.DNS
{
    /// <summary>
    /// Verifies DNS record propagation before relying on a Certificate Authority to poll for
    /// Domain Control Validation. Supports both TXT and CNAME records so it works with the
    /// generic DNS provider plugin framework regardless of which record type a CA requires.
    /// </summary>
    public class DnsVerificationHelper
    {
        private static readonly ILogger _logger = LogHandler.GetClassLogger<DnsVerificationHelper>();
        private readonly List<IPAddress> _dnsServers;
        private readonly bool _usePrivateDns;
        private const int DefaultMaxVerificationAttempts = 3;
        private const int DefaultVerificationDelaySeconds = 10;
        private readonly int _maxVerificationAttempts;
        private readonly int _verificationDelaySeconds;

        /// <summary>
        /// Creates a DNS verification helper.
        /// </summary>
        /// <param name="verificationServer">Optional DNS server IP for verification. For
        /// private/internal zones, specify your authoritative DNS server. Leave null/empty to
        /// use public DNS servers.</param>
        /// <param name="maxVerificationAttempts">Number of times to poll DNS for the record before
        /// giving up. Values below 1 fall back to the default.</param>
        /// <param name="verificationDelaySeconds">Seconds to wait between polling attempts. Values
        /// below 1 fall back to the default.</param>
        public DnsVerificationHelper(string verificationServer = null, int maxVerificationAttempts = DefaultMaxVerificationAttempts, int verificationDelaySeconds = DefaultVerificationDelaySeconds)
        {
            _maxVerificationAttempts = maxVerificationAttempts > 0 ? maxVerificationAttempts : DefaultMaxVerificationAttempts;
            _verificationDelaySeconds = verificationDelaySeconds > 0 ? verificationDelaySeconds : DefaultVerificationDelaySeconds;
            _dnsServers = new List<IPAddress>();

            if (!string.IsNullOrWhiteSpace(verificationServer) && IPAddress.TryParse(verificationServer, out var privateServer))
            {
                _usePrivateDns = true;
                _dnsServers.Add(privateServer);
                _logger.LogInformation("DNS verification will use private DNS server: {Server}", verificationServer);
            }
            else
            {
                _usePrivateDns = false;
                _dnsServers = new List<IPAddress>
                {
                    IPAddress.Parse("8.8.8.8"),        // Google Primary
                    IPAddress.Parse("8.8.4.4"),        // Google Secondary
                    IPAddress.Parse("1.1.1.1"),        // Cloudflare Primary
                    IPAddress.Parse("1.0.0.1"),        // Cloudflare Secondary
                    IPAddress.Parse("208.67.222.222"), // OpenDNS
                    IPAddress.Parse("9.9.9.9")         // Quad9
                };
            }
        }

        /// <summary>
        /// Waits for a DNS record to propagate across multiple DNS servers.
        /// </summary>
        /// <param name="recordName">DNS record name (e.g. _abc123.example.com)</param>
        /// <param name="expectedValue">Expected record value (TXT text or CNAME target)</param>
        /// <param name="recordType">Record type to query (TXT or CNAME)</param>
        /// <param name="minimumServers">Minimum number of public DNS servers that must see the record (ignored for private DNS)</param>
        /// <returns>True if the record propagated to enough servers</returns>
        public async Task<bool> WaitForDnsPropagationAsync(
            string recordName,
            string expectedValue,
            QueryType recordType = QueryType.CNAME,
            int minimumServers = 3)
        {
            _logger.LogInformation("Waiting for DNS propagation of {RecordType} record {RecordName}", recordType, recordName);

            var requiredServers = _usePrivateDns ? 1 : minimumServers;

            for (int attempt = 1; attempt <= _maxVerificationAttempts; attempt++)
            {
                var successCount = 0;
                var results = new List<string>();

                foreach (var dnsServer in _dnsServers)
                {
                    try
                    {
                        var hasRecord = await CheckDnsRecordAsync(recordName, expectedValue, recordType, dnsServer);
                        results.Add(hasRecord ? $"OK {dnsServer}" : $"-- {dnsServer}");
                        if (hasRecord) successCount++;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning("DNS query failed for server {Server}: {Error}", dnsServer, ex.Message);
                        results.Add($"?? {dnsServer} (error)");
                    }
                }

                _logger.LogInformation("DNS verification attempt {Attempt}/{MaxAttempts} for {RecordType} {RecordName}: {SuccessCount}/{TotalServers} resolver(s) confirmed (need {Required}). Results: {Results}",
                    attempt, _maxVerificationAttempts, recordType, recordName, successCount, _dnsServers.Count, requiredServers, string.Join(", ", results));

                if (successCount >= requiredServers)
                {
                    _logger.LogInformation("DNS record propagated successfully! {SuccessCount}/{TotalServers} servers confirmed record after {Attempt} attempt(s)",
                        successCount, _dnsServers.Count, attempt);
                    return true;
                }

                if (attempt < _maxVerificationAttempts)
                {
                    _logger.LogInformation("Waiting {Delay} seconds before next DNS verification attempt...", _verificationDelaySeconds);
                    await Task.Delay(TimeSpan.FromSeconds(_verificationDelaySeconds));
                }
            }

            var totalWaitSeconds = (_maxVerificationAttempts - 1) * _verificationDelaySeconds;
            _logger.LogWarning("DNS record did not propagate within {MaxAttempts} attempts (~{TotalSeconds} second(s))",
                _maxVerificationAttempts, totalWaitSeconds);
            return false;
        }

        /// <summary>
        /// Checks whether a specific DNS server returns the expected TXT or CNAME record.
        /// </summary>
        private async Task<bool> CheckDnsRecordAsync(string recordName, string expectedValue, QueryType recordType, IPAddress dnsServer)
        {
            var client = new LookupClient(dnsServer);
            var result = await client.QueryAsync(recordName, recordType);

            if (result.Answers?.Any() != true)
            {
                return false;
            }

            if (recordType == QueryType.CNAME)
            {
                var expected = NormalizeDnsName(expectedValue);
                var cnames = result.Answers
                    .OfType<DnsClient.Protocol.CNameRecord>()
                    .Select(r => NormalizeDnsName(r.CanonicalName.Value))
                    .ToList();

                var hasExpected = cnames.Any(c => string.Equals(c, expected, StringComparison.OrdinalIgnoreCase));
                _logger.LogTrace("DNS server {Server} returned {Count} CNAME record(s) for {RecordName}. Expected: {Expected}, Found: {HasExpected}",
                    dnsServer, cnames.Count, recordName, expected, hasExpected);
                return hasExpected;
            }

            var txtRecords = result.Answers
                .OfType<DnsClient.Protocol.TxtRecord>()
                .SelectMany(r => r.Text)
                .ToList();

            var hasValue = txtRecords.Any(txt => string.Equals(txt, expectedValue, StringComparison.OrdinalIgnoreCase));
            _logger.LogTrace("DNS server {Server} returned {Count} TXT record(s) for {RecordName}. Expected: {Expected}, Found: {HasExpected}",
                dnsServer, txtRecords.Count, recordName, expectedValue, hasValue);
            return hasValue;
        }

        /// <summary>
        /// Gets the authoritative DNS servers for a domain (best-effort, for diagnostics).
        /// </summary>
        public async Task<List<IPAddress>> GetAuthoritativeDnsServersAsync(string domain)
        {
            var authServers = new List<IPAddress>();

            try
            {
                var client = new LookupClient();
                var result = await client.QueryAsync(domain, QueryType.NS);

                foreach (var nsRecord in result.Answers.OfType<DnsClient.Protocol.NsRecord>())
                {
                    try
                    {
                        var nsResult = await client.QueryAsync(nsRecord.NSDName, QueryType.A);
                        authServers.AddRange(nsResult.Answers.OfType<DnsClient.Protocol.ARecord>().Select(a => a.Address));
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning("Failed to resolve NS record {NSName}: {Error}", nsRecord.NSDName, ex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Failed to get authoritative DNS servers for {Domain}: {Error}", domain, ex.Message);
            }

            return authServers.Distinct().ToList();
        }

        private static string NormalizeDnsName(string name)
        {
            return string.IsNullOrEmpty(name) ? name : name.TrimEnd('.');
        }
    }
}
