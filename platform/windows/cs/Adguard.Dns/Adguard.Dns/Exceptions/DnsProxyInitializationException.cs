using System;

namespace Adguard.Dns.Exceptions
{
    /// <summary>
    /// Represents an exception that occurred during dns proxy server initialization.
    /// </summary>
    public class DnsProxyInitializationException : InvalidOperationException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DnsProxyInitializationException"/> class.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="result">Dns proxy server initialization result</param>
        public DnsProxyInitializationException(string message, AGDnsApi.ag_dnsproxy_init_result result) : base(message)
        {
            ProxyInitResult = result;
        }

        /// <summary>
        /// Dns proxy initialization result
        /// </summary>
        public AGDnsApi.ag_dnsproxy_init_result ProxyInitResult { get; set; }
    }
}