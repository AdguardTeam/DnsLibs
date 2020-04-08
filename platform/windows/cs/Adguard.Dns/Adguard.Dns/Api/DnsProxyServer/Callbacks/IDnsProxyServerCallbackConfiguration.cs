using Adguard.Dns.Api.DnsProxyServer.EventArgs;

namespace Adguard.Dns.Api.DnsProxyServer.Callbacks
{
    /// <summary>
    /// DnsProxy callbacks interface
    /// </summary>
    public interface IDnsProxyServerCallbackConfiguration
    { 
        /// <summary>
        /// Called synchronously right after a request has been processed,
        /// but before a response is returned
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="args">Event data
        /// (<seealso cref="DnsRequestProcessedEventArgs"/>)</param>
        void OnDnsRequestProcessed(object sender, DnsRequestProcessedEventArgs args);
    }
}