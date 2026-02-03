using System;
using Adguard.Dns.Api.DnsProxyServer.Configs;

namespace Adguard.Dns.DnsProxyServer
{
    /// <summary>
    /// Interface for the proxy server
    /// </summary>
    public interface IDnsProxyServer
    {
        /// <summary>
        /// Starts the DnsProxyServer
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if cannot starting the DnsProxyServer for any reason</exception>
        void Start();

        /// <summary>
        /// Stops the DnsProxyServer.
        /// If it is not started yet, does nothing.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if cannot closing the DnsProxyServer for any reason</exception>
        void Stop();

        /// <summary>
        ///  Reapply DNS proxy settings with selective reloading
        ///
        /// This function allows updating DNS proxy configuration without full reinitialization.
        /// You can selectively reload different parts of the configuration using ag_dnsproxy_reapply_options flags.
        /// </summary>
        /// <param name="dnsProxySettings">dnsProxySettings</param>
        /// <param name="options">bitwise OR combination of <see cref="AGDnsApi.ag_dnsproxy_reapply_options"/> flags</param>
        bool ReapplySettings(DnsProxySettings dnsProxySettings, AGDnsApi.ag_dnsproxy_reapply_options options);

        /// <summary>
        /// Gets the current DNS proxy settings as a <see cref="DnsProxySettings"/> object
        /// </summary>
        /// <returns>Current DNS proxy settings
        /// (<seealso cref="DnsProxySettings"/>)</returns>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if cannot get the current dns proxy settings via native method</exception>
        DnsProxySettings GetCurrentDnsProxySettings();

        /// <summary>
        /// The DnsProxyServer status
        /// Determines, whether the current instance of the DnsProxyServer is started
        /// </summary>
        bool IsStarted { get; }

		/// <summary>
		/// Process a DNS message and return the response.
		/// </summary>
		/// <param name="message">A DNS message in wire format </param>
		/// <param name="info">Additional parameters</param>
		/// <returns>The DNS response in wire format</returns>
		byte[] HandleDnsMessage(byte[] message, DnsMessageInfo info);

		/// <summary>
		/// Process a DNS message and call `handler` on an unspecified thread with the response.
		/// </summary>
		/// <param name="message">A DNS message in wire format </param>
		/// <param name="info">Additional parameters</param>
		/// <param name="handler">Callback function for asynchronous message processing</param>
		void HandleDnsMessageAsync(byte[] message, DnsMessageInfo info, Action<byte[]> handler);
    }
}