using System;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Exceptions;
using Adguard.Dns.Logging;

namespace Adguard.Dns.Api
{
    public interface IDnsApi
    {
        #region Filtering

        /// <summary>
        /// Starts DNS filtering
        /// </summary>
        /// <param name="dnsApiConfiguration">Dns proxy configuration
        /// (<seealso cref="DnsApiConfiguration"/>)</param>
        /// <exception cref="ArgumentNullException">Thrown,
        /// if <see cref="dnsApiConfiguration"/> is not specified</exception>
        /// <exception cref="NotSupportedException">Thrown
        /// if current API version is not supported</exception>
        /// <exception cref="InvalidOperationException">Thrown, if cannot starting the proxy server
        /// for any reason</exception>
        void StartDnsFiltering(DnsApiConfiguration dnsApiConfiguration);

        /// <summary>
        /// Stops DNS filtering
        /// If it is not started yet, does nothing.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown, if cannot closing the proxy server
        /// for any reason</exception>
        void StopDnsFiltering();

        /// <summary>
        /// Reloads DNS filtering
        /// <param name="newDnsApiConfiguration">Dns proxy configuration
        /// (<seealso cref="DnsApiConfiguration"/>)</param>
        /// <param name="force">Determines, whether the DNS filtering must be reloaded,
        /// independently of whether configuration changed or not</param>
        /// <exception cref="ArgumentNullException">Thrown, if <see cref="newDnsApiConfiguration"/>
        /// is not specified</exception>
        /// <exception cref="ArgumentException">Thrown, if <see cref="DnsProxySettings"/>
        /// is not specified within the <see cref="newDnsApiConfiguration"/></exception>
        /// <exception cref="NotSupportedException">Thrown
        /// if current API version is not supported</exception>
        /// <exception cref="InvalidOperationException">Thrown, if cannot starting the proxy server
        /// for any reason</exception>
        /// <exception cref="InvalidOperationException">Thrown, if cannot closing the proxy server
        /// for any reason</exception>
        /// </summary>
        void ReloadDnsFiltering(DnsApiConfiguration newDnsApiConfiguration, bool force);

        /// <summary>
        /// Gets the current DNS proxy settings as a <see cref="DnsProxySettings"/> object
        /// </summary>
        /// <returns>Current DNS proxy settings
        /// (<seealso cref="DnsProxySettings"/>)</returns>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if cannot get the current dns proxy settings via native method</exception>
        DnsProxySettings GetCurrentDnsProxySettings();

        /// <summary>
        /// Gets the default DNS proxy settings as a <see cref="DnsProxySettings"/> object
        /// </summary>
        /// <returns>Current DNS proxy settings
        /// (<seealso cref="DnsProxySettings"/>)</returns>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if cannot get the default dns proxy settings via native method</exception>
        DnsProxySettings GetDefaultDnsProxySettings();

        #endregion

        #region DnsUtils

        /// <summary>
        /// Parses a specified DNS stamp string (<seealso cref="dnsStampStr"/>)
        /// </summary>
        /// <param name="dnsStampStr">DNS stamp string</param>
        /// <returns>DNS stamp as a <see cref="DnsStamp"/> instance</returns>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if parsing DNS stamp failed with an error</exception>
        DnsStamp ParseDnsStamp(string dnsStampStr);

        /// <summary>
        /// Checks if upstream is valid and available
        /// </summary>
        /// <param name="upstreamOptions">Upstream options
        /// (<seealso cref="UpstreamOptions"/>)</param>
        /// <returns>True, if test has completed successfully,
        /// otherwise false</returns>
        bool TestUpstream(UpstreamOptions upstreamOptions);

        /// <summary>
        /// Gets current DNS proxy version
        /// </summary>
        /// <returns></returns>
        string GetDnsProxyVersion();

        #endregion

        #region Logging

        /// <summary>
        /// Initializes the DnsLoggerAdapter with the specified log level
        /// </summary>
        /// <param name="logLevel">Log level you'd like to use</param>
        void InitLogger(LogLevel logLevel);

        #endregion

        #region Crash reporting

        /// <summary>
        /// Sets an unhandled exception configuration
        /// (<seealso cref="IUnhandledExceptionConfiguration"/>)
        /// </summary>
        /// <param name="unhandledExceptionConfiguration">
        /// Callbacks configuration to execute when native and/or managed exception occurred</param>
        void SetUnhandledExceptionConfiguration(IUnhandledExceptionConfiguration unhandledExceptionConfiguration);

        #endregion
    }
}