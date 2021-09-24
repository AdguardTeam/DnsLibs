using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.DnsProxyServer;
using Adguard.Dns.Exceptions;
using Adguard.Dns.Logging;
using Adguard.Dns.Utils;
using AdGuard.Utils.Html;
using Microsoft.Win32;

namespace Adguard.Dns.Api
{
    /// <summary>
    /// Main API Facade object, which implements <see cref="IDnsApi"/>,
    /// and provides full functionality of Core Libs windows adapter
    /// </summary>
    public class DnsApi : IDnsApi
    {
        private static readonly ILog LOG = LogProvider.For<DnsApi>();
        private static readonly object SYNC_ROOT = new object();
        private IDnsProxyServer m_DnsProxyServer;
        private static readonly Lazy<IDnsApi> LAZY = new Lazy<IDnsApi> (() => new DnsApi());
        private DnsProxySettings m_CurrentDnsProxySettings;

        private const string TCP_SETTINGS_SUB_KEY = @"System\CurrentControlSet\Services\Tcpip\Parameters";
        private const string SEARCHLIST = "SearchList";

        #region Singleton

        /// <summary>
        /// Gets a singleton instance of <see cref="DnsApi"/> object
        /// </summary>
        public static IDnsApi Instance
        {
            get
            {
                return LAZY.Value;
            }
        }

        #endregion

        #region Filtering

        /// <summary>
        /// Starts DNS filtering
        /// </summary>
        /// <param name="dnsApiConfiguration">Dns proxy configuration
        /// (<seealso cref="DnsApiConfiguration"/>)</param>
        /// <exception cref="NotSupportedException">Thrown
        /// if current API version is not supported</exception>
        /// <exception cref="ArgumentNullException">Thrown,
        /// if <see cref="dnsApiConfiguration"/> is not specified</exception>
        /// <exception cref="InvalidOperationException">Thrown, if cannot starting the proxy server
        /// for any reason</exception>
        public void StartDnsFiltering(DnsApiConfiguration dnsApiConfiguration)
        {
            lock (SYNC_ROOT)
            {
                try
                {
                    if (dnsApiConfiguration == null)
                    {
                        throw new ArgumentNullException(
                            "dnsApiConfiguration",
                            "dnsApiConfiguration is not specified");
                    }

                    if (!dnsApiConfiguration.IsEnabled)
                    {
                        LOG.InfoFormat("DNS filtering is disabled, doing nothing");
                        return;
                    }

                    LOG.InfoFormat("Starting the DNS filtering");
                    AddDnsSuffixesAndDefaultFallbacks(dnsApiConfiguration.DnsProxySettings);
                    m_DnsProxyServer = new Dns.DnsProxyServer.DnsProxyServer(
                        dnsApiConfiguration.DnsProxySettings,
                        dnsApiConfiguration.DnsProxyServerCallbackConfiguration);
                    m_CurrentDnsProxySettings = dnsApiConfiguration.DnsProxySettings;
                    m_DnsProxyServer.Start();
                    LOG.InfoFormat("Starting the DNS filtering has been successfully completed");
                }
                catch (Exception ex)
                {
                    LOG.ErrorFormat("Starting the DNS filtering failed with an error: {0}", ex);
                    throw;
                }
            }
        }

        private void AddDnsSuffixesAndDefaultFallbacks(DnsProxySettings dnsProxySettings)
        {
            List<string> dnsSuffixes = GetSystemDNSSuffixes();
            if (dnsProxySettings.FallbackDomains == null)
            {
                dnsProxySettings.FallbackDomains = new List<string>();
            }

            List<string> fallbackDomains = dnsProxySettings.FallbackDomains;

            List<string> preparedDnsSuffixes = dnsSuffixes.Select(x => $"*.{x}").ToList();
            fallbackDomains.AddRange(preparedDnsSuffixes);
            dnsProxySettings.FallbackDomains = fallbackDomains.Distinct().ToList();
        }

        /// <summary>
        /// Stops the dns filtering
        /// If it is not started yet, does nothing.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown, if cannot closing the proxy server
        /// for any reason</exception>
        public void StopDnsFiltering()
        {
            lock (SYNC_ROOT)
            {
                try
                {
                    LOG.InfoFormat("Stopping the DNS filtering");
                    if (m_DnsProxyServer == null)
                    {
                        return;
                    }

                    m_DnsProxyServer.Stop();
                    m_DnsProxyServer = null;
                    LOG.InfoFormat("Stopping the DNS filtering has been successfully completed");
                }
                catch (Exception ex)
                {
                    LOG.ErrorFormat("Stopping the DNS filtering failed with an error: {0}", ex);
                    throw;
                }
            }
        }

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
        public void ReloadDnsFiltering(DnsApiConfiguration newDnsApiConfiguration, bool force)
        {
            lock (SYNC_ROOT)
            {
                IDnsProxyServer newDnsProxyServer = null;
                try
                {
                    LOG.InfoFormat("Reloading the DNS filtering");
                    if (m_DnsProxyServer == null ||
                        m_CurrentDnsProxySettings == null)
                    {
                        LOG.InfoFormat(
                            "Start DNS filtering, because the DNS server is not started and/or configurations are not set");

                        StartDnsFiltering(newDnsApiConfiguration);
                        return;
                    }

                    if (newDnsApiConfiguration == null)
                    {
                        throw new ArgumentNullException(
                            "newDnsApiConfiguration",
                            "newDnsApiConfiguration is not specified");
                    }

                    if (newDnsApiConfiguration.DnsProxySettings == null)
                    {
                        throw new ArgumentException(
                            "DnsProxySettings is not initialized",
                            "newDnsApiConfiguration");
                    }

                    bool isConfigurationChanged = !m_CurrentDnsProxySettings.Equals(newDnsApiConfiguration.DnsProxySettings);
                    if (!force &&
                        !isConfigurationChanged)
                    {
                        LOG.InfoFormat("The DNS server configuration hasn't been changed, no need to reload");
                        return;
                    }

                    AddDnsSuffixesAndDefaultFallbacks(newDnsApiConfiguration.DnsProxySettings);
                    newDnsProxyServer = new Dns.DnsProxyServer.DnsProxyServer(
                        newDnsApiConfiguration.DnsProxySettings,
                        newDnsApiConfiguration.DnsProxyServerCallbackConfiguration);

                    m_DnsProxyServer.Stop();
                    m_DnsProxyServer = newDnsProxyServer;
                    if (newDnsApiConfiguration.IsEnabled)
                    {
                        LOG.InfoFormat("DNS filtering is enabled, starting DNS proxy server");
                        m_DnsProxyServer.Start();
                    }

                    m_CurrentDnsProxySettings = newDnsApiConfiguration.DnsProxySettings;
                    LOG.InfoFormat("Reloading the DNS filtering has been successfully completed");
                }
                catch (Exception ex)
                {
                    LOG.ErrorFormat("Reloading the DNS filtering failed with an error: {0}", ex);
                    if (newDnsProxyServer != null &&
                        newDnsProxyServer.IsStarted)
                    {
                        // if the new DNS proxy server has been already started we should stop it,
                        // otherwise - let the existed proxy server works
                        StopDnsFiltering();
                    }

                    throw;
                }
            }
        }

        /// <summary>
        /// Gets the current DNS proxy settings as a <see cref="DnsProxySettings"/> object
        /// </summary>
        /// <returns>Current DNS proxy settings
        /// (<seealso cref="DnsProxySettings"/>)</returns>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if cannot get the current dns proxy settings via native method</exception>
        public DnsProxySettings GetCurrentDnsProxySettings()
        {
            lock (SYNC_ROOT)
            {
                try
                {
                    LOG.InfoFormat("Getting current DNS proxy settings");
                    if (m_DnsProxyServer == null)
                    {
                        return null;
                    }

                    DnsProxySettings dnsProxySettings = m_DnsProxyServer.GetCurrentDnsProxySettings();
                    LOG.InfoFormat("Getting current DNS proxy settings has been successfully completed");
                    return dnsProxySettings;
                }
                catch (Exception ex)
                {
                    LOG.ErrorFormat("Getting current DNS proxy settings failed with an error: {0}", ex);
                    throw;
                }
            }
        }

        /// <summary>
        /// Gets the default DNS proxy settings as a <see cref="DnsProxySettings"/> object
        /// </summary>
        /// <returns>Current DNS proxy settings
        /// (<seealso cref="DnsProxySettings"/>)</returns>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if cannot get the default dns proxy settings via native method</exception>
        public DnsProxySettings GetDefaultDnsProxySettings()
        {
            lock (SYNC_ROOT)
            {
                try
                {
                    LOG.InfoFormat("Getting default DNS proxy settings");
                    DnsProxySettings dnsProxySettings =
                        Dns.DnsProxyServer.DnsProxyServer.GetDefaultDnsProxySettings();
                    LOG.InfoFormat("Getting default DNS proxy settings has been successfully completed");
                    return dnsProxySettings;
                }
                catch (Exception ex)
                {
                    LOG.ErrorFormat("Getting default DNS proxy settings failed with an error: {0}", ex);
                    throw;
                }
            }
        }

        private List<string> GetSystemDNSSuffixes()
        {
            LOG.Info("Start getting the DNS suffixes");
            List<string> ret = new List<string>();

            // Getting DHCP suffixes
            NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface adapter in adapters)
            {
                IPInterfaceProperties properties = adapter.GetIPProperties();
                string suffix = properties.DnsSuffix;
                if (suffix.Length < 2)
                {
                    continue;
                }

                LOG.DebugFormat("Add DNS suffix {0}", suffix);
                ret.Add(suffix);
            }

            // Getting suffixes from the System Settings
            try
            {
                using (RegistryKey reg = Registry.LocalMachine.OpenSubKey(TCP_SETTINGS_SUB_KEY))
                {
                    if (reg == null)
                    {
                        LOG.InfoFormat("Cannot open {0}", TCP_SETTINGS_SUB_KEY);
                        return ret;
                    }

                    string searchList = reg.GetValue(SEARCHLIST) as string;
                    if (searchList == null)
                    {
                        LOG.InfoFormat("Cannot get {0} value", SEARCHLIST);
                        return ret;
                    }

                    string[] searchListArr = searchList.Split((char)Chars.COMMA, (char)Chars.SPACE);
                    foreach (string suffix in searchListArr)
                    {
                        if (suffix.Length < 2)
                        {
                            continue;
                        }

                        LOG.DebugFormat("Add DNS suffix {0}", suffix);
                        ret.Add(suffix);
                    }
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("error while getting the DNS suffixes", ex);
            }

            LOG.Info("Finished getting the DNS suffixes");
            return ret.Distinct().ToList();
        }

        #endregion

        #region DnsUtils

        /// <summary>
        /// Parses a specified DNS stamp string (<seealso cref="dnsStampStr"/>)
        /// into the <see cref="DnsStamp"/> object.
        /// </summary>
        /// <param name="dnsStampStr">DNS stamp string</param>
        /// <returns>DNS stamp as a <see cref="DnsStamp"/>
        /// instance or null if smth went wrong</returns>
        public DnsStamp ParseDnsStamp(string dnsStampStr)
        {
            try
            {
                LOG.InfoFormat("Parsing DNS stamp");
                DnsStamp dnsStamp = DnsUtils.ParseDnsStamp(dnsStampStr);
                LOG.InfoFormat("Parsing DNS stamp has been successfully completed");
                return dnsStamp;
            }
            catch (Exception ex)
            {
                LOG.ErrorFormat("Parsing DNS stamp failed with an error: {0}", ex);
                return null;
            }
        }

        /// <summary>
        /// Checks if upstream is valid and available
        /// </summary>
        /// <param name="upstreamOptions">Upstream options
        /// (<seealso cref="UpstreamOptions"/>)</param>
        /// <param name=ipv6Available">Whether IPv6 is available (i.e., bootstrapper is allowed to make AAAA queries)</param>
        /// <exception cref="InvalidOperationException"></exception>
        /// <returns>True, if test has completed successfully,
        /// otherwise false</returns>
        public bool TestUpstream(UpstreamOptions upstreamOptions, bool ipv6Available)
        {
            try
            {
                LOG.InfoFormat("Testing upstream");
                bool result = DnsUtils.TestUpstream(upstreamOptions, ipv6Available);
                LOG.InfoFormat("Testing upstream has been successfully completed");
                return result;
            }
            catch (Exception ex)
            {
                LOG.ErrorFormat("Testing upstream failed with an error: {0}", ex);
                return false;
            }
        }

        /// <summary>
        /// Gets current DNS proxy version
        /// </summary>
        /// <returns></returns>
        public string GetDnsProxyVersion()
        {
            string dnsProxyVersion = DnsUtils.GetDnsProxyVersion();
            return dnsProxyVersion;
        }

        #endregion

        #region Logging

        /// <summary>
        /// Initializes the DnsLoggerAdapter with the specified log level
        /// </summary>
        /// <param name="logLevel">Log level you'd like to use</param>
        public void InitLogger(LogLevel logLevel)
        {
            lock (SYNC_ROOT)
            {
                DnsLoggerAdapter.Init(logLevel);
                DnsLoggerAdapter.SetLogger();
            }
        }

        #endregion

        #region Crash reporting

        /// <summary>
        /// Sets an unhandled exception configuration
        /// (<seealso cref="IUnhandledExceptionConfiguration"/>)
        /// </summary>
        /// <param name="unhandledExceptionConfiguration">
        /// Callbacks configuration to execute when native and/or managed exception occurred</param>
        public void SetUnhandledExceptionConfiguration(
            IUnhandledExceptionConfiguration unhandledExceptionConfiguration)
        {
            lock (SYNC_ROOT)
            {
                try
                {
                    LOG.InfoFormat("Setting unhandled exception configuration");
                    DnsExceptionHandler.Init(unhandledExceptionConfiguration);
                    DnsExceptionHandler.SetUnhandledExceptionConfiguration();
                    LOG.InfoFormat("Setting unhandled exception configuration has been successfully completed");
                }
                catch (Exception ex)
                {
                    LOG.ErrorFormat("Setting unhandled exception configuration failed with an error: {0}", ex);
                }
            }
        }

        #endregion
    }
}