using System;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.DnsProxyServer;
using Adguard.Dns.Exceptions;
using Adguard.Dns.Logging;
using Adguard.Dns.Utils;

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
        private static IDnsApi m_DnsApiInstance;
        private DnsProxySettings m_CurrentDnsProxySettings;

        #region Singleton
        
        /// <summary>
        /// Gets a singleton instance of <see cref="DnsApi"/> object
        /// </summary>
        public static IDnsApi Instance
        {
            get
            {
                if (m_DnsApiInstance == null)
                {
                    m_DnsApiInstance = new DnsApi();
                }

                return m_DnsApiInstance;
            }
        }

        #endregion

        #region Filtering

        /// <summary>
        /// Starts DNS filtering
        /// </summary>
        /// <param name="dnsProxyConfiguration">Dns proxy configuration
        /// (<seealso cref="DnsProxyConfiguration"/>)</param>
        /// <exception cref="NotSupportedException">Thrown
        /// if current API version is not supported</exception>
        public void StartDnsFiltering(DnsProxyConfiguration dnsProxyConfiguration)
        {
            lock (SYNC_ROOT)
            {
                try
                {
                    LOG.InfoFormat("Starting the DNS filtering");
                    m_DnsProxyServer = new Dns.DnsProxyServer.DnsProxyServer(
                        dnsProxyConfiguration.DnsProxySettings, 
                        dnsProxyConfiguration.DnsProxyServerCallbackConfiguration);
                    m_CurrentDnsProxySettings = dnsProxyConfiguration.DnsProxySettings;
                    m_DnsProxyServer.Start();
                    LOG.InfoFormat("Starting the DNS filtering has been successfully completed");
                }
                catch (Exception ex)
                {
                    LOG.ErrorFormat("Starting the DNS filtering failed with an error", ex);
                    throw;
                }
            }
        }

        /// <summary>
        /// Stops the dns filtering
        /// If it is not started yet, does nothing.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown, if cannot closing the proxy server
        /// via native method</exception>
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
                    LOG.InfoFormat("Stopping the DNS filtering has been successfully completed");
                }
                catch (Exception ex)
                {
                    LOG.ErrorFormat("Stopping the DNS filtering failed with an error", ex);
                    throw;
                }
            }
        }
        
        /// <summary>
        /// Reloads DNS filtering
        /// <param name="dnsProxyConfiguration">Dns proxy configuration
        /// (<seealso cref="DnsProxyConfiguration"/>)</param>
        /// </summary>
        public void ReloadDnsFiltering(DnsProxyConfiguration dnsProxyConfiguration)
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
                            "Cannot reload the DNS filtering, because the DNS server is not started and/or configurations are not set");
                        return;
                    }

                    bool isConfigurationChanged = !m_CurrentDnsProxySettings.Equals(dnsProxyConfiguration.DnsProxySettings);
                    if (!isConfigurationChanged)
                    {
                        LOG.InfoFormat("The DNS server configuration hasn't been changed, no need to reload");
                        return;
                    }
                    
                    newDnsProxyServer = new Dns.DnsProxyServer.DnsProxyServer(
                        dnsProxyConfiguration.DnsProxySettings, 
                        dnsProxyConfiguration.DnsProxyServerCallbackConfiguration);
                    
                    m_DnsProxyServer.Stop();
                    m_DnsProxyServer = newDnsProxyServer;
                    m_DnsProxyServer.Start();
                    m_CurrentDnsProxySettings = dnsProxyConfiguration.DnsProxySettings;
                    StartDnsFiltering(dnsProxyConfiguration);
                    LOG.InfoFormat("Reloading the DNS filtering has been successfully completed");
                }
                catch (Exception ex)
                {
                    LOG.ErrorFormat("Reloading the DNS filtering failed with an error", ex);
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
                    LOG.ErrorFormat("Getting current DNS proxy settings failed with an error", ex);
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
                    LOG.ErrorFormat("Getting default DNS proxy settings failed with an error", ex);
                    throw;
                }
            }
        }

        #endregion

        #region DnsUtils

        /// <summary>
        /// Parses a specified DNS stamp string (<seealso cref="dnsStampStr"/>)
        /// </summary>
        /// <param name="dnsStampStr">DNS stamp string</param>
        /// <returns>DNS stamp as a <see cref="DnsStamp"/> instance</returns>
        public DnsStamp ParseDnsStamp(string dnsStampStr)
        {
            lock (SYNC_ROOT)
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
                    LOG.ErrorFormat("Parsing DNS stamp failed with an error", ex);
                    return null;
                }
            }
        }

        /// <summary>
        /// Checks if upstream is valid and available
        /// </summary>
        /// <param name="upstreamOptions">Upstream options
        /// (<seealso cref="UpstreamOptions"/>)</param>
        /// <exception cref="InvalidOperationException"></exception>
        /// <returns>True, if test has completed successfully,
        /// otherwise false</returns>
        public bool TestUpstream(UpstreamOptions upstreamOptions)
        {
            lock (SYNC_ROOT)
            {
                try
                {
                    LOG.InfoFormat("Testing upstream");
                    bool result = DnsUtils.TestUpstream(upstreamOptions);
                    LOG.InfoFormat("Testing upstream has been successfully completed");
                    return result;
                }
                catch (Exception ex)
                {
                    LOG.ErrorFormat("Testing upstream failed with an error", ex);
                    return false;
                }
            }
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
            CoreExceptionHandler.Init(unhandledExceptionConfiguration);
            CoreExceptionHandler.SetUnhandledExceptionConfiguration(AGDnsApi.DnsLibName);
        }

        #endregion
    }
}