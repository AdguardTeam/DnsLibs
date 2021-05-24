using System;
using System.Collections.Generic;
using Adguard.Dns.Api.DnsProxyServer.Callbacks;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Helpers;
using Adguard.Dns.Logging;
using AdGuard.Utils.Interop;

namespace Adguard.Dns.DnsProxyServer
{
    // ReSharper disable InconsistentNaming
    internal class DnsProxyServer : IDnsProxyServer, IDisposable
    {
        private const string TCP_SETTINGS_SUB_KEY = @"System\CurrentControlSet\Services\Tcpip\Parameters";
        private const string SEARCHLIST = "SearchList";

        private static readonly ILog LOG = LogProvider.For<DnsProxyServer>();
        private IntPtr m_pCallbackConfigurationC;
        private IntPtr m_pProxyServer;

        // ReSharper disable once PrivateFieldCanBeConvertedToLocalVariable
        // We shouldn't make this variable local (within the DnsProxyServer ctor) to protect it from the GC
        private AGDnsApi.AGDnsProxyServerCallbacks m_callbackConfigurationC;
        private bool m_IsStarted;
        private readonly object m_SyncRoot = new object();
        private readonly DnsProxySettings m_DnsProxySettings;
        private readonly IDnsProxyServerCallbackConfiguration m_CallbackConfiguration;

        /// <summary>
        /// Initializes the new instance of the DnsProxyServer
        /// </summary>
        /// <param name="dnsProxySettings">Dns proxy settings
        /// (<seealso cref="DnsProxySettings"/>)</param>
        /// <param name="callbackConfiguration">Callback config configuration
        /// (<seealso cref="IDnsProxyServerCallbackConfiguration"/>)</param>
        /// <exception cref="NotSupportedException">Thrown if current API version is not supported</exception>
        internal DnsProxyServer(
            DnsProxySettings dnsProxySettings,
            IDnsProxyServerCallbackConfiguration callbackConfiguration)
        {
            lock (m_SyncRoot)
            {
                LOG.Info("Creating the DnsProxyServer");
                AGDnsApi.ValidateApi();
                m_DnsProxySettings = dnsProxySettings;
                m_CallbackConfiguration = callbackConfiguration;
            }
        }

        #region IDnsProxyServer members

        /// <summary>
        /// Starts the proxy server
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown, if cannot starting the proxy server
        /// for any reason</exception>
        public void Start()
        {
            lock (m_SyncRoot)
            {
                LOG.Info("Starting the DnsProxyServer");
                if (IsStarted)
                {
                    LOG.Info("DnsProxyServer is already started, doing nothing");
                    return;
                }

                Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
                try
                {
                    AGDnsApi.ag_dnsproxy_settings dnsProxySettingsC =
                        DnsApiConverter.ToNativeObject(m_DnsProxySettings, allocatedPointers);
                    m_callbackConfigurationC = DnsApiConverter.ToNativeObject(m_CallbackConfiguration, this);

                    IntPtr pDnsProxySettingsC = MarshalUtils.StructureToPtr(dnsProxySettingsC, allocatedPointers);
                    m_pCallbackConfigurationC = MarshalUtils.StructureToPtr(m_callbackConfigurationC);
                    m_pProxyServer = AGDnsApi.ag_dnsproxy_init(
                        pDnsProxySettingsC,
                        m_pCallbackConfigurationC);
                    if (m_pProxyServer == IntPtr.Zero)
                    {
                        const string errorMessage = "Failed to start the DnsProxyServer due to an error";
                        throw new InvalidOperationException(errorMessage);
                    }

                    m_IsStarted = true;
                    LOG.Info("Finished starting the DnsProxyServer");
                }
                catch (Exception ex)
                {
                    Dispose();
                    throw new InvalidOperationException("error while starting the DnsProxyServer", ex);
                }
                finally
                {
                    MarshalUtils.SafeFreeHGlobal(allocatedPointers);
                }
            }
        }

        /// <summary>
        /// Stops the proxy server
        /// If it is not started yet, does nothing.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown, if cannot closing the proxy server
        /// via native method</exception>
        public void Stop()
        {
            lock (m_SyncRoot)
            {
                try
                {
                    LOG.Info("Stopping the DnsProxyServer");
                    if (!IsStarted)
                    {
                        LOG.Info("DnsProxyServer is not started, doing nothing");
                        return;
                    }

                    AGDnsApi.ag_dnsproxy_deinit(m_pProxyServer);
                    m_IsStarted = false;
                    LOG.Info("Finished stopping the DnsProxyServer");
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException("error while stopping the DnsProxyServer", ex);
                }
                finally
                {
                    Dispose();
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
            LOG.Info("Get current DnsProxyServer settings");
            lock (m_SyncRoot)
            {
                if (!IsStarted)
                {
                    LOG.Info("DnsProxyServer is not started, doing nothing");
                    return null;
                }

                IntPtr pSettings = AGDnsApi.ag_dnsproxy_get_settings(m_pProxyServer);
                DnsProxySettings currentDnsProxySettings =
                    GetDnsProxySettings(pSettings);
                return currentDnsProxySettings;
            }
        }

        /// <summary>
        /// Gets the default DNS proxy settings as a <see cref="DnsProxySettings"/> object
        /// </summary>
        /// <returns>Current DNS proxy settings
        /// (<seealso cref="DnsProxySettings"/>)</returns>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if cannot get the default dns proxy settings via native method</exception>
        public static DnsProxySettings GetDefaultDnsProxySettings()
        {
            LOG.Info("Get default DnsProxyServer settings");
            IntPtr pSettings = AGDnsApi.ag_dnsproxy_settings_get_default();
            DnsProxySettings defaultDnsProxySettings =
                GetDnsProxySettings(pSettings);
            return defaultDnsProxySettings;
        }

        /// <summary>
        /// Gets the DNS proxy settings,
        /// according to the specified <see cref="pCurrentDnsProxySettings"/>
        /// </summary>
        /// <param name="pCurrentDnsProxySettings">DNS proxy settings
        /// (<seealso cref="Func{TResult}"/>)</param>
        /// <exception cref="InvalidOperationException">Thrown,
        /// if cannot get the DNS proxy settings via native method</exception>
        /// <returns>The <see cref="DnsProxySettings"/> object</returns>
        private static DnsProxySettings GetDnsProxySettings(IntPtr pCurrentDnsProxySettings)
        {
            LOG.Info("Get DNS proxy settings settings");
            if (pCurrentDnsProxySettings == IntPtr.Zero)
            {
                throw new InvalidOperationException("Cannot get the DNS proxy settings");
            }

            AGDnsApi.ag_dnsproxy_settings currentDnsProxySettingsC =
                MarshalUtils.PtrToStructure<AGDnsApi.ag_dnsproxy_settings>(pCurrentDnsProxySettings);
            DnsProxySettings currentDnsProxySettings = DnsApiConverter.FromNativeObject(currentDnsProxySettingsC);
            LOG.Info("Finished getting the DNS proxy settings");
            return currentDnsProxySettings;
        }

        /// <summary>
        /// The DnsProxyServer status
        /// Determines, whether the current instance of the proxy server is started
        /// </summary>
        public bool IsStarted
        {
            get
            {
                lock (m_SyncRoot)
                {
                    return m_IsStarted;
                }
            }
        }

        #endregion

        public void Dispose()
        {
            lock (m_SyncRoot)
            {
                if (m_pCallbackConfigurationC == IntPtr.Zero)
                {
                    return;
                }

                MarshalUtils.SafeFreeHGlobal(m_pCallbackConfigurationC);
                m_pCallbackConfigurationC = IntPtr.Zero;
            }
        }
    }
}
