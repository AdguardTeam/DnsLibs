using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.DnsProxyServer;
using Adguard.Dns.Logging;
using AdGuard.Utils.Base.Logging;
using AdGuard.Utils.Base.Logging.TraceListeners;
using AdGuard.Utils.Html;
using Microsoft.Win32;

namespace Adguard.Dns.TestApp
{
    /// <summary>
    /// Simple dns api for sample app
    /// </summary>
    public static class DnsSimpleApi
    {
        private static readonly object SyncRoot = new object();
        private static IDnsProxyServer m_DnsProxyServer;

        private const string TCP_SETTINGS_SUB_KEY = @"System\CurrentControlSet\Services\Tcpip\Parameters";
        private const string SEARCHLIST = "SearchList";
        private const int GET_NETWORK_INTERFACE_ATTEMPT_COUNT = 5;
        
        public static void StartLogger()
        {
            ITraceListener coloredConsoleTraceListener = new ColoredConsoleTraceListener();
            Logger.SetCustomListener(coloredConsoleTraceListener);
            DnsLoggerAdapter.Init(AGDnsApi.ag_log_level.AGLL_DEBUG);
            DnsLoggerAdapter.SetLogger();
        }

        
        /// <summary>
        /// Stops the dns filtering
        /// If it is not started yet, does nothing.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown, if cannot closing the proxy server
        /// for any reason</exception>
        public static void StopDnsFiltering()
        {
            lock (SyncRoot)
            {
                try
                {
                    Logger.Info("Stopping the DNS filtering");
                    if (m_DnsProxyServer == null)
                    {
                        return;
                    }

                    m_DnsProxyServer.Stop();
                    m_DnsProxyServer = null;
                    Logger.Info("Stopping the DNS filtering has been successfully completed");
                }
                catch (Exception ex)
                {
                    Logger.Error("Stopping the DNS filtering failed with an error: {0}", ex);
                    throw;
                }
            }
        }
        
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
        public static void StartDnsFiltering(DnsApiConfiguration dnsApiConfiguration)
        {
            lock (SyncRoot)
            {
                try
                {
                    if (dnsApiConfiguration == null)
                    {
                        throw new ArgumentNullException(
                            nameof(dnsApiConfiguration),
                            "dnsApiConfiguration is not specified");
                    }

                    if (!dnsApiConfiguration.IsEnabled)
                    {
                        Logger.Info("DNS filtering is disabled, doing nothing");
                        return;
                    }

                    Logger.Info("Starting the DNS filtering");
                    AddDnsSuffixesAndDefaultFallbacks(dnsApiConfiguration.DnsProxySettings);
                    m_DnsProxyServer = new DnsProxyServer.DnsProxyServer(
                        dnsApiConfiguration.DnsProxySettings,
                        dnsApiConfiguration.DnsProxyServerCallbackConfiguration);
                    m_DnsProxyServer.Start();
                    Logger.Info("Starting the DNS filtering has been successfully completed");
                }
                catch (Exception ex)
                {
                    Logger.Error("Starting the DNS filtering failed with an error: {0}", ex);
                    throw;
                }
            }
        }
        
        private static void AddDnsSuffixesAndDefaultFallbacks(DnsProxySettings dnsProxySettings)
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
        
        private static List<string> GetSystemDNSSuffixes()
        {
            Logger.Info("Start getting the DNS suffixes");
            List<string> ret = new List<string>();

            // Getting DHCP suffixes
            NetworkInterface[] adapters = GetNetworkInterfaces();
            foreach (NetworkInterface adapter in adapters)
            {
                IPInterfaceProperties properties = adapter.GetIPProperties();
                string suffix = properties.DnsSuffix;
                if (suffix.Length < 2)
                {
                    continue;
                }

                Logger.Verbose("Add DNS suffix {0}", suffix);
                ret.Add(suffix);
            }

            // Getting suffixes from the System Settings
            try
            {
                using (RegistryKey reg = Registry.LocalMachine.OpenSubKey(TCP_SETTINGS_SUB_KEY))
                {
                    if (reg == null)
                    {
                        Logger.Info("Cannot open {0}", TCP_SETTINGS_SUB_KEY);
                        return ret;
                    }

                    string searchList = reg.GetValue(SEARCHLIST) as string;
                    if (searchList == null)
                    {
                        Logger.Info("Cannot get {0} value", SEARCHLIST);
                        return ret;
                    }

                    string[] searchListArr = searchList.Split((char)Chars.COMMA, (char)Chars.SPACE);
                    foreach (string suffix in searchListArr)
                    {
                        if (suffix.Length < 2)
                        {
                            continue;
                        }

                        Logger.Verbose("Add DNS suffix {0}", suffix);
                        ret.Add(suffix);
                    }
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("error while getting the DNS suffixes", ex);
            }

            Logger.Info("Finished getting the DNS suffixes");
            return ret.Distinct().ToList();
        }
        
        private static NetworkInterface[] GetNetworkInterfaces()
        {
            NetworkInterface[] adapters = new NetworkInterface[0];
            for (int i = 0; i < GET_NETWORK_INTERFACE_ATTEMPT_COUNT; i++)
            {
                try
                {
                    // Disabling IPv4 while running can cause a NetworkInformationException: The pipe is being closed.
                    // https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/blob/master/LibreHardwareMonitorLib/Hardware/Network/NetworkGroup.cs
                    // https://jira.adguard.com/browse/AG-12977
                    adapters = NetworkInterface.GetAllNetworkInterfaces();
                    Logger.Verbose("Network interfaces have been got successfully");
                    return adapters;
                }
                catch (NetworkInformationException ex)
                {
                    Logger.Error("Cannot get network interfaces: {0}", ex);
                }
            }

            return adapters;
        }
    }
}