using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using AdGuard.Utils.Base.Interop;
using AdGuard.Utils.Base.Logging;

namespace Adguard.Dns.Api.SystemDnsModifier
{
    /// <summary>
    /// Helper methods for modifying system DNS settings and managing WFP firewall
    /// </summary>
    public static class SystemDnsModifierHelper
    {
        /// <summary>
        /// Return the string representation of the GUID of the "preferred adapter":
        /// the network interface whose DNS settings Windows considers first
        /// when deciding where to send a DNS query.
        /// </summary>
        /// <returns>The preferred adapter GUID string on success, <c>null</c> on error</returns>
        public static string GetPreferredAdapterGuid()
        {
            IntPtr pGuid = IntPtr.Zero;
            try
            {
                pGuid = AGDnsApi.ag_dns_get_preferred_adapter_guid();
                if (pGuid == IntPtr.Zero)
                {
                    Logger.Info("Failed to get preferred adapter GUID");
                    return null;
                }

                string guid = MarshalUtils.PtrToString(pGuid);
                return guid;
            }
            catch (Exception ex)
            {
                Logger.QuietWarn(ex, "Getting preferred adapter GUID failed with an error");
                return null;
            }
            finally
            {
                AGDnsApi.ag_str_free(pGuid);
            }
        }

        /// <summary>
        /// Modify the DNS settings for a network interface.
        /// Equivalent to specifying the preferred/alternative DNS server in IPv4/IPv6 properties
        /// in the interface properties GUI.
        /// An empty string is equivalent to selecting "Obtain DNS server address automatically".
        /// </summary>
        /// <param name="dnsList">Comma-separated list of nameserver addresses</param>
        /// <param name="ifGuid">Interface GUID string</param>
        /// <param name="ipv6"><c>true</c> to modify the IPv6 properties, <c>false</c> for IPv4</param>
        /// <returns><c>0</c> on success or a non-zero error code defined in Winerror.h</returns>
        public static uint SetIfNameserver(string dnsList, string ifGuid, bool ipv6)
        {
            Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
            try
            {
                IntPtr pDnsList = MarshalUtils.StringToPtr(dnsList, allocatedPointers);
                IntPtr pIfGuid = MarshalUtils.StringToPtr(ifGuid, allocatedPointers);
                uint result = AGDnsApi.ag_dns_set_if_nameserver(pDnsList, pIfGuid, ipv6);
                if (result != 0)
                {
                    Logger.Info(
                        "Setting nameserver for interface {0} (ipv6={1}) failed with error code {2}",
                        ifGuid,
                        ipv6,
                        result);
                }

                return result;
            }
            catch (Exception ex)
            {
                Logger.QuietWarn(ex, "Setting interface nameserver failed with an error");
                return uint.MaxValue;
            }
            finally
            {
                MarshalUtils.SafeFreeHGlobal(allocatedPointers);
            }
        }

        /// <summary>
        /// Get the current value of the NameServer property of an interface.
        /// Returns <c>null</c> on any error,
        /// including if the property does not exist or isn't a null-terminated string.
        /// </summary>
        /// <param name="ifGuid">Interface GUID string</param>
        /// <param name="ipv6"><c>true</c> to get the IPv6 property, <c>false</c> for IPv4</param>
        /// <returns>The current nameserver value on success, <c>null</c> on error</returns>
        public static string GetIfNameserver(string ifGuid, bool ipv6)
        {
            Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
            IntPtr pResult = IntPtr.Zero;
            try
            {
                IntPtr pIfGuid = MarshalUtils.StringToPtr(ifGuid, allocatedPointers);
                pResult = AGDnsApi.ag_dns_get_if_nameserver(pIfGuid, ipv6);
                if (pResult == IntPtr.Zero)
                {
                    Logger.Warn(
                        "Failed to get nameserver for interface {0} (ipv6={1})",
                        ifGuid,
                        ipv6);
                    return null;
                }

                string nameserver = MarshalUtils.PtrToString(pResult);
                return nameserver;
            }
            catch (Exception ex)
            {
                Logger.QuietWarn(ex, "Getting interface nameserver failed with an error");
                return null;
            }
            finally
            {
                AGDnsApi.ag_str_free(pResult);
                MarshalUtils.SafeFreeHGlobal(allocatedPointers);
            }
        }

        /// <summary>
        /// Create a new WFP firewall.
        /// Firewall restrictions will remain active until <see cref="WfpFirewallDeinit"/> is called
        /// on the returned pointer.
        /// </summary>
        /// <param name="name">A string which shall be included in WFP entities names</param>
        /// <param name="excludePid">ID of the process to exclude from all restrictions.
        /// If <c>0</c>, exclude the current process</param>
        /// <returns>Pointer to the WFP firewall instance, or <see cref="IntPtr.Zero"/> on error</returns>
        public static IntPtr WfpFirewallInit(string name, uint excludePid)
        {
            IntPtr pName = IntPtr.Zero;
            try
            {
                pName = Marshal.StringToHGlobalUni(name);
                IntPtr pFw = AGDnsApi.ag_dns_wfpfirewall_init(pName, excludePid);
                if (pFw == IntPtr.Zero)
                {
                    Logger.Info("Failed to initialize WFP firewall");
                }

                return pFw;
            }
            catch (Exception ex)
            {
                Logger.QuietWarn(ex, "WFP firewall initialization failed with an error");
                return IntPtr.Zero;
            }
            finally
            {
                MarshalUtils.SafeFreeHGlobal(pName);
            }
        }

        /// <summary>
        /// Block DNS traffic to/from all addresses except <paramref name="allowedV4"/>
        /// and <paramref name="allowedV6"/>.
        /// </summary>
        /// <param name="pFw">Pointer returned by <see cref="WfpFirewallInit"/></param>
        /// <param name="allowedV4">Comma-separated list of IPv4 prefixes in CIDR notation</param>
        /// <param name="allowedV6">Comma-separated list of IPv6 prefixes in CIDR notation</param>
        /// <returns><c>null</c> on success, an error description on error</returns>
        public static string WfpFirewallRestrictDnsTo(IntPtr pFw, string allowedV4, string allowedV6)
        {
            Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
            IntPtr pError = IntPtr.Zero;
            try
            {
                IntPtr pAllowedV4 = MarshalUtils.StringToPtr(allowedV4, allocatedPointers);
                IntPtr pAllowedV6 = MarshalUtils.StringToPtr(allowedV6, allocatedPointers);
                pError = AGDnsApi.ag_dns_wfpfirewall_restrict_dns_to(pFw, pAllowedV4, pAllowedV6);
                if (pError == IntPtr.Zero)
                {
                    return null;
                }
                
                string error = MarshalUtils.PtrToString(pError);
                Logger.Info("WFP firewall restrict DNS failed with an error: {0}", error);
                return error;
            }
            catch (Exception ex)
            {
                Logger.QuietWarn(ex, "WFP firewall restrict DNS failed with an error");
                return ex.Message;
            }
            finally
            {
                AGDnsApi.ag_str_free(pError);
                MarshalUtils.SafeFreeHGlobal(allocatedPointers);
            }
        }

        /// <summary>
        /// Revert all restrictions and destroy the firewall.
        /// </summary>
        /// <param name="pFw">Pointer returned by <see cref="WfpFirewallInit"/></param>
        public static void WfpFirewallDeinit(IntPtr pFw)
        {
            try
            {
                AGDnsApi.ag_dns_wfpfirewall_deinit(pFw);
            }
            catch (Exception ex)
            {
                Logger.QuietWarn(ex, "WFP firewall deinitialization failed with an error");
            }
        }
    }
}
