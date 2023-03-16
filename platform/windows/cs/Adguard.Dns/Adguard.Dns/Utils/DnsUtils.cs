using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Helpers;
using AdGuard.Utils.Interop;
using AdGuard.Utils.Logging;

namespace Adguard.Dns.Utils
{
    /// <summary>
    /// Helper methods for working with DNS libs
    /// </summary>
    public static class DnsUtils
    {
        /// <summary>
        /// Gets current DNS proxy version
        /// </summary>
        /// <returns></returns>
        public static string GetDnsProxyVersion()
        {
            IntPtr pDnsProxyVersion = AGDnsApi.ag_dnsproxy_version();
            string dnsProxyVersion = MarshalUtils.PtrToString(pDnsProxyVersion);
            return dnsProxyVersion;
        }

        /// <summary>
        /// Parses a specified DNS stamp string (<seealso cref="dnsStampStr"/>)
        /// into the <see cref="DnsStamp"/> object.
        /// </summary>
        /// <param name="dnsStampStr">DNS stamp string</param>
        /// <returns>DNS stamp as a <see cref="DnsStamp"/> instance or null if smth went wrong</returns>
        public static DnsStamp ParseDnsStamp(string dnsStampStr)
        {
            Logger.Info("Start parsing DNS stamp {0}", dnsStampStr);
            IntPtr ppError = IntPtr.Zero;
            IntPtr pError = IntPtr.Zero;
            IntPtr pDnsStampResult = IntPtr.Zero;
            try
            {
                ppError = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
                pDnsStampResult = AGDnsApi.ag_dns_stamp_from_str(dnsStampStr, ppError);
                if (pDnsStampResult == IntPtr.Zero)
                {
                    pError = MarshalUtils.SafeReadIntPtr(ppError);
                    string error = MarshalUtils.PtrToString(pError);
                    Logger.Info("Parsing DNS stamp {0} failed with an error {1}",
                        dnsStampStr,
                        error);
                    return null;
                }

                DnsStamp dnsStamp =
                    MarshalUtils.PtrToClass<DnsStamp, AGDnsApi.ag_dns_stamp>(
                        pDnsStampResult,
                        DnsApiConverter.FromNativeObject);
                Logger.Info("Parsing DNS stamp has been completed successfully");
                return dnsStamp;
            }
            catch (Exception ex)
            {
                Logger.QuietWarn(ex, "Parsing DNS stamp failed with an error");
                return null;
            }
            finally
            {
                AGDnsApi.ag_dns_stamp_free(pDnsStampResult);
                AGDnsApi.ag_str_free(pError);
                MarshalUtils.SafeFreeHGlobal(ppError);
            }
        }

        /// <summary>
        /// Gets the DNS stamp pretty url specified by <see cref="DnsStamp"/> object
        /// </summary>
        /// <param name="dnsStamp">DNS stamp object
        /// (<seealso cref="DnsStamp"/>)</param>
        /// <returns>DNS stamp as a string</returns>
        public static string GetDnsStampPrettyUrl(DnsStamp dnsStamp)
        {
            IntPtr pPrettyUrl = IntPtr.Zero;
            Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
            try
            {
                AGDnsApi.ag_dns_stamp dnsStampC =
                    DnsApiConverter.ToNativeObject(dnsStamp, allocatedPointers);
                IntPtr pDnsStampC = MarshalUtils.StructureToPtr(dnsStampC, allocatedPointers);
                pPrettyUrl = AGDnsApi.ag_dns_stamp_pretty_url(pDnsStampC);
                string prettyUrl = MarshalUtils.PtrToString(pPrettyUrl);
                return prettyUrl;
            }
            catch (Exception ex)
            {
                Logger.Verbose("Getting DNS stamp pretty url failed with an error {0}", ex);
                return null;
            }
            finally
            {
                MarshalUtils.SafeFreeHGlobal(allocatedPointers);
                AGDnsApi.ag_str_free(pPrettyUrl);
            }
        }

        /// <summary>
        /// Gets the DNS stamp prettier url specified by <see cref="DnsStamp"/> object
        /// </summary>
        /// <param name="dnsStamp">DNS stamp object
        /// (<seealso cref="DnsStamp"/>)</param>
        /// <returns>DNS stamp as a string</returns>
        public static string GetDnsStampPrettierUrl(DnsStamp dnsStamp)
        {
            IntPtr pDnsStampPrettierUrl = IntPtr.Zero;
            Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
            try
            {
                AGDnsApi.ag_dns_stamp dnsStampC =
                    DnsApiConverter.ToNativeObject(dnsStamp, allocatedPointers);
                IntPtr pDnsStampC = MarshalUtils.StructureToPtr(dnsStampC, allocatedPointers);
                pDnsStampPrettierUrl = AGDnsApi.ag_dns_stamp_prettier_url(pDnsStampC);
                string dnsStampPrettierUrl = MarshalUtils.PtrToString(pDnsStampPrettierUrl);
                return dnsStampPrettierUrl;
            }
            catch (Exception ex)
            {
                Logger.Verbose("Getting DNS stamp prettier url failed with an error {0}", ex);
                return null;
            }
            finally
            {
                MarshalUtils.SafeFreeHGlobal(allocatedPointers);
                AGDnsApi.ag_str_free(pDnsStampPrettierUrl);
            }
        }

        /// <summary>
        /// Gets the DNS stamp string specified by <see cref="DnsStamp"/> object
        /// </summary>
        /// <param name="dnsStamp">DNS stamp object
        /// (<seealso cref="DnsStamp"/>)</param>
        /// <returns>DNS stamp as a string</returns>
        public static string GetDnsStampString(DnsStamp dnsStamp)
        {
            // Don't invoke "dnsStamp.ToString()" within this method to prevent infinite recursion
            Logger.Verbose("Start getting DNS stamp string from {0}",
                dnsStamp.ServerAddress);
            IntPtr pDnsStampString = IntPtr.Zero;
            Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
            try
            {
                AGDnsApi.ag_dns_stamp dnsStampC =
                    DnsApiConverter.ToNativeObject(dnsStamp, allocatedPointers);
                IntPtr pDnsStampC = MarshalUtils.StructureToPtr(dnsStampC, allocatedPointers);
                pDnsStampString = AGDnsApi.ag_dns_stamp_to_str(pDnsStampC);
                string dnsStampString = MarshalUtils.PtrToString(pDnsStampString);
                Logger.Verbose("Getting DNS stamp string has been successfully completed");
                return dnsStampString;
            }
            catch (Exception ex)
            {
                Logger.Verbose("Getting DNS stamp string failed with an error {0}", ex);
                return null;
            }
            finally
            {
                MarshalUtils.SafeFreeHGlobal(allocatedPointers);
                AGDnsApi.ag_str_free(pDnsStampString);
            }
        }

        /// <summary>
        /// Checks if specified rule is valid
        /// </summary>
        /// <param name="ruleText">Rule text</param>
        /// <returns>True, is specified rule is valid, otherwise false</returns>
        public static bool IsRuleValid(string ruleText)
        {
            if (string.IsNullOrEmpty(ruleText))
            {
                return false;
            }

            return AGDnsApi.ag_is_valid_dns_rule(ruleText);
        }

        /// <summary>
        /// Checks if upstream is valid and available
        /// </summary>
        /// <param name="upstreamOptions">Upstream options
        /// (<seealso cref="UpstreamOptions"/>)</param>
        /// <param name="timeoutMs">Maximum amount of time allowed for upstream exchange (in milliseconds)</param>
        /// <param name="ipv6Available">Whether IPv6 is available (i.e., bootstrapper is allowed to make AAAA queries)</param>
        /// <param name="offline">Don't perform online upstream check</param>
        public static bool TestUpstream(
            UpstreamOptions upstreamOptions, 
            uint timeoutMs,
            bool ipv6Available, 
            bool offline)
        {
            IntPtr pUpstreamOptionsC = IntPtr.Zero;
            Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
            IntPtr pError = IntPtr.Zero;
            try
            {
                Logger.Info("Start testing upstream {0}", upstreamOptions);
                CertificateVerificationCallback certificateVerificationCallback = new CertificateVerificationCallback();
                AGDnsApi.ag_upstream_options upstreamOptionsC =
                    DnsApiConverter.ToNativeObject(upstreamOptions, allocatedPointers);
                AGDnsApi.cbd_onCertificateVerification testUpstreamCallbackC =
                    DnsApiConverter.ToNativeObject(certificateVerificationCallback);
                pUpstreamOptionsC = MarshalUtils.StructureToPtr(upstreamOptionsC);
                pError = AGDnsApi.ag_test_upstream(
                    pUpstreamOptionsC, 
                    timeoutMs,
                    ipv6Available, 
                    testUpstreamCallbackC, 
                    offline);
                string error = MarshalUtils.PtrToString(pError);
                if (string.IsNullOrEmpty(error))
                {
                    Logger.Info("Testing upstream has been completed successfully");
                    return true;
                }

                Logger.Info("Testing upstream failed with an error {0}", error);
                return false;
            }
            catch (Exception ex)
            {
                Logger.QuietWarn(ex,"Testing upstream failed with an error");
                return false;
            }
            finally
            {
                AGDnsApi.ag_str_free(pError);
                MarshalUtils.SafeFreeHGlobal(allocatedPointers);
                MarshalUtils.SafeFreeHGlobal(pUpstreamOptionsC);
            }
        }
    }
}
