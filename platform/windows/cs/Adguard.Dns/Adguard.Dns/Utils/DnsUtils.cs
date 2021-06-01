using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Adguard.Dns.Api;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Helpers;
using Adguard.Dns.Logging;
using AdGuard.Utils.Interop;

namespace Adguard.Dns.Utils
{
    /// <summary>
    /// Helper methods for working with DNS libs
    /// </summary>
    internal static class DnsUtils
    {
        private static readonly ILog LOG = LogProvider.For<DnsApi>();

        /// <summary>
        /// Gets current DNS proxy version
        /// </summary>
        /// <returns></returns>
        internal static string GetDnsProxyVersion()
        {
            IntPtr pDnsProxyVersion = AGDnsApi.ag_dnsproxy_version();
            string dnsProxyVersion = MarshalUtils.PtrToString(pDnsProxyVersion);
            return dnsProxyVersion;
        }

        /// <summary>
        /// Parses a specified DNS stamp string (<seealso cref="dnsStampStr"/>)
        /// to <see cref="DnsStamp"/> object
        /// </summary>
        /// <param name="dnsStampStr">DNS stamp string</param>
        /// <returns>DNS stamp as a <see cref="DnsStamp"/> instance</returns>
        internal static DnsStamp ParseDnsStamp(string dnsStampStr)
        {
            LOG.InfoFormat("Start parsing DNS stamp {0}", dnsStampStr);
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
                    LOG.InfoFormat("Parsing DNS stamp {0} failed with an error {1}",
                        dnsStampStr,
                        error);
                    return null;
                }

                AGDnsApi.ag_dns_stamp dnsStampResult =
                    MarshalUtils.PtrToStructure<AGDnsApi.ag_dns_stamp>(pDnsStampResult);
                DnsStamp dnsStamp = DnsApiConverter.FromNativeObject(dnsStampResult);
                LOG.Info("Parsing DNS stamp has been completed successfully");
                return dnsStamp;
            }
            catch (Exception ex)
            {
                LOG.InfoException("Parsing DNS stamp failed with an error {0}", ex);
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
        internal static string GetDnsStampPrettyUrl(DnsStamp dnsStamp)
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
                LOG.DebugException("Getting DNS stamp pretty url failed with an error {0}", ex);
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
        internal static string GetDnsStampPrettierUrl(DnsStamp dnsStamp)
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
                LOG.DebugException("Getting DNS stamp prettier url failed with an error {0}", ex);
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
        internal static string GetDnsStampString(DnsStamp dnsStamp)
        {
            LOG.DebugFormat("Start getting DNS stamp string from {0}", dnsStamp);
            IntPtr pDnsStampString = IntPtr.Zero;
            Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
            try
            {
                AGDnsApi.ag_dns_stamp dnsStampC =
                    DnsApiConverter.ToNativeObject(dnsStamp, allocatedPointers);
                IntPtr pDnsStampC = MarshalUtils.StructureToPtr(dnsStampC, allocatedPointers);
                pDnsStampString = AGDnsApi.ag_dns_stamp_to_str(pDnsStampC);
                string dnsStampString = MarshalUtils.PtrToString(pDnsStampString);
                LOG.DebugFormat("Getting DNS stamp string has been successfully completed");
                return dnsStampString;
            }
            catch (Exception ex)
            {
                LOG.DebugException("Getting DNS stamp string failed with an error {0}", ex);
                return null;
            }
            finally
            {
                MarshalUtils.SafeFreeHGlobal(allocatedPointers);
                AGDnsApi.ag_str_free(pDnsStampString);
            }
        }

        /// <summary>
        /// Checks if upstream is valid and available
        /// </summary>
        /// <param name="upstreamOptions">Upstream options
        /// (<seealso cref="UpstreamOptions"/>)</param>
        internal static bool TestUpstream(UpstreamOptions upstreamOptions)
        {
            IntPtr pUpstreamOptionsC = IntPtr.Zero;
            Queue<IntPtr> allocatedPointers = new Queue<IntPtr>();
            IntPtr pError = IntPtr.Zero;
            try
            {
                LOG.InfoFormat("Start testing upstream {0}", upstreamOptions);
                CertificateVerificationCallback certificateVerificationCallback = new CertificateVerificationCallback();
                AGDnsApi.ag_upstream_options upstreamOptionsC =
                    DnsApiConverter.ToNativeObject(upstreamOptions, allocatedPointers);
                AGDnsApi.cbd_onCertificateVerification testUpstreamCallbackC =
                    DnsApiConverter.ToNativeObject(certificateVerificationCallback);
                pUpstreamOptionsC = MarshalUtils.StructureToPtr(upstreamOptionsC);
                pError = AGDnsApi.ag_test_upstream(pUpstreamOptionsC, testUpstreamCallbackC);
                string error = MarshalUtils.PtrToString(pError);
                if (string.IsNullOrEmpty(error))
                {
                    LOG.InfoFormat("Testing upstream has been completed successfully");
                    return true;
                }

                LOG.InfoFormat("Testing upstream failed with an error {0}", error);
                return false;
            }
            catch (Exception ex)
            {
                LOG.InfoException("Testing upstream failed with an error {0}", ex);
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
