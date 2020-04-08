using System;
using System.Collections.Generic;
using Adguard.Dns.Api;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using Adguard.Dns.Helpers;
using Adguard.Dns.Logging;

namespace Adguard.Dns.Utils
{
    /// <summary>
    /// Helper methods for working with DNS libs
    /// </summary>
    internal static class DnsUtils
    {
        private static readonly ILog LOG = LogProvider.For<DnsApi>();
        
        /// <summary>
        /// Parses a specified DNS stamp string (<seealso cref="dnsStampStr"/>)
        /// </summary>
        /// <param name="dnsStampStr">DNS stamp string</param>
        /// <returns>DNS stamp as a <see cref="DnsStamp"/> instance</returns>
        internal static DnsStamp ParseDnsStamp(string dnsStampStr)
        {
            LOG.InfoFormat("Start parsing DNS stamp {0}", dnsStampStr);
            IntPtr pDnsStampResult = IntPtr.Zero;
            try
            {
                pDnsStampResult = AGDnsApi.ag_parse_dns_stamp(dnsStampStr);
                AGDnsApi.ag_parse_dns_stamp_result dnsStampResult =
                    MarshalUtils.PtrToStructure<AGDnsApi.ag_parse_dns_stamp_result>(pDnsStampResult);
                if (dnsStampResult.error != IntPtr.Zero)
                {
                    string error = MarshalUtils.PtrToString(dnsStampResult.error);
                    LOG.InfoFormat("Parsing DNS stamp {0} failed with an error {1}", 
                        dnsStampStr,
                        error);
                    return null;
                }

                LOG.Info("Parsing DNS stamp has been completed successfully");
                DnsStamp dnsStamp = DnsApiConverter.FromNativeObject(dnsStampResult.stamp);
                return dnsStamp;
            }
            catch (Exception ex)
            {
                LOG.InfoException("Parsing DNS stamp failed with an error {0}", ex);
                return null;
            }
            finally
            {
                AGDnsApi.ag_parse_dns_stamp_result_free(pDnsStampResult);
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
