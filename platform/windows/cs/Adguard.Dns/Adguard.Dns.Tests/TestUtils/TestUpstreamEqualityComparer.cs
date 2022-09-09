using System.Collections.Generic;
using Adguard.Dns.Api.DnsProxyServer.Configs;
using AdGuard.Utils.Collections;

namespace Adguard.Dns.Tests.TestUtils
{
    public class TestUpstreamEqualityComparer : IEqualityComparer<UpstreamOptions>
    {
        public bool Equals(UpstreamOptions x, UpstreamOptions y)
        {
            return Equals(x.Address, y.Address) &&
                   CollectionUtils.CollectionsEquals(x.Bootstrap, y.Bootstrap) &&
                   x.TimeoutMs == y.TimeoutMs &&
                   Equals(x.ResolvedIpAddress, y.ResolvedIpAddress) &&
                   x.Id == y.Id &&
                   x.OutboundInterfaceIndex == y.OutboundInterfaceIndex;
        }

        public int GetHashCode(UpstreamOptions obj)
        {
            unchecked
            {
                int hashCode = (obj.Address != null ? obj.Address.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (obj.Bootstrap != null ? obj.Bootstrap.Count : 0);
                hashCode = (hashCode * 397) ^ obj.TimeoutMs.GetHashCode();
                hashCode = (hashCode * 397) ^ (obj.ResolvedIpAddress != null ? obj.ResolvedIpAddress.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ obj.Id.GetHashCode();
                hashCode = (hashCode * 397) ^ obj.OutboundInterfaceIndex.GetHashCode();
                return hashCode;
            }
        }
    }
}