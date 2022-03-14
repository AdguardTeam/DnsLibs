using System.Net;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Listener settings
    /// Managed mirror of <see cref="AGDnsApi.ag_listener_settings"/>
    /// </summary>
    public class ListenerSettings
    {
        /// <summary>
        /// The <see cref="IPEndPoint"/> to listen on
        /// </summary>
        public IPEndPoint EndPoint { get; set; }
        
        /// <summary>
        /// The protocol to listen for
        /// </summary>
        public AGDnsApi.ag_listener_protocol Protocol { get; set; }
        
        /// <summary>
        /// Don't close the TCP connection after sending the first response
        /// </summary>
        public bool IsPersistent { get; set; }
        
        /// <summary>
        /// Close the TCP connection this long after the last request received
        /// </summary>
        public uint IdleTimeoutMs { get; set; }
    }
}