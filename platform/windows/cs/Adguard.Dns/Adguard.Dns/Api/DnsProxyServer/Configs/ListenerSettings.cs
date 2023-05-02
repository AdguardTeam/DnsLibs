using System.Net;

namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
    /// <summary>
    /// Listener settings
    /// Defines the various configuration options that can be used to specify DNS listener.
    /// (A managed mirror of <see cref="AGDnsApi.ag_listener_settings"/>)
    /// </summary>
    public class ListenerSettings
    {
        /// <summary>
        /// The <see cref="IPEndPoint"/> to listen on
        /// The specified port on which the listener will wait for incoming DNS queries.
        /// </summary>
        public IPEndPoint EndPoint { get; set; }
        
        /// <summary>
        /// The protocol to listen for
        /// </summary>
        public AGDnsApi.ag_listener_protocol Protocol { get; set; }
        
        /// <summary>
        /// Whether the listener should keep the TCP connection open after sending the first response.
        /// If set to true, the connection will not be closed immediately,
        /// allowing for multiple requests and responses over the same connection.
        /// </summary>
        public bool IsPersistent { get; set; }
        
        /// <summary>
        /// Idle timeout.
        /// Duration (in milliseconds) after which the listener should close the TCP connection if no
        /// requests have been received. This setting helps to prevent idle connections from consuming resources.
        /// </summary>
        public uint IdleTimeoutMs { get; set; }
    }
}