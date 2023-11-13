namespace Adguard.Dns.Api.DnsProxyServer.Configs
{
	/// <summary>
	/// Holds out-of-band information about a DNS message or how to process it.
	/// </summary>
	/// (A managed mirror of <see cref="AGDnsApi.ag_dns_message_info"/>)
	public class DnsMessageInfo
	{
		/// <summary>
		/// If <c>true</c>, the proxy will handle the message transparently: queries are returned to the caller
		/// instead of being forwarded to the upstream by the proxy, responses are processed as if they were received
		/// from an upstream, and the processed response is returned to the caller.The proxy may return a response
		/// when transparently handling a query if the query is blocked.The proxy may still perform an upstream
		/// query when handling a message transparently, for example, to process CNAME-rewrites.
		/// </summary>
		public bool Transparent { get; set; }
	}
}
