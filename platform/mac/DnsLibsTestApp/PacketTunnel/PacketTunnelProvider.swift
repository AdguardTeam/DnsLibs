import Foundation
import NetworkExtension
import AGDnsProxy
import Network

class PacketTunnelProvider: NEPacketTunnelProvider {

    var dnsProxy : AGDnsProxy?
    var dnsTunListener : AGDnsTunListener?
    var logWriter: LogWriter?
    let mtu: Int32 = 1500
    let queue = DispatchQueue(label: "com.adguard.dns.provider.queue")

    override func startTunnel(options: [String : NSObject]?) async throws {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = NSNumber(value: mtu)
        let ipv4Settings = NEIPv4Settings(addresses: ["198.18.53.1"], subnetMasks: ["255.255.255.255"])
        ipv4Settings.includedRoutes = [NEIPv4Route(destinationAddress: "198.18.53.53", subnetMask: "255.255.255.255")]
        settings.ipv4Settings = ipv4Settings
        let dnsSettings = NEDNSSettings(servers: ["198.18.53.53"])
        dnsSettings.matchDomains = [""]
        settings.dnsSettings = dnsSettings
        setupLogger()
        try startDnsProxy()
        try await setTunnelNetworkSettings(settings)
    }

    func setupLogger() {
        AGDnsLogger.setLevel(.AGDLLDebug)
        AGDnsLogger.setCallback { level, message, size in
            guard let message, size > 0 else {
                return
            }

            let data = Data(bytes: message, count: Int(size))
            var text = String(decoding: data, as: UTF8.self)
            text = text.trimmingCharacters(in: CharacterSet(charactersIn: "\0\n\r"))

            let levelStr: String
            switch level {
            case .AGDLLTrace: levelStr = "TRACE"
            case .AGDLLDebug: levelStr = "DEBUG"
            case .AGDLLInfo: levelStr = "INFO"
            case .AGDLLWarn: levelStr = "WARN"
            case .AGDLLErr: levelStr = "ERROR"
            default: levelStr = "LOG"
            }

            NSLog("AGDnsProxy[%@]: %@", levelStr, text)
        }
    }

    func startDnsProxy() throws {
        let upstreamAddress: String = {
            if let proto = self.protocolConfiguration as? NETunnelProviderProtocol,
               let cfg = proto.providerConfiguration,
               let addr = cfg["Upstream"] as? String,
               !addr.isEmpty {
                return addr
            }
            return "https://dns.adguard-dns.com/dns-query"
        }()

        let config = AGDnsProxyConfig.getDefault()
        let upstream = AGDnsUpstream()
        upstream.id = 1
        upstream.address = upstreamAddress
        upstream.bootstrap = ["8.8.8.8"]
        config?.upstreams = [upstream]
        let events = AGDnsProxyEvents()
        events.onRequestProcessed = { [weak self] request in
            guard let self else { return }
            guard let request else { return }

            let payload: [String: Any] = [
                "domain": request.domain ?? "",
                "type": request.type ?? "",
                "startTime": request.startTime,
                "elapsed": request.elapsed,
                "status": request.status ?? "",
                "answer": request.answer ?? "",
                "originalAnswer": request.originalAnswer ?? "",
                "upstreamId": request.upstreamId ?? NSNull(),
                "bytesSent": request.bytesSent,
                "bytesReceived": request.bytesReceived,
                "rules": request.rules ?? [],
                "filterListIds": request.filterListIds ?? [],
                "whitelist": request.whitelist,
                "error": request.error ?? "",
                "cacheHit": request.cacheHit,
                "dnssec": request.dnssec,
                "blockingReason": request.blockingReason
            ]

            guard let json = try? JSONSerialization.data(withJSONObject: payload, options: []) else {
                return
            }
            guard let line = String(data: json, encoding: .utf8) else {
                return
            }
            self.logWriter?.writeLine(line)
        }
        var error : NSError?
        dnsProxy = AGDnsProxy(config: config, handler: events, error: &error)

        if logWriter == nil {
            logWriter = LogWriter(queue: queue)
        }
        try logWriter?.start()

        dnsTunListener = try AGDnsTunListener(tunFd: nil, orTunnelFlow: self.packetFlow,
                                          mtu: mtu, messageHandler: { [weak self] data, handler in
            guard let dnsProxy = self?.dnsProxy else {
                handler(nil)
                return
            }
            dnsProxy.handleMessage(data, with: AGDnsMessageInfo(), withCompletionHandler: { reply in
                handler(reply)
            })
        })
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
        self.dnsProxy?.stop()
        self.dnsProxy = nil
        self.dnsTunListener?.stop()
        self.dnsTunListener = nil
        self.logWriter?.stop()
        self.logWriter = nil
    }

    override func handleAppMessage(_ messageData: Data) async -> Data? {
        return nil
    }

    override func sleep() async {
    }

    override func wake() {
    }
}
