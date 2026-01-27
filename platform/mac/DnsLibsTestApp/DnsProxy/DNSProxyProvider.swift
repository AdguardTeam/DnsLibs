import NetworkExtension
import AGDnsProxy

class DNSProxyProvider: NEDNSProxyProvider {
    var dnsProxy: AGDnsProxy?
    var dnsFlowManager: AGDnsAppProxyFlowManager?
    var logWriter: LogWriter?
    // NEDNSProxyProvider does not have providerConfiguration field.
    // Configuration is passed by system via "options" parameter under "VendorData" key.
    var providerConfiguration: [String: Any]?
    let queue = DispatchQueue(label: "com.adguard.dns.provider.queue")

    override func startProxy(options:[String: Any]? = nil) async throws {
        NSLog("DNSProxyProvider: Starting proxy \(options)")
        self.providerConfiguration = options?["VendorData"] as? [String: Any]
        setupLogger()
        try startDnsProxy();
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
            if let cfg = self.providerConfiguration,
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
        upstream.bootstrap = ["tls://8.8.8.8"]
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

        dnsFlowManager = AGDnsAppProxyFlowManager(dnsProxy: self.dnsProxy);
    }


    override func stopProxy(with reason: NEProviderStopReason) async {
        NSLog("DNSProxyProvider: Stopping proxy")
        dnsProxy?.stop()
        dnsProxy = nil
        dnsFlowManager?.stop()
        dnsFlowManager = nil
    }

    override func sleep() async {
    }

    override func wake() {
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        return dnsFlowManager?.handle(flow, mode: .redirect) ?? false
    }
}
