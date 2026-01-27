import SwiftUI
import Combine

struct ContentView: View {
    @ObservedObject private var manager = Manager.shared
    @StateObject private var logReader = LogReader()
    @State private var upstream: String = "https://dns.adguard-dns.com/dns-query"

    private enum ProviderType: String, CaseIterable, Identifiable {
        case packetTunnel = "Packet Tunnel"
        case dnsProxyProvider = "DNS Proxy"

        var id: String { rawValue }
    }

    @State private var providerType: ProviderType = .packetTunnel

    var body: some View {
        VStack {
            Spacer()
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text("DnsLibs test application")
            Spacer()
            HStack {
                Spacer()
                Picker("Provider", selection: $providerType) {
                    ForEach(ProviderType.allCases) { type in
                        Text(type.rawValue).tag(type)
                    }
                }
                .pickerStyle(.menu)
                .fixedSize()
                Spacer()
            }
            HStack {
                Spacer()
                Text("Upstream")
                TextField("Upstream", text: $upstream)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 520)
                Spacer()
            }
            Spacer()
            HStack {
                Spacer()
                Button("Start") {
                    startSelectedProvider()
                }
                Spacer()
                Button("Stop") {
                    stopSelectedProvider()
                }
                Spacer()
                Button("Delete") {
                    deleteSelectedProvider()
                }
                Spacer()
            }

            ScrollView {
                Text(manager.logText)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
            .frame(maxWidth: .infinity, maxHeight: 200)
            .font(.system(.body, design: .monospaced))
            .padding(.horizontal)
            Spacer()
        }
        .padding()
        .onReceive(logReader.$lines) { _ in
            Task { @MainActor in
                let drained = logReader.takeLines()
                guard !drained.isEmpty else { return }
                for message in drained {
                    if let data = message.data(using: .utf8),
                       let obj = try? JSONSerialization.jsonObject(with: data, options: []) as? Dictionary<String, Any>
                    {
                        Manager.shared.appendLog("Request: \(obj["domain"] ?? "null") \(obj["type"] ?? "null")")
                    }
                }
            }
        }
    }

    private func startSelectedProvider() {
        manager.clearLog()
        switch providerType {
        case .packetTunnel:
            Task {
                try? await manager.start(provider: .packetTunnel, providerConfiguration: [
                    "Upstream": upstream
                ])
            }

            do {
                try logReader.start()
            } catch {
                Manager.shared.appendLog("LogReader error: \(error.localizedDescription)")
                return
            }
        case .dnsProxyProvider:
            Task {
                try? await manager.start(provider: .dnsProxy, providerConfiguration: [
                    "Upstream": upstream
                ])
            }
        }
    }

    private func stopSelectedProvider() {
        manager.clearLog()
        switch providerType {
        case .packetTunnel:
            logReader.stop()
            Task {
                try? await manager.stop(provider: .packetTunnel)
            }
        case .dnsProxyProvider:
            Task {
                try? await manager.stop(provider: .dnsProxy)
            }
        }
    }

    private func deleteSelectedProvider() {
        manager.clearLog()
        switch providerType {
        case .packetTunnel:
            logReader.stop()
            Task {
                try? await manager.deleteConfiguration(provider: .packetTunnel)
            }
        case .dnsProxyProvider:
            Task {
                try? await manager.deleteConfiguration(provider: .dnsProxy)
            }
        }
    }
}

#Preview {
    ContentView()
}
