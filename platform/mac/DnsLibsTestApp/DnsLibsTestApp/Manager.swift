import Foundation
import NetworkExtension
import Combine

@MainActor
final class Manager: ObservableObject {
    enum Provider {
        case packetTunnel
        case dnsProxy
    }

    static let shared = Manager()

    @Published private(set) var logText: String = ""

    private static let packetTunnelDescription = "DnsLibs PacketTunnel"
    private static let dnsProxyDescription = "DnsLibs DNS Proxy"

#if os(macOS)
    static let systemExtensionBundleIdentifier = "com.adguard.dns.DnsLibsTestApp.SystemExtension"
    private static let packetTunnelProviderBundleIdentifier = systemExtensionBundleIdentifier
    private static let dnsProxyProviderBundleIdentifier = systemExtensionBundleIdentifier
#else
    private static let packetTunnelProviderBundleIdentifier = "com.adguard.dns.DnsLibsTestApp.PacketTunnel"
    private static let dnsProxyProviderBundleIdentifier = "com.adguard.dns.DnsLibsTestApp.DnsProxy"
#endif

    func clearLog() {
        logText = ""
    }

    func appendLog(_ line: String) {
        if logText.isEmpty {
            logText = line
        } else {
            logText = line + "\n" + logText
        }
    }

    func start(provider: Provider) async throws {
        try await start(provider: provider, providerConfiguration: nil)
    }

    func start(provider: Provider, providerConfiguration: [String: Any]?) async throws {
        appendLog("Start: \(provider == .packetTunnel ? "PacketTunnel" : "DnsProxyProvider")")
        do {
#if os(macOS)
            appendLog("System extension: install/update")
            try await SystemManager.shared.installOrUpdate()
            appendLog("System extension: ok")
#endif
            switch provider {
            case .packetTunnel:
                appendLog("PacketTunnel: load/create configuration")
                var manager = try await loadOrCreatePacketTunnelManager(providerConfiguration: providerConfiguration)
                appendLog("PacketTunnel: save configuration")
                try await savePacketTunnelManager(manager)
                manager = try await loadOrCreatePacketTunnelManager(providerConfiguration: providerConfiguration)
                appendLog("PacketTunnel: start")
                try manager.connection.startVPNTunnel()
            case .dnsProxy:
                appendLog("DNS proxy: load configuration")
                let manager = try await loadDNSProxyManager()
                appendLog("DNS proxy: update configuration")
                configureDNSProxyManager(manager, providerConfiguration: providerConfiguration)
                appendLog("DNS proxy: save configuration")
                try await saveDNSProxyManager(manager)
            }
            appendLog("Successfully started")
        } catch {
            appendLog("Error: \(error.localizedDescription)")
            throw error
        }
    }

    func deleteConfiguration(provider: Provider) async throws {
        appendLog("Delete: \(provider == .packetTunnel ? "PacketTunnel" : "DnsProxyProvider")")
        do {
            switch provider {
            case .packetTunnel:
                appendLog("PacketTunnel: load configuration")
                let manager = try await loadExistingPacketTunnelManager()
                guard let manager else {
                    appendLog("Successfully deleted")
                    return
                }
                appendLog("PacketTunnel: stop")
                manager.connection.stopVPNTunnel()
                appendLog("PacketTunnel: remove from preferences")
                try await manager.removeFromPreferences()
            case .dnsProxy:
                appendLog("DNS proxy: load configuration")
                let manager = try await loadDNSProxyManager()
                appendLog("DNS proxy: remove from preferences")
                try await manager.removeFromPreferences()
            }
            appendLog("Successfully deleted")
        } catch {
            appendLog("Error: \(error.localizedDescription)")
            throw error
        }
    }

    func stop(provider: Provider) async throws {
        appendLog("Stop: \(provider == .packetTunnel ? "PacketTunnel" : "DnsProxyProvider")")
        do {
            switch provider {
            case .packetTunnel:
                appendLog("PacketTunnel: load configuration")
                let manager = try await loadExistingPacketTunnelManager()
                appendLog("PacketTunnel: stop")
                manager?.connection.stopVPNTunnel()
            case .dnsProxy:
                appendLog("DNS proxy: load configuration")
                let manager = try await loadDNSProxyManager()
                guard manager.isEnabled else {
                    appendLog("Successfully stopped")
                    return
                }
                appendLog("DNS proxy: disable")
                manager.isEnabled = false
                appendLog("DNS proxy: save configuration")
                try await saveDNSProxyManager(manager)
            }
            appendLog("Successfully stopped")
        } catch {
            appendLog("Error: \(error.localizedDescription)")
            throw error
        }
    }

    private func loadExistingPacketTunnelManager() async throws -> NETunnelProviderManager? {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        let manager = managers.first(where: { $0.localizedDescription == Self.packetTunnelDescription })
        return manager
    }

    private func loadOrCreatePacketTunnelManager() async throws -> NETunnelProviderManager {
        return try await loadOrCreatePacketTunnelManager(providerConfiguration: nil)
    }

    private func loadOrCreatePacketTunnelManager(providerConfiguration: [String: Any]?) async throws -> NETunnelProviderManager {
        if let existing = try await loadExistingPacketTunnelManager() {
            configurePacketTunnelManager(existing, providerConfiguration: providerConfiguration)
            return existing
        }

        let manager = NETunnelProviderManager()
        configurePacketTunnelManager(manager, providerConfiguration: providerConfiguration)
        return manager
    }

    private func configurePacketTunnelManager(_ manager: NETunnelProviderManager, providerConfiguration: [String: Any]?) {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.packetTunnelProviderBundleIdentifier
        proto.serverAddress = "127.0.0.1"

        if let providerConfiguration {
            proto.providerConfiguration = providerConfiguration
        } else if let existing = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration {
            proto.providerConfiguration = existing
        }

        manager.localizedDescription = Self.packetTunnelDescription
        manager.protocolConfiguration = proto
        manager.isEnabled = true
    }

    private func savePacketTunnelManager(_ manager: NETunnelProviderManager) async throws {
        try await manager.saveToPreferences()
    }

    private func loadDNSProxyManager() async throws -> NEDNSProxyManager {
        let manager = NEDNSProxyManager.shared()
        try await manager.loadFromPreferences()
        return manager
    }

    private func configureDNSProxyManager(_ manager: NEDNSProxyManager, providerConfiguration: [String: Any]?) {
        if manager.localizedDescription?.isEmpty ?? true {
            manager.localizedDescription = Self.dnsProxyDescription
        }

        let proto = NEDNSProxyProviderProtocol()
        proto.providerBundleIdentifier = Self.dnsProxyProviderBundleIdentifier

        if let providerConfiguration {
            proto.providerConfiguration = providerConfiguration
        } else if let existing = manager.providerProtocol?.providerConfiguration {
            proto.providerConfiguration = existing
        }

        manager.providerProtocol = proto
        manager.isEnabled = true
    }

    private func saveDNSProxyManager(_ manager: NEDNSProxyManager) async throws {
        try await manager.saveToPreferences()
    }
}
