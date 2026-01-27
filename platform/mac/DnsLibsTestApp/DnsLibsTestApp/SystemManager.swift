import Foundation

#if os(macOS)
import SystemExtensions

@MainActor
final class SystemManager: NSObject {
    static let shared = SystemManager()

    private var continuation: CheckedContinuation<Void, Error>?

    func installOrUpdate() async throws {
        if continuation != nil {
            Manager.shared.appendLog("System extension: already in progress")
            return
        }

        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation

            Manager.shared.appendLog("System extension: submit activation request")

            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: Manager.systemExtensionBundleIdentifier,
                queue: .main
            )
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }
}

extension SystemManager: OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Manager.shared.appendLog("System extension: finished (\(String(describing: result)))")
        let continuation = continuation
        self.continuation = nil
        continuation?.resume(returning: ())
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Manager.shared.appendLog("System extension: failed")
        let continuation = continuation
        self.continuation = nil
        continuation?.resume(throwing: error)
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Manager.shared.appendLog("System extension: needs user approval")
        // Intentionally no-op; macOS will show a system prompt.
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension extensionProperties: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }
}
#else

@MainActor
final class SystemManager {
    static let shared = SystemManager()

    func installOrUpdate() async throws {
    }
}
#endif
