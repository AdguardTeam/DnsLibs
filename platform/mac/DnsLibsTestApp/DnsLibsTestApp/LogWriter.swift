import Foundation

final class LogWriter {
    private let queue: DispatchQueue
    private let appGroupId: String
    private let fileName: String
    private var fileURL: URL?

    init(queue: DispatchQueue, appGroupId: String = "group.com.adguard.dns.DnsLibsTestApp", fileName: String = "dns-proxy-events.log") {
        self.queue = queue
        self.appGroupId = appGroupId
        self.fileName = fileName
    }

    func start() throws {
        guard fileURL == nil else { return }
        guard let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupId) else {
            throw NSError(domain: "LogWriter", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to resolve App Group container URL"])
        }
        let url = containerURL.appendingPathComponent(fileName, isDirectory: false)
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil)
        }
        fileURL = url
    }

    func stop() {
        queue.async { [weak self] in
            self?.fileURL = nil
        }
    }

    func writeLine(_ line: String) {
        let data = Data((line + "\n").utf8)
        write(data)
    }

    func write(_ data: Data) {
        queue.async { [weak self] in
            guard let self else { return }
            guard let url = self.fileURL else { return }

            do {
                let handle = try FileHandle(forWritingTo: url)
                try handle.seekToEnd()
                try handle.write(contentsOf: data)
                try handle.close()
            } catch {
                return
            }
        }
    }
}
