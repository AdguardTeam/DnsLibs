import Foundation
import Combine
import Darwin

final class LogReader: ObservableObject {
    private let queue: DispatchQueue
    private let appGroupId: String
    private let fileName: String
    private var fileURL: URL?

    @Published private(set) var lines: [String] = []

    private var fileDescriptor: Int32 = -1
    private var source: DispatchSourceFileSystemObject?

    init(queue: DispatchQueue = DispatchQueue(label: "com.adguard.dns.logreader.queue"), appGroupId: String = "group.com.adguard.dns.DnsLibsTestApp", fileName: String = "dns-proxy-events.log") {
        self.queue = queue
        self.appGroupId = appGroupId
        self.fileName = fileName
    }

    func start() throws {
        guard fileURL == nil else { return }
        guard let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupId) else {
            throw NSError(domain: "LogReader", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to resolve App Group container URL"])
        }
        let url = containerURL.appendingPathComponent(fileName, isDirectory: false)
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil)
        }
        fileURL = url

        fileDescriptor = open(url.path, O_EVTONLY)
        if fileDescriptor < 0 {
            throw NSError(domain: "LogReader", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to open log file for watching"])
        }

        let src = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fileDescriptor, eventMask: [.extend], queue: queue)
        src.setEventHandler { [weak self] in
            self?.drainAvailableLines()
        }
        src.setCancelHandler { [weak self] in
            guard let self else { return }
            if self.fileDescriptor >= 0 {
                close(self.fileDescriptor)
                self.fileDescriptor = -1
            }
        }
        source = src
        src.resume()

        drainAvailableLines()
    }

    func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            self.source?.cancel()
            self.source = nil
            self.fileURL = nil
        }
    }

    @MainActor
    func takeLines() -> [String] {
        let taken = lines
        lines.removeAll(keepingCapacity: true)
        return taken
    }

    private func drainAvailableLines() {
        guard let url = fileURL else { return }
        guard let drained = try? drain(url: url), !drained.isEmpty else { return }

        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.lines.append(contentsOf: drained)
        }
    }

    private func drain(url: URL) throws -> [String] {
        let data = try Data(contentsOf: url)
        guard !data.isEmpty else { return [] }

        let text = String(decoding: data, as: UTF8.self)
        let endsWithNewline = text.hasSuffix("\n")
        var parts = text.components(separatedBy: "\n")

        if endsWithNewline {
            if parts.last == "" {
                parts.removeLast()
            }
            try Data().write(to: url, options: .atomic)
            return parts
        }

        guard parts.count >= 2 else {
            return []
        }

        let remaining = parts.removeLast()
        let consumed = parts
        let remainingData = Data(remaining.utf8)
        try remainingData.write(to: url, options: .atomic)
        return consumed
    }
}
