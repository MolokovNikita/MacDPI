import AppKit
import Foundation

struct HelperState: Decodable {
    let version: Int
    let active: Bool
    let interface: String?
    let strategy: String?
    let error: String?
    let tcp: UInt64
    let udp: UInt64
    let quic_blocked: UInt64
    let voice_fakes: UInt64
    let flow_errors: UInt64
    let checks: [ServiceCheck]?
    let packet_engine: Bool?
    let packet_error: String?
    let target_only: Bool?
    let profiles: ProfileStatus?
}

struct ProfileStatus: Decodable {
    let active: String
    let available: String?
    let last_checked: String?
    let error: String?
    let upstream_changed: Bool
}

struct ServiceCheck: Decodable {
    let host: String
    let tls: Bool
    let https: Bool?
    let bytes: Int?
    let error: String?

    var summary: String {
        if https == true {
            return "страница загружена"
        }
        if tls && (bytes ?? 0) > 0 {
            return "загрузка оборвалась после \(bytes ?? 0) байт"
        }
        return "доступ не подтверждён"
    }
}

@MainActor
final class AppModel: ObservableObject {
    static let helperVersion = 11
    nonisolated static let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev"

    @Published var active = false
    @Published var busy = false
    @Published var installed = false
    @Published var status = "Готов к подключению"
    @Published var detail = ""
    @Published var strategy = "auto"
    @Published var targetOnly = (UserDefaults.standard.object(forKey: "targetOnly") as? Bool) ?? true {
        didSet { UserDefaults.standard.set(targetOnly, forKey: "targetOnly") }
    }
    @Published var events = ""
    @Published var exporting = false
    @Published var checkingUpdates = false
    @Published var state: HelperState?

    private let worker = DispatchQueue(label: "local.macdpi.control")
    private var timer: Timer?
    private var polling = false
    private var previousError = ""
    private let binary = Bundle.main.url(forResource: "macdpi-daemon", withExtension: nil)
    private let logURL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Logs/MacDPI/app.log")

    var hasError: Bool {
        if let error = state?.error, !error.isEmpty {
            return true
        }
        return status.hasPrefix("Не удалось")
    }

    init() {
        log("app.started version=\(Self.appVersion) pid=\(ProcessInfo.processInfo.processIdentifier)")
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    func refresh() {
        guard !busy, !polling, !exporting, !checkingUpdates, let binary else { return }
        polling = true
        let uid = String(getuid())
        worker.async {
            let result = try? Self.run(binary, ["--control", "status", "--uid", uid])
            Task { @MainActor in
                self.polling = false
                guard !self.busy else { return }
                if let result, let state = try? JSONDecoder().decode(HelperState.self, from: result.output) {
                    self.apply(state)
                } else {
                    self.installed = false
                    self.active = false
                    self.status = "Готов к подключению"
                    self.detail = "Первый запуск: macOS попросит пароль администратора"
                }
            }
        }
    }

    func toggle() {
        guard !busy, let binary else { return }
        busy = true
        log("connection action; active=\(active), installed=\(installed), strategy=\(strategy), targetOnly=\(targetOnly)")

        let stopping = active
        let needsInstall = !installed
        if stopping {
            status = "Восстановление сети…"
        } else if needsInstall {
            status = "Обновление системного компонента…"
        } else {
            status = "Подключение и проверка обычного HTTPS…"
        }

        let uid = String(getuid())
        let owner = String(ProcessInfo.processInfo.processIdentifier)
        let selected = strategy
        let onlyServices = targetOnly
        worker.async {
            do {
                if needsInstall && !stopping {
                    try Self.installHelper(binary, uid: uid)
                }
                let command = stopping ? "stop" : "start"
                var arguments = ["--control", command, "--uid", uid, "--owner", owner, "--strategy", selected]
                if onlyServices { arguments.append("--target-only") }
                let result = try Self.run(binary, arguments)
                if result.code != 0 {
                    let reason = (try? JSONDecoder().decode(HelperState.self, from: result.output))?.error
                        ?? String(data: result.output, encoding: .utf8)
                        ?? "Ошибка системного компонента"
                    throw Self.error(Int(result.code), reason)
                }
                let state = try JSONDecoder().decode(HelperState.self, from: result.output)
                Task { @MainActor in
                    self.busy = false
                    self.apply(state)
                    self.log(stopping ? "Системный режим выключен" : "Включён \(state.strategy ?? selected); перехват TCP/UDP")
                }
            } catch {
                Task { @MainActor in
                    self.busy = false
                    self.status = stopping ? "Не удалось восстановить сеть" : "Не удалось подключиться"
                    self.detail = error.localizedDescription
                    self.log(error.localizedDescription)
                }
            }
        }
    }

    func checkProfileUpdates() {
        guard !checkingUpdates, !busy, let binary else { return }
        checkingUpdates = true
        let uid = String(getuid())
        worker.async {
            let result = try? Self.run(binary, ["--control", "update-profiles", "--uid", uid])
            Task { @MainActor in
                self.checkingUpdates = false
                if let result, let state = try? JSONDecoder().decode(HelperState.self, from: result.output) {
                    self.apply(state)
                } else { self.log("Не удалось проверить обновления профилей") }
            }
        }
    }

    func saveReport() {
        guard !exporting, let binary else { return }
        let panel = NSSavePanel()
        panel.title = "Сохранить диагностику MacDPI"
        let date = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        panel.nameFieldStringValue = "macdpi-report-\(date).txt"
        panel.directoryURL = FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first
        panel.begin { response in
            guard response == .OK, let target = panel.url else { return }
            self.exporting = true
            self.log("diagnostic report requested")
            let uid = String(getuid())
            let logURL = self.logURL
            self.worker.async {
                do {
                    let result = try Self.run(binary, ["--control", "diagnostics", "--uid", uid])
                    var report = "MacDPI GUI \(Self.appVersion)\n"
                    report += "Time: \(ISO8601DateFormatter().string(from: Date()))\n"
                    report += "Helper export exit: \(result.code)\n\n"
                    report += String(decoding: result.output, as: UTF8.self)
                    report += "\n\nGUI EVENT LOG\n"
                    for url in [logURL.appendingPathExtension("1"), logURL] {
                        if let text = try? String(contentsOf: url, encoding: .utf8) {
                            report += text + "\n"
                        }
                    }
                    try Data(report.utf8).write(to: target, options: .atomic)
                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
                    Task { @MainActor in
                        self.exporting = false
                        self.log("report saved: \(target.path)")
                        NSWorkspace.shared.activateFileViewerSelecting([target])
                    }
                } catch {
                    Task { @MainActor in
                        self.exporting = false
                        self.detail = error.localizedDescription
                        self.log("report export failed: \(error.localizedDescription)")
                    }
                }
            }
        }
    }

    /// The root helper also stops the tunnel on its own if the app dies without calling this.
    func stopBeforeQuit() {
        guard let binary else { return }
        _ = try? Self.run(binary, ["--control", "stop", "--uid", String(getuid())])
    }

    private func apply(_ result: HelperState) {
        installed = result.version == Self.helperVersion
        active = result.active
        if result.active, let scoped = result.target_only { targetOnly = scoped }
        state = result

        if !installed {
            status = "Нужно обновить системный компонент"
            detail = "Нажмите «Подключить» и разрешите обновление в диалоге macOS"
        } else if result.active {
            status = "Системный режим включён"
            detail = "\(result.interface ?? "Сеть") · TCP + UDP · DNS-over-HTTPS"
            if let discord = result.checks?.first(where: { $0.host == "discord.com" }), discord.https != true {
                detail = "Туннель включён. Проверка Discord: \(discord.summary)"
            }
        } else {
            status = "Отключено"
            detail = "Настройки сети восстановлены"
        }

        if let error = result.error, !error.isEmpty {
            detail = error
            if previousError != error {
                log(error)
                previousError = error
            }
        }
    }

    private func log(_ text: String) {
        let line = "\(ISO8601DateFormatter().string(from: Date())) \(text)\n"
        events = String((events + line).suffix(14000))

        let fileManager = FileManager.default
        do {
            try fileManager.createDirectory(at: logURL.deletingLastPathComponent(), withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
            if let size = try? logURL.resourceValues(forKeys: [.fileSizeKey]).fileSize, size > 256 * 1024 {
                let previous = logURL.appendingPathExtension("1")
                try? fileManager.removeItem(at: previous)
                try fileManager.moveItem(at: logURL, to: previous)
            }
            if !fileManager.fileExists(atPath: logURL.path) {
                fileManager.createFile(atPath: logURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
            }
            let handle = try FileHandle(forWritingTo: logURL)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: Data(line.utf8))
        } catch {
            // The in-memory log is still shown in the app.
        }
    }

    nonisolated private static func run(_ binary: URL, _ arguments: [String]) throws -> (code: Int32, output: Data) {
        let process = Process()
        process.executableURL = binary
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, output)
    }

    nonisolated private static func installHelper(_ binary: URL, uid: String) throws {
        let result = try run(binary, ["--install-script", "--uid", uid])
        guard result.code == 0, let script = String(data: result.output, encoding: .utf8) else {
            throw error(1, "Не удалось подготовить установку")
        }
        let literal = "\"" + script
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n") + "\""
        var scriptError: NSDictionary?
        NSAppleScript(source: "do shell script \(literal) with administrator privileges")?.executeAndReturnError(&scriptError)
        if let scriptError {
            throw error(2, scriptError[NSAppleScript.errorMessage] as? String ?? "Установка отменена")
        }
        // launchd starts the helper asynchronously, so wait for its control socket.
        for _ in 0..<30 {
            if let status = try? run(binary, ["--control", "status", "--uid", uid]), status.code == 0 {
                break
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
    }

    nonisolated private static func error(_ code: Int, _ message: String) -> NSError {
        NSError(domain: "MacDPI", code: code, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
