// TunnelBar — a tiny menu bar app that turns the SSH tunnels in ~/.ssh/config on and off.
//
// Any `Host` block (without wildcards) that has LocalForward / RemoteForward / DynamicForward
// lines shows up as a tunnel. Each tunnel runs as `/usr/bin/ssh -N <host>`, so everything
// OpenSSH supports (ProxyJump, IdentityFile, agent, certificates…) just works.

import AppKit
import ServiceManagement
import SwiftUI

// MARK: - SSH config

struct Tunnel: Identifiable, Hashable {
    let host: String
    let forwards: [String]
    var id: String { host }
}

enum SSHConfig {
    static var path: String {
        if let p = ProcessInfo.processInfo.environment["TUNNELBAR_SSH_CONFIG"], !p.isEmpty {
            return (p as NSString).expandingTildeInPath
        }
        return (NSHomeDirectory() as NSString).appendingPathComponent(".ssh/config")
    }

    static var modificationDate: Date? {
        (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date
    }

    static func loadTunnels() -> [Tunnel] {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
        var tunnels: [Tunnel] = []
        var hosts: [String] = []
        var forwards: [String] = []

        func flush() {
            if !forwards.isEmpty {
                for host in hosts where !host.contains(where: { "*?!".contains($0) }) {
                    tunnels.append(Tunnel(host: host, forwards: forwards))
                }
            }
            hosts = []
            forwards = []
        }

        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let parts = line.split(maxSplits: 1, whereSeparator: { $0 == " " || $0 == "\t" || $0 == "=" })
            guard let keyword = parts.first?.lowercased() else { continue }
            let arg = parts.count > 1 ? parts[1].trimmingCharacters(in: CharacterSet(charactersIn: " \t=")) : ""
            switch keyword {
            case "host":
                flush()
                hosts = arg.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            case "match":
                flush()
            case "localforward": forwards.append(describe("L", arg))
            case "remoteforward": forwards.append(describe("R", arg))
            case "dynamicforward": forwards.append(describe("D", arg))
            default: break
            }
        }
        flush()
        return tunnels
    }

    private static func describe(_ kind: String, _ arg: String) -> String {
        let p = arg.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard let listen = p.first else { return arg }
        let from = listen.contains(":") ? listen : ":" + listen
        switch kind {
        case "L": return p.count >= 2 ? "local \(from) → \(p[1])" : "local \(arg)"
        case "R": return p.count >= 2 ? "remote \(from) → \(p[1])" : "remote \(arg)"
        default: return "SOCKS \(from)"
        }
    }

    static let template = """
        # SSH config — TunnelBar lists every Host below that has a *Forward line.
        #
        # Example:
        #
        # Host db-tunnel
        #     HostName bastion.example.com
        #     User your-username
        #     IdentityFile ~/.ssh/id_ed25519
        #     LocalForward 5433 db.internal:5432      # localhost:5433 → db.internal:5432
        #
        # Host socks
        #     HostName my-server.example.com
        #     DynamicForward 1080                     # SOCKS proxy on localhost:1080

        """
}

// MARK: - Tunnel manager

enum TunnelState: Equatable {
    case off, connecting, connected, failed(String)
}

/// Collects ssh's stderr into whole lines (data can arrive split mid-line).
final class LineBuffer: @unchecked Sendable {
    private var pending = ""
    private let lock = NSLock()

    func append(_ chunk: String) -> [String] {
        lock.lock(); defer { lock.unlock() }
        pending += chunk
        var lines = pending.components(separatedBy: "\n")
        pending = lines.removeLast()
        return lines.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }
}

@MainActor
final class TunnelManager: ObservableObject {
    @Published private(set) var tunnels: [Tunnel] = []
    @Published private(set) var states: [String: TunnelState] = [:]
    @Published private(set) var wanted: Set<String> = []
    @Published private(set) var launchAtLogin = SMAppService.mainApp.status == .enabled

    private var processes: [String: Process] = [:]
    private var lastMessage: [String: String] = [:]
    private var retryCount: [String: Int] = [:]
    private var retryTasks: [String: Task<Void, Never>] = [:]
    private var configDate: Date?
    private var configTimer: Timer?
    private let persists: Bool
    private static let wantedKey = "wantedTunnels"

    init(restoreSession: Bool = true) {
        persists = restoreSession
        reload()
        if restoreSession {
            // Tunnels that were on when the app quit come back up on launch.
            let saved = UserDefaults.standard.stringArray(forKey: Self.wantedKey) ?? []
            for host in saved where tunnels.contains(where: { $0.host == host }) { start(host) }

            configTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated {
                    guard let self, SSHConfig.modificationDate != self.configDate else { return }
                    self.reload()
                }
            }
            NSWorkspace.shared.notificationCenter.addObserver(
                forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.reconnectAll() }
            }
            NotificationCenter.default.addObserver(
                forName: NSApplication.willTerminateNotification, object: nil, queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.shutdown() }
            }
        }
    }

    func state(_ host: String) -> TunnelState { states[host] ?? .off }
    var connectedCount: Int { states.values.filter { $0 == .connected }.count }
    var anyFailed: Bool {
        states.values.contains { if case .failed = $0 { return true } else { return false } }
    }

    func reload() {
        configDate = SSHConfig.modificationDate
        tunnels = SSHConfig.loadTunnels()
        let names = Set(tunnels.map(\.host))
        for host in wanted where !names.contains(host) { stop(host) }
    }

    func setOn(_ host: String, _ on: Bool) { on ? start(host) : stop(host) }
    func startAll() { tunnels.forEach { start($0.host) } }
    func stopAll() { tunnels.forEach { stop($0.host) } }

    func start(_ host: String) {
        wanted.insert(host)
        persist()
        retryTasks.removeValue(forKey: host)?.cancel()
        retryCount[host] = 0
        launch(host)
    }

    func stop(_ host: String) {
        wanted.remove(host)
        persist()
        retryTasks.removeValue(forKey: host)?.cancel()
        retryCount[host] = 0
        if let p = processes.removeValue(forKey: host), p.isRunning { p.terminate() }
        states[host] = .off
    }

    /// After sleep the old connections are usually dead; restart them instead of waiting for keepalives to time out.
    func reconnectAll() {
        for host in wanted {
            retryTasks.removeValue(forKey: host)?.cancel()
            retryCount[host] = 0
            if let p = processes.removeValue(forKey: host), p.isRunning { p.terminate() }
            states[host] = .connecting
            retryTasks[host] = Task { [weak self] in
                try? await Task.sleep(nanoseconds: 3_000_000_000)  // give Wi-Fi a moment to come back
                guard !Task.isCancelled, let self, self.wanted.contains(host) else { return }
                self.launch(host)
            }
        }
    }

    /// Stops every ssh process but remembers which tunnels were on, so they return next launch.
    func shutdown() {
        retryTasks.values.forEach { $0.cancel() }
        retryTasks.removeAll()
        for p in processes.values where p.isRunning { p.terminate() }
        processes.removeAll()
    }

    func setLaunchAtLogin(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            NSLog("TunnelBar: launch at login change failed: \(error)")
        }
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    func openConfig() {
        let path = SSHConfig.path
        let fm = FileManager.default
        if !fm.fileExists(atPath: path) {
            let dir = (path as NSString).deletingLastPathComponent
            try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            fm.createFile(atPath: path, contents: Data(SSHConfig.template.utf8), attributes: [.posixPermissions: 0o600])
        }
        NSWorkspace.shared.open(
            [URL(fileURLWithPath: path)],
            withApplicationAt: URL(fileURLWithPath: "/System/Applications/TextEdit.app"),
            configuration: NSWorkspace.OpenConfiguration()
        )
    }

    // MARK: Process handling

    private func persist() {
        guard persists else { return }
        UserDefaults.standard.set(Array(wanted).sorted(), forKey: Self.wantedKey)
    }

    private func launch(_ host: String) {
        if let p = processes[host], p.isRunning { return }

        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        p.arguments = [
            "-v", "-N", "-F", SSHConfig.path,
            "-o", "BatchMode=yes",  // never hang on a password prompt nobody can see
            "-o", "ExitOnForwardFailure=yes",  // a port already in use is an error, not a half-working tunnel
            "-o", "StrictHostKeyChecking=accept-new",  // trust new hosts once, still reject changed keys
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            host,
        ]
        let errPipe = Pipe()
        p.standardError = errPipe
        p.standardOutput = FileHandle.nullDevice
        p.standardInput = FileHandle.nullDevice

        let buffer = LineBuffer()
        errPipe.fileHandleForReading.readabilityHandler = { [weak self] fh in
            let data = fh.availableData
            guard !data.isEmpty, let chunk = String(data: data, encoding: .utf8) else { return }
            let lines = buffer.append(chunk)
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    guard let self, self.processes[host] === p else { return }
                    lines.forEach { self.handle(line: $0, host: host) }
                }
            }
        }
        p.terminationHandler = { [weak self] proc in
            let status = proc.terminationStatus
            // Short delay so the last stderr lines (the actual error) are handled first.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                MainActor.assumeIsolated {
                    errPipe.fileHandleForReading.readabilityHandler = nil
                    guard let self, self.processes[host] === proc else { return }
                    self.processes[host] = nil
                    guard self.wanted.contains(host) else {
                        self.states[host] = .off
                        return
                    }
                    let message = self.lastMessage[host].flatMap { $0.isEmpty ? nil : $0 }
                    self.states[host] = .failed(message ?? "ssh exited with status \(status)")
                    self.scheduleRetry(host)
                }
            }
        }

        lastMessage[host] = ""
        states[host] = .connecting
        processes[host] = p
        do {
            try p.run()
        } catch {
            processes[host] = nil
            states[host] = .failed("Couldn't run ssh: \(error.localizedDescription)")
        }
    }

    private func handle(line: String, host: String) {
        if line.hasPrefix("Authenticated to") {
            states[host] = .connected
            retryCount[host] = 0
        } else if !line.hasPrefix("debug"), !line.hasPrefix("OpenSSH_"), !line.hasPrefix("Transferred:") {
            lastMessage[host] = line
        }
    }

    private func scheduleRetry(_ host: String) {
        let attempt = (retryCount[host] ?? 0) + 1
        retryCount[host] = attempt
        let delay = [5, 10, 30, 60][min(attempt - 1, 3)]
        retryTasks[host] = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(delay) * 1_000_000_000)
            guard !Task.isCancelled, let self, self.wanted.contains(host) else { return }
            self.launch(host)
        }
    }
}

// MARK: - UI

struct TunnelBarApp: App {
    @StateObject private var manager = TunnelManager()

    var body: some Scene {
        MenuBarExtra {
            MenuView().environmentObject(manager)
        } label: {
            MenuBarLabel(manager: manager)
        }
        .menuBarExtraStyle(.window)
    }
}

struct MenuBarLabel: View {
    @ObservedObject var manager: TunnelManager

    var body: some View {
        let count = manager.connectedCount
        let symbol = manager.anyFailed
            ? "exclamationmark.triangle"
            : count > 0 ? "point.3.filled.connected.trianglepath.dotted" : "point.3.connected.trianglepath.dotted"
        HStack(spacing: 3) {
            Image(systemName: symbol)
            if count > 0 { Text("\(count)") }
        }
    }
}

struct MenuView: View {
    @EnvironmentObject var manager: TunnelManager

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("SSH Tunnels").font(.headline)
                Spacer()
                if !manager.tunnels.isEmpty {
                    Text("\(manager.connectedCount) of \(manager.tunnels.count) connected")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 14).padding(.top, 12).padding(.bottom, 8)

            Divider()

            if manager.tunnels.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("No tunnels yet").font(.subheadline.weight(.medium))
                    Text("Add a Host with a LocalForward, RemoteForward or DynamicForward line to ~/.ssh/config and it will appear here.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(14)
            } else {
                VStack(spacing: 0) {
                    ForEach(manager.tunnels) { TunnelRow(tunnel: $0) }
                }
                .padding(.vertical, 4)
            }

            Divider()

            VStack(spacing: 0) {
                if !manager.tunnels.isEmpty {
                    MenuRowButton(title: "Connect All") { manager.startAll() }
                    MenuRowButton(title: "Disconnect All") { manager.stopAll() }
                    Divider().padding(.vertical, 4)
                }
                MenuRowButton(title: "Edit SSH Config…") { manager.openConfig() }
                MenuRowButton(title: "Reload Config") { manager.reload() }
                MenuRowButton(title: "Launch at Login", checked: manager.launchAtLogin) {
                    manager.setLaunchAtLogin(!manager.launchAtLogin)
                }
                Divider().padding(.vertical, 4)
                MenuRowButton(title: "Quit TunnelBar") { NSApp.terminate(nil) }
            }
            .padding(.vertical, 6)
        }
        .frame(width: 330)
    }
}

struct TunnelRow: View {
    @EnvironmentObject var manager: TunnelManager
    let tunnel: Tunnel

    var body: some View {
        let state = manager.state(tunnel.host)
        HStack(alignment: .top, spacing: 10) {
            Circle().fill(color(for: state)).frame(width: 8, height: 8).padding(.top, 6)
            VStack(alignment: .leading, spacing: 2) {
                Text(tunnel.host).font(.body.weight(.medium))
                ForEach(tunnel.forwards, id: \.self) {
                    Text($0).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                if let detail = detail(for: state) {
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(isFailed(state) ? Color.red : Color.secondary)
                        .lineLimit(3)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 8)
            Toggle("", isOn: Binding(
                get: { manager.wanted.contains(tunnel.host) },
                set: { manager.setOn(tunnel.host, $0) }
            ))
            .toggleStyle(.switch)
            .controlSize(.small)
            .labelsHidden()
        }
        .padding(.horizontal, 14).padding(.vertical, 7)
    }

    private func color(for state: TunnelState) -> Color {
        switch state {
        case .off: return .gray.opacity(0.5)
        case .connecting: return .orange
        case .connected: return .green
        case .failed: return .red
        }
    }

    private func detail(for state: TunnelState) -> String? {
        switch state {
        case .connecting: return "Connecting…"
        case .failed(let message): return "\(message) — retrying"
        default: return nil
        }
    }

    private func isFailed(_ state: TunnelState) -> Bool {
        if case .failed = state { return true }
        return false
    }
}

/// Hover flag for MenuRowButton. A tiny ObservableObject instead of @State, because the
/// Command Line Tools toolchain ships without the SwiftUI macro plugin that @State now needs.
final class HoverState: ObservableObject {
    @Published var on = false
}

/// A full-width row that highlights on hover, like a native menu item.
struct MenuRowButton: View {
    let title: String
    var checked: Bool? = nil
    let action: () -> Void
    @StateObject private var hover = HoverState()

    var body: some View {
        let hovering = hover.on
        Button(action: action) {
            HStack(spacing: 6) {
                if let checked {
                    Image(systemName: "checkmark").opacity(checked ? 1 : 0).font(.caption.weight(.semibold))
                }
                Text(title)
                Spacer()
            }
            .padding(.horizontal, 8).padding(.vertical, 4)
            .frame(maxWidth: .infinity, alignment: .leading)
            .foregroundStyle(hovering ? Color.white : Color.primary)
            .background(RoundedRectangle(cornerRadius: 5).fill(hovering ? Color.accentColor : Color.clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover.on = $0 }
        .padding(.horizontal, 6)
    }
}

// MARK: - Entry point

@main
enum Main {
    static func main() {
        if let arg = CommandLine.arguments.first(where: { $0.hasPrefix("--selftest") }) {
            let seconds = Double(arg.split(separator: "=").last.map(String.init) ?? "") ?? 8
            MainActor.assumeIsolated { SelfTest.run(seconds: seconds) }
        } else {
            TunnelBarApp.main()
        }
    }
}

/// `TunnelBar --selftest[=seconds]`: start every tunnel, wait, print each state, exit. No UI, nothing saved.
@MainActor
enum SelfTest {
    static func run(seconds: Double) {
        let manager = TunnelManager(restoreSession: false)
        print("config: \(SSHConfig.path)")
        print("tunnels found: \(manager.tunnels.count)")
        manager.startAll()
        RunLoop.main.run(until: Date().addingTimeInterval(seconds))
        for t in manager.tunnels {
            print("- \(t.host) [\(t.forwards.joined(separator: ", "))]: \(manager.state(t.host))")
        }
        manager.stopAll()
        RunLoop.main.run(until: Date().addingTimeInterval(0.5))
        exit(0)
    }
}
