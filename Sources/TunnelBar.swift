// TunnelBar — a tiny menu bar app that turns the SSH tunnels in ~/.ssh/config on and off.
//
// Any `Host` (without wildcards) whose resolved config has LocalForward / RemoteForward /
// DynamicForward lines shows up as a tunnel. Each tunnel runs as `/usr/bin/ssh -N <host>`, so
// everything OpenSSH supports (ProxyJump, IdentityFile, agent, certificates…) just works.

import AppKit
import Darwin
import ServiceManagement
import SwiftUI

// MARK: - SSH config

struct Forward: Hashable {
    enum Kind: Int, Hashable { case local, dynamic, remote }

    struct Endpoint: Hashable {
        var host: String?  // nil = ssh's default bind address (localhost)
        var port: Int?
        var path: String?  // Unix socket
    }

    enum Action: Equatable {
        case open(URL)
        case copy(String)
        var label: String {
            if case .open = self { return "Open" }
            return "Copy"
        }
    }

    let kind: Kind
    let listen: Endpoint
    let target: Endpoint?  // nil for DynamicForward and dynamic RemoteForward

    /// Ports whose service isn't a web page, so clicking copies the address instead of opening a browser.
    private static let nonWebPorts: Set<Int> = [
        21, 22, 25, 53, 110, 143, 389, 445, 587, 993, 995, 1433, 1521, 2222, 3306, 3389,
        5432, 5672, 6379, 9042, 9092, 11211, 27017,
    ]

    static func isLoopback(_ host: String?) -> Bool {
        guard let host else { return true }
        return ["localhost", "127.0.0.1", "::1"].contains(host.lowercased())
    }

    static func hostPort(_ host: String, _ port: Int) -> String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    /// Where you connect on this Mac for local and SOCKS forwards, e.g. "localhost:5900".
    var localAddress: String? {
        guard kind != .remote else { return nil }
        if let path = listen.path { return path }
        guard let port = listen.port else { return nil }
        return Self.hostPort(Self.isLoopback(listen.host) ? "localhost" : listen.host!, port)
    }

    /// The address worth copying: where you connect for L/D, where the server listens for R.
    func address(server: String) -> String? {
        if kind == .remote { return listen.path ?? listen.port.map { Self.hostPort(server, $0) } }
        return localAddress
    }

    /// Human-readable "from → to", naming the server instead of its own "localhost".
    func summary(server: String) -> String {
        switch kind {
        case .dynamic:
            return "SOCKS proxy on \(localAddress ?? "?")"
        case .local:
            guard let target else { return localAddress ?? "?" }
            if let path = target.path { return "\(localAddress ?? "?") → \(server):\(path)" }
            if Self.isLoopback(target.host) {
                return "\(localAddress ?? "?") → \(target.port.map { Self.hostPort(server, $0) } ?? server)"
            }
            let to = target.port.map { Self.hostPort(target.host!, $0) } ?? target.host!
            return "\(localAddress ?? "?") → \(to) via \(server)"
        case .remote:
            let from = address(server: server) ?? "?"
            guard let target else { return "\(from) → SOCKS via this Mac" }
            if let path = target.path { return "\(from) → \(path)" }
            let host = Self.isLoopback(target.host) ? "localhost" : target.host!
            return "\(from) → \(target.port.map { Self.hostPort(host, $0) } ?? host)"
        }
    }

    /// The same forward written as an ssh command-line flag, e.g. "-L 5900:localhost:5900".
    var sshFlag: String {
        func spec(_ e: Endpoint) -> String {
            if let path = e.path { return path }
            let port = e.port.map(String.init) ?? ""
            guard let host = e.host else { return port }
            return (host.contains(":") ? "[\(host)]" : host) + ":" + port
        }
        switch kind {
        case .local: return "-L \(spec(listen)):\(target.map(spec) ?? "")"
        case .dynamic: return "-D \(spec(listen))"
        case .remote: return target.map { "-R \(spec(listen)):\(spec($0))" } ?? "-R \(spec(listen))"
        }
    }

    /// What a click does: open VNC/web forwards, copy everything else.
    var primaryAction: Action? {
        switch kind {
        case .remote:
            return nil
        case .dynamic:
            return localAddress.map { .copy("socks5://\($0)") }
        case .local:
            guard let address = localAddress else { return nil }
            guard listen.port != nil else { return .copy(address) }
            // Classify by the service's real port (the target), but connect to the local one.
            let servicePort = target?.port ?? listen.port!
            if (5900...5999).contains(servicePort), let url = URL(string: "vnc://\(address)") { return .open(url) }
            if Self.nonWebPorts.contains(servicePort) { return .copy(address) }
            let scheme = [443, 8443].contains(servicePort) ? "https" : "http"
            return URL(string: "\(scheme)://\(address)").map { .open($0) } ?? .copy(address)
        }
    }
}

struct Tunnel: Identifiable, Hashable {
    let host: String
    let hostName: String  // what the alias resolves to, e.g. "omarchy"
    let forwards: [Forward]
    var id: String { host }
}

/// Whether a forward's local port is currently bound (by ssh, or by something else).
enum PortCheck {
    static func inUse(_ forward: Forward) -> Bool? {
        guard forward.kind != .remote, let port = forward.listen.port, (1...65535).contains(port) else { return nil }
        let ipv6 = forward.listen.host?.contains(":") == true
        let fd = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        let result: Int32
        if ipv6 {
            var addr = sockaddr_in6()
            addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = in_port_t(UInt16(port).bigEndian)
            addr.sin6_addr = in6addr_loopback
            result = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
            }
        } else {
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = in_port_t(UInt16(port).bigEndian)
            let literal = forward.listen.host.map { inet_addr($0) } ?? INADDR_NONE
            addr.sin_addr.s_addr = literal != INADDR_NONE ? literal : inet_addr("127.0.0.1")
            result = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
        }
        return result != 0 && errno == EADDRINUSE
    }
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
        hostAliases().compactMap { host in
            guard let resolved = resolve(host), !resolved.forwards.isEmpty else { return nil }
            return Tunnel(host: host, hostName: resolved.hostName, forwards: resolved.forwards)
        }
    }

    /// Every concrete (wildcard-free) name on a `Host` line, in file order.
    private static func hostAliases() -> [String] {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
        var seen = Set<String>()
        var aliases: [String] = []
        for raw in text.components(separatedBy: .newlines) {
            let parts = raw.trimmingCharacters(in: .whitespaces)
                .split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "=" }).map(String.init)
            guard parts.first?.lowercased() == "host" else { continue }
            for alias in parts.dropFirst() where !alias.contains(where: { "*?!".contains($0) }) {
                if seen.insert(alias).inserted { aliases.append(alias) }
            }
        }
        return aliases
    }

    /// Asks ssh itself for the host's final config (`ssh -G`), so forwards split across several
    /// `Host` blocks, `Match` blocks and included files are all picked up exactly as ssh sees them.
    private static func resolve(_ host: String) -> (hostName: String, forwards: [Forward])? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        p.arguments = ["-G", "-F", path, host]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0, let text = String(data: data, encoding: .utf8) else { return nil }

        var hostName = host
        var forwards: [Forward] = []
        for line in text.split(separator: "\n") {
            let f = line.split(separator: " ").map(String.init)
            guard f.count >= 2 else { continue }
            switch f[0] {
            case "hostname":
                hostName = f[1]
            case "localforward" where f.count >= 3:
                if let l = endpoint(f[1]), let t = endpoint(f[2]) { forwards.append(Forward(kind: .local, listen: l, target: t)) }
            case "remoteforward":
                guard let l = endpoint(f[1]) else { continue }
                let t = f.count >= 3 ? endpoint(f[2]) : nil
                let dynamic = t == nil || (t?.host == "socks" && t?.port == 0)  // ssh -G writes "[socks]:0"
                forwards.append(Forward(kind: .remote, listen: l, target: dynamic ? nil : t))
            case "dynamicforward":
                // ssh -G also lists Unix-socket LocalForwards here; only real ports are SOCKS proxies.
                if let l = endpoint(f[1]), l.port != nil { forwards.append(Forward(kind: .dynamic, listen: l, target: nil)) }
            default:
                break
            }
        }
        // Stable sort: local forwards first, then SOCKS, then remote.
        let ordered = forwards.enumerated().sorted { ($0.element.kind.rawValue, $0.offset) < ($1.element.kind.rawValue, $1.offset) }
        return (hostName, ordered.map(\.element))
    }

    /// Parses ssh -G's forward endpoints: "5900", "[127.0.0.1]:3000", "[localhost]:5900", "/path.sock".
    private static func endpoint(_ s: String) -> Forward.Endpoint? {
        if s.hasPrefix("/") { return Forward.Endpoint(path: s) }
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") {
            let host = String(s[s.index(after: s.startIndex)..<close])
            let rest = s[s.index(after: close)...]
            guard rest.hasPrefix(":"), let port = Int(rest.dropFirst()) else { return nil }
            return Forward.Endpoint(host: host, port: port)
        }
        if let port = Int(s) { return Forward.Endpoint(port: port) }
        if let i = s.lastIndex(of: ":"), let port = Int(s[s.index(after: i)...]) {
            return Forward.Endpoint(host: String(s[..<i]), port: port)
        }
        return nil
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
    @Published private(set) var portsInUse: Set<Forward> = []  // local/SOCKS forwards whose port is bound

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

            configTimer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated {
                    guard let self else { return }
                    if SSHConfig.modificationDate != self.configDate { self.reload() }
                    self.refreshPorts()
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
        refreshPorts()
    }

    func refreshPorts() {
        let used = Set(tunnels.flatMap(\.forwards).filter { PortCheck.inUse($0) == true })
        if used != portsInUse { portsInUse = used }
    }

    enum ForwardStatus {
        case active, idle, notListening, portTaken

        var color: Color {
            switch self {
            case .active: return .green
            case .idle: return .gray.opacity(0.4)
            case .notListening: return .orange
            case .portTaken: return .red
            }
        }

        var help: String {
            switch self {
            case .active: return "Active"
            case .idle: return "Off"
            case .notListening: return "Tunnel is up but this port isn't listening"
            case .portTaken: return "Another app is using this port, so the tunnel can't open it"
            }
        }
    }

    func status(of forward: Forward, in tunnel: Tunnel) -> ForwardStatus {
        let connected = state(tunnel.host) == .connected
        // Remote forwards and Unix sockets can't be checked from here; follow the tunnel.
        guard forward.kind != .remote, forward.listen.port != nil else { return connected ? .active : .idle }
        switch (connected, portsInUse.contains(forward)) {
        case (true, true): return .active
        case (true, false): return .notListening
        case (false, true): return .portTaken
        case (false, false): return .idle
        }
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
        refreshPortsSoon()
    }

    /// ssh binds (or releases) its ports a moment after the state changes; check again shortly after.
    private func refreshPortsSoon() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
            MainActor.assumeIsolated { self?.refreshPorts() }
        }
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
                    self.refreshPorts()
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
            refreshPortsSoon()
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
        .frame(width: 370)
    }
}

struct TunnelRow: View {
    @EnvironmentObject var manager: TunnelManager
    let tunnel: Tunnel

    var body: some View {
        let state = manager.state(tunnel.host)
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .center, spacing: 10) {
                Circle().fill(color(for: state)).frame(width: 8, height: 8)
                VStack(alignment: .leading, spacing: 1) {
                    Text(tunnel.host).font(.body.weight(.medium))
                    if tunnel.hostName != tunnel.host {
                        Text(tunnel.hostName).font(.caption).foregroundStyle(.secondary)
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
            if let detail = detail(for: state) {
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(isFailed(state) ? Color.red : Color.secondary)
                    .lineLimit(3)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.leading, 18)
            }
            VStack(spacing: 1) {
                ForEach(tunnel.forwards, id: \.self) { ForwardRow(forward: $0, tunnel: tunnel) }
            }
            .padding(.leading, 12)
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

/// Per-row UI state for ForwardRow (same @State workaround as HoverState).
final class ForwardRowState: ObservableObject {
    @Published var hovering = false
    @Published var copied = false

    func flashCopied() {
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { [weak self] in self?.copied = false }
    }
}

/// One forwarded port: type badge, "from → to", live dot. Click opens or copies; ⌥-click copies
/// the address; right-click offers every option including the equivalent ssh flag.
struct ForwardRow: View {
    @EnvironmentObject var manager: TunnelManager
    let forward: Forward
    let tunnel: Tunnel
    @StateObject private var ui = ForwardRowState()

    var body: some View {
        let status = manager.status(of: forward, in: tunnel)
        let action = forward.primaryAction
        let clickable = action != nil || forward.address(server: tunnel.hostName) != nil
        HStack(spacing: 7) {
            KindBadge(kind: forward.kind)
            Text(forward.summary(server: tunnel.hostName))
                .font(.caption.monospaced())
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 4)
            if ui.copied {
                Text("Copied").font(.caption2).foregroundStyle(.secondary)
            } else if ui.hovering, clickable {
                Text(action?.label ?? "Copy").font(.caption2.weight(.medium)).foregroundStyle(Color.accentColor)
            }
            Circle().fill(status.color).frame(width: 6, height: 6).help(status.help)
        }
        .padding(.horizontal, 6).padding(.vertical, 3)
        .background(RoundedRectangle(cornerRadius: 4).fill(ui.hovering && clickable ? Color.primary.opacity(0.08) : Color.clear))
        .contentShape(Rectangle())
        .onHover { ui.hovering = $0 }
        .onTapGesture {
            if NSEvent.modifierFlags.contains(.option) || action == nil {
                copy(forward.address(server: tunnel.hostName))
            } else {
                perform(action)
            }
        }
        .contextMenu {
            if case .open(let url)? = action {
                Button("Open \(url.absoluteString)") { NSWorkspace.shared.open(url) }
            }
            if let address = forward.address(server: tunnel.hostName) {
                Button("Copy \(address)") { copy(address) }
            }
            if forward.kind == .dynamic, let address = forward.localAddress {
                Button("Copy socks5://\(address)") { copy("socks5://\(address)") }
            }
            Button("Copy ssh Flag: \(forward.sshFlag)") { copy(forward.sshFlag) }
        }
        .help("\(forward.sshFlag)\n\(status.help)")
    }

    private func perform(_ action: Forward.Action?) {
        switch action {
        case .open(let url)?: NSWorkspace.shared.open(url)
        case .copy(let text)?: copy(text)
        case nil: break
        }
    }

    private func copy(_ text: String?) {
        guard let text else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        ui.flashCopied()
    }
}

struct KindBadge: View {
    let kind: Forward.Kind

    var body: some View {
        let (letter, color, title): (String, Color, String) = {
            switch kind {
            case .local: return ("L", .blue, "Local forward: a port on this Mac reaches the server side")
            case .dynamic: return ("D", .teal, "Dynamic forward: SOCKS proxy on this Mac")
            case .remote: return ("R", .purple, "Remote forward: a port on the server reaches this Mac")
            }
        }()
        Text(letter)
            .font(.system(size: 9, weight: .bold, design: .monospaced))
            .foregroundStyle(.white)
            .frame(width: 15, height: 14)
            .background(RoundedRectangle(cornerRadius: 3).fill(color))
            .help(title)
    }
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
        manager.refreshPorts()
        for t in manager.tunnels {
            print("- \(t.host) (\(t.hostName)): \(manager.state(t.host))")
            for f in t.forwards {
                let action: String
                switch f.primaryAction {
                case .open(let url)?: action = "click opens \(url.absoluteString)"
                case .copy(let text)?: action = "click copies \(text)"
                case nil: action = "click copies \(f.address(server: t.hostName) ?? "-")"
                }
                let flag = f.sshFlag.padding(toLength: 30, withPad: " ", startingAt: 0)
                print("    \(flag) \(f.summary(server: t.hostName))  [\(manager.status(of: f, in: t))]  \(action)")
            }
        }
        manager.stopAll()
        RunLoop.main.run(until: Date().addingTimeInterval(0.5))
        exit(0)
    }
}
