import Foundation
import Network
import NetworkExtension

// Transparent TCP/443 interception; UDP and non-HTTPS flows are passed through.
final class ProxyProvider: NETransparentProxyProvider {
    private let queue = DispatchQueue(label: "local.macdpi.flows")
    private var relays: [UUID: FlowRelay] = [:]
    private var healthTimer: DispatchSourceTimer?
    private var healthConnection: NWConnection?
    private var active = false
    private func probe(_ completion: @escaping (Error?) -> Void) {
        guard healthConnection == nil else { return }
        let connection = NWConnection(host: "127.0.0.1", port: 18080, using: .tcp)
        healthConnection = connection
        var completed = false
        let finish: (Error?) -> Void = { error in
            guard !completed else { return }; completed = true
            connection.stateUpdateHandler = nil; connection.cancel(); self.healthConnection = nil
            completion(error)
        }
        connection.stateUpdateHandler = { state in
            switch state { case .ready: finish(nil); case .failed(let error): finish(error); default: break }
        }
        queue.asyncAfter(deadline: .now() + 2) { if !completed { finish(NSError(domain: NSPOSIXErrorDomain, code: Int(ETIMEDOUT))) } }
        connection.start(queue: queue)
    }
    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = ["0.0.0.0", "::"].map {
            NENetworkRule(destinationNetwork: NWHostEndpoint(hostname: $0, port: "443"), prefix: 0, protocol: .TCP)
        }
        queue.async {
            self.active = true
            self.probe { error in
                guard self.active else { completionHandler(NSError(domain: NSPOSIXErrorDomain, code: Int(ECANCELED))); return }
                if let error { self.active = false; completionHandler(error); return }
                self.setTunnelNetworkSettings(settings) { error in
                    self.queue.async {
                        if error == nil && self.active {
                            let timer = DispatchSource.makeTimerSource(queue: self.queue)
                            timer.schedule(deadline: .now() + 2, repeating: 2)
                            timer.setEventHandler { [weak self] in
                                guard let self, self.active else { return }
                                self.probe { error in if let error, self.active { self.cancelProxyWithError(error) } }
                            }
                            self.healthTimer = timer; timer.resume()
                        }
                        completionHandler(error)
                    }
                }
            }
        }
    }
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcp = flow as? NEAppProxyTCPFlow, let endpoint = tcp.remoteEndpoint as? NWHostEndpoint else { return false }
        // The engine's outbound connections must never re-enter the proxy.
        if flow.metaData.sourceAppSigningIdentifier == "local.macdpi.daemon" { return false }
        let id = UUID()
        queue.async {
            guard self.relays.count < 256 else { tcp.closeReadWithError(NSError(domain: NSPOSIXErrorDomain, code: Int(ENOBUFS))); tcp.closeWriteWithError(nil); return }
            let relay = FlowRelay(flow: tcp, endpoint: endpoint, queue: self.queue) { self.relays.removeValue(forKey: id) }
            self.relays[id] = relay; relay.start()
        }
        return true
    }
    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.async {
            self.active = false; self.healthTimer?.cancel(); self.healthTimer = nil
            self.healthConnection?.stateUpdateHandler = nil; self.healthConnection?.cancel(); self.healthConnection = nil
            let active = Array(self.relays.values); active.forEach { $0.finish(nil) }; completionHandler()
        }
    }
}
private final class FlowRelay {
    let flow: NEAppProxyTCPFlow
    let endpoint: NWHostEndpoint
    let queue: DispatchQueue
    let connection = NWConnection(host: "127.0.0.1", port: 18080, using: .tcp)
    var done: () -> Void
    var closed = false
    var header = Data()
    var readEnded = false
    var writeEnded = false
    var timeout: DispatchWorkItem?
    init(flow: NEAppProxyTCPFlow, endpoint: NWHostEndpoint, queue: DispatchQueue, done: @escaping () -> Void) { self.flow = flow; self.endpoint = endpoint; self.queue = queue; self.done = done }
    func start() {
        armTimeout(15)
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                let host = self.endpoint.hostname.contains(":") ? "[\(self.endpoint.hostname)]" : self.endpoint.hostname
                let target = "\(host):\(self.endpoint.port)"
                self.connection.send(content: Data("CONNECT \(target) HTTP/1.1\r\nHost: \(target)\r\n\r\n".utf8), completion: .contentProcessed { error in
                    if let error { self.finish(error) } else { self.readHeader() }
                })
            case .failed(let error): self.finish(error)
            case .cancelled: self.finish(nil)
            default: break
            }
        }
        connection.start(queue: queue)
    }
    func armTimeout(_ seconds: Double = 120) {
        timeout?.cancel()
        let item = DispatchWorkItem { [weak self] in self?.finish(NSError(domain: NSPOSIXErrorDomain, code: Int(ETIMEDOUT))) }
        timeout = item; queue.asyncAfter(deadline: .now() + seconds, execute: item)
    }
    func readHeader() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 16384) { data, _, end, error in
            if let error { self.finish(error); return }
            if let data { self.header.append(data) }
            guard self.header.count <= 16384 else { self.finish(NSError(domain: NSPOSIXErrorDomain, code: Int(EPROTO))); return }
            guard let range = self.header.range(of: Data("\r\n\r\n".utf8)) else { if end { self.finish(NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNRESET))) } else { self.readHeader() }; return }
            guard String(data: self.header.prefix(range.lowerBound), encoding: .utf8)?.hasPrefix("HTTP/1.1 200 ") == true else { self.finish(NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNREFUSED))); return }
            let tail = Data(self.header[range.upperBound...]); self.header.removeAll()
            self.flow.open(withLocalEndpoint: nil) { error in
                self.queue.async {
                    if let error { self.finish(error); return }
                    self.armTimeout(); self.readFlow()
                    if tail.isEmpty { self.readRemote() } else { self.flow.write(tail) { error in self.queue.async { if let error { self.finish(error) } else { self.readRemote() } } } }
                }
            }
        }
    }
    func readFlow() {
        guard !closed else { return }
        flow.readData { data, error in
            self.queue.async {
                if let error { self.finish(error); return }
                self.armTimeout()
                guard let data, !data.isEmpty else {
                    self.readEnded = true
                    self.connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { error in
                        if let error { self.finish(error) } else if self.writeEnded { self.finish(nil) }
                    }); return
                }
                self.connection.send(content: data, completion: .contentProcessed { error in if let error { self.finish(error) } else { self.readFlow() } })
            }
        }
    }
    func readRemote() {
        guard !closed else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 32768) { data, _, end, error in
            if let error { self.finish(error); return }
            self.armTimeout()
            let next = {
                if end { self.writeEnded = true; self.flow.closeWriteWithError(nil); if self.readEnded { self.finish(nil) } }
                else { self.readRemote() }
            }
            if let data, !data.isEmpty { self.flow.write(data) { error in self.queue.async { if let error { self.finish(error) } else { next() } } } }
            else { next() }
        }
    }
    func finish(_ error: Error?) {
        guard !closed else { return }; closed = true
        timeout?.cancel(); connection.stateUpdateHandler = nil; connection.cancel()
        flow.closeReadWithError(error); flow.closeWriteWithError(error)
        let callback = done; done = {}; callback()
    }
}
