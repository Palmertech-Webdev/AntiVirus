import Foundation
import EndpointSecurity

// MARK: - Bootstrap
print("Starting Fenrir macOS Endpoint Security Agent...")

let config = AgentConfig.load()
print("Device: \(config.deviceId) | Backend: \(config.backendURL)")

// Initialise subsystems
let scanEngine = ScanEngine()
scanEngine.initialize()

let processInventory = ProcessInventory()

let controlPlaneClient = ControlPlaneClient(config: config)

let telemetryQueue = TelemetryQueueStore(maxSize: 50, client: controlPlaneClient)

let broker = RealtimeProtectionBroker(
    config: config,
    scanEngine: scanEngine,
    processInventory: processInventory,
    telemetryQueue: telemetryQueue
)

let esManager = EndpointSecurityManager(broker: broker)
guard esManager.start() else {
    print("Failed to start EndpointSecurityManager. Ensure the ES entitlement is granted.")
    exit(1)
}

// Graceful shutdown on SIGTERM / SIGINT
let signalSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
signalSource.setEventHandler {
    print("SIGTERM received. Flushing telemetry and shutting down...")
    broker.flushAll()
    esManager.stop()
    exit(0)
}
signal(SIGTERM, SIG_IGN)
signalSource.resume()

let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
sigintSource.setEventHandler {
    print("SIGINT received. Shutting down...")
    broker.flushAll()
    esManager.stop()
    exit(0)
}
signal(SIGINT, SIG_IGN)
sigintSource.resume()

print("Agent is running.")
RunLoop.main.run()
