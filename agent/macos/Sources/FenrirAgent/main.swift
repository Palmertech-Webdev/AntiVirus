import Foundation

print("Starting Fenrir macOS Endpoint Security Agent...")

let manager = EndpointSecurityManager()
if !manager.start() {
    print("Failed to start EndpointSecurityManager. Exiting.")
    exit(1)
}

print("Agent is running. Press Ctrl+C to exit.")

// Start the main run loop to keep the daemon alive and listening for events
RunLoop.main.run()
