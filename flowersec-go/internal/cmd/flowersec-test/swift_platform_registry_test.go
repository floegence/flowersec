package main

import "testing"

func TestSwiftServerAcceptanceRegistersMacOSAndIOSOnDarwinHosts(t *testing.T) {
	for _, goos := range []string{"darwin", "linux", "windows"} {
		entries := make(map[string]bool)
		for _, entry := range registryForOS(goos) {
			if entry.Suite == "acceptance" {
				entries[entry.ID] = true
			}
		}
		for _, id := range []string{
			"connector/swift-v4", "connector/swift-v4/ios-simulator",
			"controller/swift-client-handlers", "controller/swift-client-handlers/ios-simulator",
			"server/swift-acceptor", "server/swift-acceptor/ios-simulator",
			"server/swift-session-handlers", "server/swift-session-handlers/ios-simulator",
		} {
			if entries[id] != (goos == "darwin") {
				t.Fatalf("%s: unexpected Swift acceptance registration for %s", goos, id)
			}
		}
	}
}
