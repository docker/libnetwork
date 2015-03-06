package bridge

import (
	"bytes"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/docker/libnetwork"
)

func TestSetupIPForwarding(t *testing.T) {
	defer libnetwork.SetupTestNetNS(t)()
	// Read current setting and ensure the original value gets restored
	// even though net ns will be destroyed.
	procSetting := readCurrentIPForwardingSetting(t)
	defer reconcileIPForwardingSetting(t, procSetting)

	// Disable IP Forwarding if enabled
	if bytes.Compare(procSetting, []byte("1\n")) == 0 {
		writeIPForwardingSetting(t, []byte{'0', '\n'})
	}

	// Create test interface with ip forwarding setting enabled
	br := &bridgeInterface{
		Config: &Configuration{
			BridgeName:         DefaultBridgeName,
			EnableIPForwarding: true,
		},
	}

	// Set IP Forwarding
	if err := setupIPForwarding(br); err != nil {
		t.Fatalf("Failed to setup IP forwarding: %v", err)
	}

	// Read new setting
	procSetting = readCurrentIPForwardingSetting(t)
	if bytes.Compare(procSetting, []byte("1\n")) != 0 {
		t.Fatalf("Failed to effectively setup IP forwarding")
	}
}

func TestUnexpectedSetupIPForwarding(t *testing.T) {
	defer libnetwork.SetupTestNetNS(t)()
	// Read current setting and ensure the original value gets restored
	// even though net ns will be destroyed.
	procSetting := readCurrentIPForwardingSetting(t)
	defer reconcileIPForwardingSetting(t, procSetting)

	// Create test interface without ip forwarding setting enabled
	br := &bridgeInterface{
		Config: &Configuration{
			BridgeName:         DefaultBridgeName,
			EnableIPForwarding: false,
		},
	}

	// Attempt Set IP Forwarding
	if err := setupIPForwarding(br); err == nil {
		t.Fatal("Setup IP forwarding was expected to fail")
	} else if !strings.Contains(err.Error(), "Unexpected request") {
		t.Fatalf("Setup IP forwarding failed with unexpected error: %v", err)
	}
}

func readCurrentIPForwardingSetting(t *testing.T) []byte {
	procSetting, err := ioutil.ReadFile(ipv4ForwardConf)
	if err != nil {
		t.Fatalf("Can't execute test: Failed to read current IP forwarding setting: %v", err)
	}
	return procSetting
}

func writeIPForwardingSetting(t *testing.T, chars []byte) {
	err := ioutil.WriteFile(ipv4ForwardConf, chars, ipv4ForwardConfPerm)
	if err != nil {
		t.Fatalf("Can't execute or cleanup after test: Failed to reset IP forwarding: %v", err)
	}
}

func reconcileIPForwardingSetting(t *testing.T, original []byte) {
	current := readCurrentIPForwardingSetting(t)
	if bytes.Compare(original, current) != 0 {
		writeIPForwardingSetting(t, original)
	}
}
