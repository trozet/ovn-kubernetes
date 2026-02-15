package node

import (
	"strconv"
	"testing"
	"time"
)

func TestOpenFlowManagerDefaultNetOVSBridgeFinder(t *testing.T) {
	const nodeName = "multi-homing-worker-0.maiqueb.org"

	testCases := []struct {
		name                  string
		desc                  string
		inputPortInfo         string
		expectedBridgeName    string
		expectedPatchPortName string
	}{
		{
			name:                  "empty input ports",
			inputPortInfo:         "",
			expectedBridgeName:    "",
			expectedPatchPortName: "",
		},
		{
			name:                  "input ports without patch ports",
			inputPortInfo:         "port1",
			expectedBridgeName:    "",
			expectedPatchPortName: "",
		},
		{
			name: "input ports with a patch port",
			inputPortInfo: `
port1
port2
patch-br-ex_multi-homing-worker-0.maiqueb.org-to-br-int`,
			expectedBridgeName:    "br-ex",
			expectedPatchPortName: "patch-br-ex_multi-homing-worker-0.maiqueb.org-to-br-int",
		},
		{
			name: "input ports with a patch port for a localnet network",
			inputPortInfo: `
port1
port2
patch-vlan2003_ovn_localnet_port-to-br-int`,
			expectedBridgeName:    "",
			expectedPatchPortName: "",
		},
		{
			name: "input ports with a patch port for the default network and a localnet",
			inputPortInfo: `
port1
port2
patch-vlan2003_ovn_localnet_port-to-br-int
patch-br-ex_multi-homing-worker-0.maiqueb.org-to-br-int`,
			expectedBridgeName:    "br-ex",
			expectedPatchPortName: "patch-br-ex_multi-homing-worker-0.maiqueb.org-to-br-int",
		},
		{
			name: "input ports with a patch port for the default network, a localnet, and an extra primary UDN",
			inputPortInfo: `
port1
port2
patch-vlan2003_ovn_localnet_port-to-br-int
patch-br-ex_tenant-blue_multi-homing-worker-0.maiqueb.org-to-br-int
patch-br-ex_multi-homing-worker-0.maiqueb.org-to-br-int`,
			expectedBridgeName:    "br-ex",
			expectedPatchPortName: "patch-br-ex_multi-homing-worker-0.maiqueb.org-to-br-int",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bridgeName, patchPortName := localnetPortInfo(nodeName, tc.inputPortInfo)
			if bridgeName != tc.expectedBridgeName {
				t.Errorf("Expected bridge name %q got %q", tc.expectedBridgeName, bridgeName)
			}
			if patchPortName != tc.expectedPatchPortName {
				t.Errorf("Expected patch port name %q got %q", tc.expectedPatchPortName, patchPortName)
			}
		})
	}
}

func TestExtractCookieFromFlow(t *testing.T) {
	tests := []struct {
		name         string
		flow         string
		expectCookie string
		expectOK     bool
	}{
		{
			name:         "valid cookie",
			flow:         "cookie=0xdeff105, priority=100, table=0, actions=NORMAL",
			expectCookie: "0xdeff105",
			expectOK:     true,
		},
		{
			name:         "cookie with spaces",
			flow:         "priority=100, cookie=0xabc, table=0, actions=drop",
			expectCookie: "0xabc",
			expectOK:     true,
		},
		{
			name:         "missing cookie",
			flow:         "priority=100, table=0, actions=drop",
			expectCookie: "",
			expectOK:     false,
		},
		{
			name:         "invalid cookie",
			flow:         "cookie=nothex,priority=100,table=0,actions=drop",
			expectCookie: "",
			expectOK:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotCookie, gotOK := extractCookieFromFlow(tc.flow)
			if gotOK != tc.expectOK {
				t.Fatalf("expected ok=%v, got ok=%v", tc.expectOK, gotOK)
			}
			if gotCookie != tc.expectCookie {
				t.Fatalf("expected cookie=%q, got cookie=%q", tc.expectCookie, gotCookie)
			}
		})
	}
}

func TestCountFlowsByCookie(t *testing.T) {
	validFlows := []string{
		"cookie=0x1, priority=100, table=0, actions=drop",
		"cookie=0x1, priority=90, table=0, actions=drop",
		"cookie=0x2, priority=80, table=0, actions=drop",
	}
	counts, ok := countFlowsByCookie(validFlows)
	if !ok {
		t.Fatalf("expected countFlowsByCookie to succeed")
	}
	if counts["0x1"] != 2 || counts["0x2"] != 1 {
		t.Fatalf("unexpected cookie counts: %#v", counts)
	}

	invalidFlows := []string{
		"cookie=0x1, priority=100, table=0, actions=drop",
		"priority=90, table=0, actions=drop",
	}
	_, ok = countFlowsByCookie(invalidFlows)
	if ok {
		t.Fatalf("expected countFlowsByCookie to fail when a flow has no cookie")
	}
}

func TestShouldSyncBridgeFlowsFastPaths(t *testing.T) {
	bridge := "breth0"
	flows := []string{"cookie=0x1, priority=100, table=0, actions=drop"}

	shouldSync, err := shouldSyncBridgeFlows(bridge, flows, 2, 1, time.Now())
	if err != nil {
		t.Fatalf("expected no error for generation mismatch: %v", err)
	}
	if !shouldSync {
		t.Fatalf("expected sync when flow generation changed")
	}

	shouldSync, err = shouldSyncBridgeFlows(bridge, flows, 1, 1, time.Time{})
	if err != nil {
		t.Fatalf("expected no error for first sync: %v", err)
	}
	if !shouldSync {
		t.Fatalf("expected sync when there has never been a successful replace")
	}

	shouldSync, err = shouldSyncBridgeFlows(bridge, flows, 1, 1, time.Now().Add(-(openFlowForcedReconcilePeriod + time.Second)))
	if err != nil {
		t.Fatalf("expected no error for forced reconcile window: %v", err)
	}
	if !shouldSync {
		t.Fatalf("expected sync when forced reconcile interval has elapsed")
	}

	tooManyCookies := make([]string, 0, openFlowCookieCountCheckLimit+1)
	for i := 0; i <= openFlowCookieCountCheckLimit; i++ {
		tooManyCookies = append(tooManyCookies, "cookie=0x"+strconv.FormatInt(int64(i+1), 16)+", priority=1, table=0, actions=drop")
	}
	shouldSync, err = shouldSyncBridgeFlows(bridge, tooManyCookies, 1, 1, time.Now())
	if err != nil {
		t.Fatalf("expected no error when cookie count check limit is exceeded: %v", err)
	}
	if !shouldSync {
		t.Fatalf("expected sync when cookie count check limit is exceeded")
	}
}
