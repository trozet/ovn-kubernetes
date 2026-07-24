// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package openflow

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	libof "antrea.io/libOpenflow/openflow13"
)

func TestSyncBridgeProgramsFlowsAndGroupsIncrementally(t *testing.T) {
	clientConn, switchConn := net.Pipe()
	client := newTestClient(func(context.Context, string, string) (net.Conn, error) {
		return clientConn, nil
	})
	t.Cleanup(client.Close)

	switchResult := make(chan error, 1)
	go func() {
		ports := []testPort{{number: 7, name: "patch-br-ex", mac: testMAC(7)}}
		if err := serveHandshake(switchConn, ports); err != nil {
			switchResult <- err
			return
		}
		first, err := serveBundle(switchConn)
		if err != nil {
			switchResult <- err
			return
		}
		if err := checkBundleCommands(first, []bundleCommand{
			{messageType: libof.Type_FlowMod, command: libof.FC_DELETE},
			{messageType: libof.Type_GroupMod, command: libof.OFPGC_DELETE},
			{messageType: libof.Type_GroupMod, command: libof.OFPGC_ADD},
			{messageType: libof.Type_FlowMod, command: libof.FC_ADD},
		}); err != nil {
			switchResult <- err
			return
		}

		second, err := serveBundle(switchConn)
		if err != nil {
			switchResult <- err
			return
		}
		switchResult <- checkBundleCommands(second, []bundleCommand{
			{messageType: libof.Type_FlowMod, command: libof.FC_DELETE_STRICT},
			{messageType: libof.Type_FlowMod, command: libof.FC_ADD},
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	groups := []string{"group_id=100,type=select,bucket=actions=output:7"}
	if err := client.SyncBridge(ctx, "br-ex",
		[]string{"cookie=0x1,priority=100,ip,nw_dst=10.0.0.1,actions=group:100"},
		groups,
	); err != nil {
		t.Fatalf("initial SyncBridge() error = %v", err)
	}
	if err := client.SyncBridge(ctx, "br-ex",
		[]string{"cookie=0x1,priority=100,ip,nw_dst=10.0.0.1,actions=output:7"},
		groups,
	); err != nil {
		t.Fatalf("incremental SyncBridge() error = %v", err)
	}
	if err := <-switchResult; err != nil {
		t.Fatal(err)
	}
}

func TestSyncBridgeReplaysStateAfterReconnect(t *testing.T) {
	firstClient, firstSwitch := net.Pipe()
	secondClient, secondSwitch := net.Pipe()
	connections := make(chan net.Conn, 2)
	connections <- firstClient
	connections <- secondClient

	client := newTestClient(func(ctx context.Context, _, _ string) (net.Conn, error) {
		select {
		case connection := <-connections:
			return connection, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	client.reconnectInterval = time.Millisecond
	t.Cleanup(client.Close)

	firstResult := make(chan error, 1)
	go func() {
		if err := serveHandshake(firstSwitch, nil); err != nil {
			firstResult <- err
			return
		}
		_, err := serveBundle(firstSwitch)
		if closeErr := firstSwitch.Close(); err == nil {
			err = closeErr
		}
		firstResult <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.SyncBridge(ctx, "br-ex", []string{"priority=0,actions=NORMAL"}, nil); err != nil {
		t.Fatalf("SyncBridge() error = %v", err)
	}
	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}

	replayed := make(chan error, 1)
	go func() {
		if err := serveHandshake(secondSwitch, nil); err != nil {
			replayed <- err
			return
		}
		messages, err := serveBundle(secondSwitch)
		if err == nil {
			err = checkBundleCommands(messages, []bundleCommand{
				{messageType: libof.Type_FlowMod, command: libof.FC_DELETE},
				{messageType: libof.Type_GroupMod, command: libof.OFPGC_DELETE},
				{messageType: libof.Type_FlowMod, command: libof.FC_ADD},
			})
		}
		replayed <- err
	}()
	select {
	case err := <-replayed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for flow replay after reconnect")
	}
}

func TestModifyPortsUsesControllerConnectionAndSkipsSatisfiedPorts(t *testing.T) {
	clientConn, switchConn := net.Pipe()
	client := newTestClient(func(context.Context, string, string) (net.Conn, error) {
		return clientConn, nil
	})
	t.Cleanup(client.Close)

	switchResult := make(chan error, 1)
	go func() {
		ports := []testPort{
			{
				number: 7,
				name:   "patch-one",
				mac:    testMAC(7),
			},
			{
				number:     9,
				name:       "patch-two",
				mac:        testMAC(9),
				config:     PortConfigNoFlood,
				advertised: 0x20,
			},
		}
		if err := serveHandshake(switchConn, ports); err != nil {
			switchResult <- err
			return
		}
		if err := servePortDescriptions(switchConn, ports); err != nil {
			switchResult <- err
			return
		}
		portMod, err := readMessage(switchConn)
		if err != nil {
			switchResult <- err
			return
		}
		if portMod.Type != ofpTypePortMod {
			switchResult <- fmt.Errorf("message type = %d, want PortMod", portMod.Type)
			return
		}
		if got := binary.BigEndian.Uint32(portMod.Payload[0:4]); got != 7 {
			switchResult <- fmt.Errorf("PortMod port = %d, want 7", got)
			return
		}
		if got := PortConfig(binary.BigEndian.Uint32(portMod.Payload[16:20])); got != PortConfigNoFlood {
			switchResult <- fmt.Errorf("PortMod config = %#x, want no-flood", got)
			return
		}
		barrier, err := readMessage(switchConn)
		if err != nil {
			switchResult <- err
			return
		}
		switchResult <- writeMessage(switchConn, ofpVersion, ofpTypeBarrierReply, barrier.XID, nil)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.ModifyPorts(ctx, "br-ex", []PortModification{
		{Port: 7, Config: PortConfigNoFlood, Mask: PortConfigNoFlood},
		{
			Port:      9,
			Config:    PortConfigNoFlood,
			Mask:      PortConfigNoFlood,
			Advertise: 0x20,
		},
	})
	if err != nil {
		t.Fatalf("ModifyPorts() error = %v", err)
	}
	if err := <-switchResult; err != nil {
		t.Fatal(err)
	}
}

func TestModifyPortsReportsPortErrorAfterBarrier(t *testing.T) {
	clientConn, switchConn := net.Pipe()
	client := newTestClient(func(context.Context, string, string) (net.Conn, error) {
		return clientConn, nil
	})
	t.Cleanup(client.Close)

	switchResult := make(chan error, 1)
	go func() {
		ports := []testPort{{number: 7, name: "patch", mac: testMAC(7)}}
		if err := serveHandshake(switchConn, ports); err != nil {
			switchResult <- err
			return
		}
		if err := servePortDescriptions(switchConn, ports); err != nil {
			switchResult <- err
			return
		}
		portMod, err := readMessage(switchConn)
		if err != nil {
			switchResult <- err
			return
		}
		barrier, err := readMessage(switchConn)
		if err != nil {
			switchResult <- err
			return
		}
		errorPayload := make([]byte, 4)
		binary.BigEndian.PutUint16(errorPayload[0:2], 4)
		binary.BigEndian.PutUint16(errorPayload[2:4], 1)
		if err := writeMessage(switchConn, ofpVersion, ofpTypeError, portMod.XID, errorPayload); err != nil {
			switchResult <- err
			return
		}
		switchResult <- writeMessage(switchConn, ofpVersion, ofpTypeBarrierReply, barrier.XID, nil)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.ModifyPorts(ctx, "br-ex", []PortModification{{
		Port: 7, Config: PortConfigNoFlood, Mask: PortConfigNoFlood,
	}})
	if err == nil || !strings.Contains(err.Error(), "port 7 modification failed") {
		t.Fatalf("ModifyPorts() error = %v, want port-specific error", err)
	}
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("ModifyPorts() error = %v, want ProtocolError", err)
	}
	if err := <-switchResult; err != nil {
		t.Fatal(err)
	}
}

func TestClientValidatesInputsBeforeDial(t *testing.T) {
	dialed := false
	client := newTestClient(func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("unexpected dial")
	})
	t.Cleanup(client.Close)

	if err := client.SyncBridge(context.Background(), "../br-ex", nil, nil); err == nil {
		t.Fatal("SyncBridge() accepted invalid bridge name")
	}
	if err := client.ModifyPorts(context.Background(), "br-ex", []PortModification{{
		Port: libof.P_MAX,
		Mask: PortConfigNoFlood,
	}}); err == nil {
		t.Fatal("ModifyPorts() accepted invalid port")
	}
	if err := client.ModifyPorts(context.Background(), "br-ex", []PortModification{
		{Port: 7, Mask: PortConfigNoFlood},
		{Port: 7, Mask: PortConfigNoForward},
	}); err == nil {
		t.Fatal("ModifyPorts() accepted duplicate port")
	}
	if dialed {
		t.Fatal("invalid input caused a connection attempt")
	}
}

func TestClientHonorsContextDuringHandshake(t *testing.T) {
	clientConn, switchConn := net.Pipe()
	client := newTestClient(func(context.Context, string, string) (net.Conn, error) {
		return clientConn, nil
	})
	t.Cleanup(client.Close)
	t.Cleanup(func() {
		_ = switchConn.Close()
	})
	helloRead := make(chan error, 1)
	go func() {
		_, err := readMessage(switchConn)
		helloRead <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := client.SyncBridge(ctx, "br-ex", []string{"actions=NORMAL"}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SyncBridge() error = %v, want context deadline exceeded", err)
	}
	if err := <-helloRead; err != nil {
		t.Fatal(err)
	}
}

func newTestClient(dial dialContextFunc) *Client {
	return &Client{
		runDir:            "/run/openvswitch",
		dialContext:       dial,
		reconnectInterval: time.Hour,
		echoInterval:      time.Hour,
		operationTimeout:  time.Second,
		controllers:       make(map[string]*bridgeController),
	}
}

type testPort struct {
	number     uint32
	name       string
	mac        net.HardwareAddr
	config     PortConfig
	advertised uint32
}

type bundleCommand struct {
	messageType uint8
	command     uint16
}

func testMAC(last byte) net.HardwareAddr {
	return net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, last}
}

func serveHandshake(conn net.Conn, ports []testPort) error {
	hello, err := readMessage(conn)
	if err != nil {
		return err
	}
	if hello.Version != ofpVersion || hello.Type != ofpTypeHello {
		return fmt.Errorf("unexpected hello: %#v", hello)
	}
	// OVS advertises its highest version in the Hello header. The connection
	// still negotiates 1.3 because the client sent a 1.3 Hello.
	if err := writeMessage(conn, 6, ofpTypeHello, 100, nil); err != nil {
		return err
	}

	features, err := readMessage(conn)
	if err != nil {
		return err
	}
	if features.Type != ofpTypeFeaturesRequest {
		return fmt.Errorf("message type = %d, want FeaturesRequest", features.Type)
	}
	if err := writeMessage(conn, ofpVersion, ofpTypeFeaturesReply, features.XID,
		make([]byte, ofp13FeaturesSize)); err != nil {
		return err
	}
	return servePortDescriptions(conn, ports)
}

func servePortDescriptions(conn net.Conn, ports []testPort) error {
	request, err := readMessage(conn)
	if err != nil {
		return err
	}
	if request.Type != ofpTypeMultipartRequest ||
		len(request.Payload) < 2 ||
		binary.BigEndian.Uint16(request.Payload[0:2]) != libof.MultipartType_PortDesc {
		return fmt.Errorf("unexpected port description request: %#v", request)
	}
	payload := make([]byte, 8+len(ports)*ofp13PortLength)
	binary.BigEndian.PutUint16(payload[0:2], libof.MultipartType_PortDesc)
	for index, current := range ports {
		offset := 8 + index*ofp13PortLength
		binary.BigEndian.PutUint32(payload[offset:offset+4], current.number)
		copy(payload[offset+8:offset+14], current.mac)
		copy(payload[offset+16:offset+32], current.name)
		binary.BigEndian.PutUint32(payload[offset+32:offset+36], uint32(current.config))
		binary.BigEndian.PutUint32(payload[offset+44:offset+48], current.advertised)
	}
	return writeMessage(conn, ofpVersion, ofpTypeMultipartReply, request.XID, payload)
}

func serveBundle(conn net.Conn) ([][]byte, error) {
	var embeddedMessages [][]byte
	for {
		message, err := readMessage(conn)
		if err != nil {
			return nil, err
		}
		if message.Type != ofpTypeExperimenter || len(message.Payload) < 8 {
			return nil, fmt.Errorf("unexpected bundle message: %#v", message)
		}
		subtype := binary.BigEndian.Uint32(message.Payload[4:8])
		switch subtype {
		case libof.Type_BundleAdd:
			if len(message.Payload) < 16+ofpHeaderLength {
				return nil, fmt.Errorf("short bundle add message")
			}
			embeddedMessages = append(embeddedMessages,
				append([]byte(nil), message.Payload[16:]...))
		case libof.Type_BundleCtrl:
			if len(message.Payload) < 16 {
				return nil, fmt.Errorf("short bundle control message")
			}
			controlType := binary.BigEndian.Uint16(message.Payload[12:14])
			replyPayload := append([]byte(nil), message.Payload...)
			binary.BigEndian.PutUint16(replyPayload[12:14], controlType+1)
			if err := writeMessage(conn, ofpVersion, ofpTypeExperimenter, message.XID, replyPayload); err != nil {
				return nil, err
			}
			if controlType == libof.OFPBCT_COMMIT_REQUEST {
				return embeddedMessages, nil
			}
		default:
			return nil, fmt.Errorf("unknown experimenter subtype %d", subtype)
		}
	}
}

func checkBundleCommands(messages [][]byte, expected []bundleCommand) error {
	if len(messages) != len(expected) {
		return fmt.Errorf("bundle has %d messages, want %d", len(messages), len(expected))
	}
	for index, message := range messages {
		if len(message) < ofpHeaderLength {
			return fmt.Errorf("bundle message %d is short", index)
		}
		if message[1] != expected[index].messageType {
			return fmt.Errorf("bundle message %d type = %d, want %d",
				index, message[1], expected[index].messageType)
		}
		var command uint16
		switch message[1] {
		case libof.Type_FlowMod:
			if len(message) < 26 {
				return fmt.Errorf("flow mod %d is short", index)
			}
			command = uint16(message[25])
		case libof.Type_GroupMod:
			if len(message) < 10 {
				return fmt.Errorf("group mod %d is short", index)
			}
			command = binary.BigEndian.Uint16(message[8:10])
		default:
			return fmt.Errorf("unsupported message type %d", message[1])
		}
		if command != expected[index].command {
			return fmt.Errorf("bundle message %d command = %d, want %d",
				index, command, expected[index].command)
		}
	}
	return nil
}

func TestReaderExitsWhenConnectionCloses(t *testing.T) {
	clientConn, switchConn := net.Pipe()
	results := startReader(clientConn)
	if err := switchConn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-results:
		if !errors.Is(result.err, io.EOF) && !errors.Is(result.err, net.ErrClosed) {
			t.Fatalf("reader error = %v, want closed connection", result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("reader did not report closed connection")
	}
}

func TestCloseIsSafeDuringConcurrentSubmit(_ *testing.T) {
	client := newTestClient(func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		_ = client.SyncBridge(ctx, "br-ex", []string{"actions=NORMAL"}, nil)
	}()
	cancel()
	client.Close()
	waitGroup.Wait()
}
