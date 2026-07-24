// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

// Package openflow provides the OpenFlow controller used for OVN-Kubernetes
// gateway bridges.
package openflow

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	libof "antrea.io/libOpenflow/openflow13"
	libofutil "antrea.io/libOpenflow/util"

	"k8s.io/klog/v2"
)

// PortConfig is a bitmap of OpenFlow OFPPC_* port configuration flags.
type PortConfig uint32

const (
	PortConfigDown       PortConfig = 1 << 0
	PortConfigNoSTP      PortConfig = 1 << 1
	PortConfigNoReceive  PortConfig = 1 << 2
	PortConfigNoSTPRecv  PortConfig = 1 << 3
	PortConfigNoFlood    PortConfig = 1 << 4
	PortConfigNoForward  PortConfig = 1 << 5
	PortConfigNoPacketIn PortConfig = 1 << 6
)

const validPortConfig = PortConfigDown |
	PortConfigNoSTP |
	PortConfigNoReceive |
	PortConfigNoSTPRecv |
	PortConfigNoFlood |
	PortConfigNoForward |
	PortConfigNoPacketIn

const (
	defaultReconnectInterval = time.Second
	defaultEchoInterval      = 5 * time.Second
	defaultOperationTimeout  = 10 * time.Second
)

// PortModification describes a PortMod operation. Config bits selected by Mask
// are applied to Port; bits outside Mask are unchanged.
type PortModification struct {
	Port      uint32
	Config    PortConfig
	Mask      PortConfig
	Advertise uint32
}

// ProtocolError is an error response returned by the OpenFlow peer.
type ProtocolError struct {
	XID  uint32
	Type uint16
	Code uint16
	Data []byte
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("OpenFlow error xid=%d type=%d code=%d", e.XID, e.Type, e.Code)
}

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

type bridgeRequest struct {
	ctx           context.Context
	syncState     bool
	flows         []string
	groups        []string
	modifications []PortModification
	response      chan error
}

type desiredState struct {
	flows  []string
	groups []string
}

type compiledState struct {
	flows  map[string]*libof.FlowMod
	groups map[uint32]parsedGroup
}

type stateChange struct {
	message     libofutil.Message
	description string
}

type readResult struct {
	message ofpMessage
	err     error
}

type stateUpdateError struct {
	err error
}

func (e *stateUpdateError) Error() string {
	return e.err.Error()
}

func (e *stateUpdateError) Unwrap() error {
	return e.err
}

type bridgeController struct {
	client     *Client
	bridge     string
	socketPath string
	requests   chan bridgeRequest
	stop       chan struct{}
	done       chan struct{}
	stopOnce   sync.Once
}

// Client maintains one OpenFlow 1.3 controller connection per managed bridge.
// The most recently applied flow and group state is replayed after reconnecting
// to ovs-vswitchd.
type Client struct {
	runDir      string
	dialContext dialContextFunc

	reconnectInterval time.Duration
	echoInterval      time.Duration
	operationTimeout  time.Duration

	xid      atomic.Uint32
	bundleID atomic.Uint32

	mutex       sync.Mutex
	controllers map[string]*bridgeController
	closed      bool
}

// NewClient creates a controller that connects to bridge management sockets in
// runDir. Connections are established lazily.
func NewClient(runDir string) *Client {
	dialer := &net.Dialer{}
	return &Client{
		runDir:            filepath.Clean(runDir),
		dialContext:       dialer.DialContext,
		reconnectInterval: defaultReconnectInterval,
		echoInterval:      defaultEchoInterval,
		operationTimeout:  defaultOperationTimeout,
		controllers:       make(map[string]*bridgeController),
	}
}

// SyncBridge makes flows and groups the complete desired OpenFlow state for a
// bridge. Subsequent calls send only the differences. A reconnect causes the
// complete latest state to be installed atomically before incremental updates
// resume.
func (c *Client) SyncBridge(ctx context.Context, bridge string, flows, groups []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	controller, err := c.controller(bridge)
	if err != nil {
		return err
	}
	request := bridgeRequest{
		ctx:       ctx,
		syncState: true,
		flows:     slices.Clone(flows),
		groups:    slices.Clone(groups),
		response:  make(chan error, 1),
	}
	return controller.submit(request)
}

// ModifyPorts applies port modifications over the bridge's existing
// controller connection and waits for a barrier reply. Satisfied modifications
// are omitted.
func (c *Client) ModifyPorts(ctx context.Context, bridge string, modifications []PortModification) error {
	if len(modifications) == 0 {
		return nil
	}
	if err := validateModifications(modifications); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	controller, err := c.controller(bridge)
	if err != nil {
		return err
	}
	request := bridgeRequest{
		ctx:           ctx,
		modifications: slices.Clone(modifications),
		response:      make(chan error, 1),
	}
	return controller.submit(request)
}

// Close stops all bridge controllers and closes their connections.
func (c *Client) Close() {
	c.mutex.Lock()
	if c.closed {
		c.mutex.Unlock()
		return
	}
	c.closed = true
	controllers := slices.Collect(maps.Values(c.controllers))
	c.mutex.Unlock()

	for _, controller := range controllers {
		controller.stopController()
	}
	for _, controller := range controllers {
		<-controller.done
	}
}

func (c *Client) controller(bridge string) (*bridgeController, error) {
	if err := validateBridgeName(bridge); err != nil {
		return nil, err
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.closed {
		return nil, fmt.Errorf("OpenFlow client is closed")
	}
	if controller, found := c.controllers[bridge]; found {
		return controller, nil
	}
	controller := &bridgeController{
		client:     c,
		bridge:     bridge,
		socketPath: filepath.Join(c.runDir, bridge+".mgmt"),
		requests:   make(chan bridgeRequest),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	c.controllers[bridge] = controller
	go controller.run()
	return controller, nil
}

func (c *Client) nextXID() uint32 {
	xid := c.xid.Add(1)
	if xid == 0 {
		xid = c.xid.Add(1)
	}
	return xid
}

func (c *Client) nextBundleID() uint32 {
	id := c.bundleID.Add(1)
	if id == 0 {
		id = c.bundleID.Add(1)
	}
	return id
}

func (b *bridgeController) submit(request bridgeRequest) error {
	select {
	case b.requests <- request:
	case <-request.ctx.Done():
		return request.ctx.Err()
	case <-b.stop:
		return fmt.Errorf("OpenFlow controller for bridge %s is stopped", b.bridge)
	}
	select {
	case err := <-request.response:
		return err
	case <-request.ctx.Done():
		return request.ctx.Err()
	case <-b.stop:
		return fmt.Errorf("OpenFlow controller for bridge %s is stopped", b.bridge)
	}
}

func (b *bridgeController) stopController() {
	b.stopOnce.Do(func() {
		close(b.stop)
	})
}

func (b *bridgeController) run() {
	defer close(b.done)

	var (
		conn      net.Conn
		incoming  <-chan readResult
		ports     portMap
		desired   *desiredState
		installed *compiledState
		reconnect <-chan time.Time
	)
	echoTicker := time.NewTicker(b.client.echoInterval)
	defer echoTicker.Stop()

	disconnect := func() {
		if conn != nil {
			_ = conn.Close()
		}
		conn = nil
		incoming = nil
		ports = nil
		installed = nil
		reconnect = time.After(b.client.reconnectInterval)
	}
	connect := func(ctx context.Context) error {
		newConn, newIncoming, newPorts, err := b.connect(ctx)
		if err != nil {
			return err
		}
		conn = newConn
		incoming = newIncoming
		ports = newPorts
		installed = nil
		reconnect = nil
		klog.V(4).Infof("Connected OpenFlow controller to bridge %s", b.bridge)
		return nil
	}
	replay := func(ctx context.Context) error {
		if desired == nil {
			return nil
		}
		compiled, err := compileState(*desired, ports)
		if err != nil {
			return err
		}
		if err := b.applyState(ctx, conn, incoming, installed, compiled); err != nil {
			return err
		}
		installed = compiled
		return nil
	}

	for {
		select {
		case request := <-b.requests:
			if request.syncState {
				desired = &desiredState{
					flows:  request.flows,
					groups: request.groups,
				}
			}
			if conn == nil {
				if err := connect(request.ctx); err != nil {
					request.response <- fmt.Errorf("failed to connect to OpenFlow management socket %s: %w",
						b.socketPath, err)
					reconnect = time.After(b.client.reconnectInterval)
					continue
				}
				if err := replay(request.ctx); err != nil {
					request.response <- fmt.Errorf("failed to replay OpenFlow state on bridge %s: %w", b.bridge, err)
					if shouldReconnect(err) {
						disconnect()
					}
					continue
				}
			}

			var err error
			if request.syncState {
				compiled, compileErr := compileState(*desired, ports)
				if compileErr != nil {
					err = compileErr
				} else {
					err = b.applyState(request.ctx, conn, incoming, installed, compiled)
					if err == nil {
						installed = compiled
					}
				}
			} else {
				ports, err = b.refreshPorts(request.ctx, conn, incoming, ports)
				if err == nil {
					err = b.applyPortModifications(request.ctx, conn, incoming, ports, request.modifications)
				}
			}
			if err != nil {
				err = fmt.Errorf("OpenFlow update failed on bridge %s: %w", b.bridge, err)
				if shouldReconnect(err) {
					disconnect()
				}
			}
			request.response <- err

		case result := <-incoming:
			if result.err != nil {
				klog.Warningf("OpenFlow controller disconnected from bridge %s: %v", b.bridge, result.err)
				disconnect()
				continue
			}
			if err := b.handleUnsolicited(conn, ports, result.message); err != nil {
				klog.Warningf("OpenFlow controller error for bridge %s: %v", b.bridge, err)
			}

		case <-reconnect:
			ctx, cancel := context.WithTimeout(context.Background(), b.client.operationTimeout)
			err := connect(ctx)
			if err == nil {
				err = replay(ctx)
			}
			cancel()
			if err != nil {
				klog.Warningf("Failed to reconnect OpenFlow controller to bridge %s: %v", b.bridge, err)
				disconnect()
			}

		case <-echoTicker.C:
			if conn == nil {
				continue
			}
			if err := writeMessage(conn, ofpVersion, ofpTypeEchoRequest, b.client.nextXID(), nil); err != nil {
				klog.Warningf("Failed to send OpenFlow echo to bridge %s: %v", b.bridge, err)
				disconnect()
			}

		case <-b.stop:
			if conn != nil {
				_ = conn.Close()
			}
			return
		}
	}
}

func (b *bridgeController) connect(ctx context.Context) (net.Conn, <-chan readResult, portMap, error) {
	conn, err := b.client.dialContext(ctx, "unix", b.socketPath)
	if err != nil {
		return nil, nil, nil, err
	}
	incoming := startReader(conn)
	stopDeadline, err := watchContext(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	defer stopDeadline()

	if err := writeMessage(conn, ofpVersion, ofpTypeHello, b.client.nextXID(), nil); err != nil {
		_ = conn.Close()
		return nil, nil, nil, fmt.Errorf("failed to send hello: %w", err)
	}
	hello, err := b.waitForMessage(ctx, conn, incoming, nil, func(message ofpMessage) bool {
		return message.Type == ofpTypeHello
	})
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, fmt.Errorf("failed to negotiate OpenFlow 1.3: %w", err)
	}
	// With no version-bitmap hello element, OpenFlow negotiates the lower of
	// the two header versions. OVS advertises its highest supported version in
	// its Hello header, so a value newer than 1.3 is expected here.
	if hello.Version < ofpVersion {
		_ = conn.Close()
		return nil, nil, nil, fmt.Errorf("peer only supports OpenFlow version %d, but 1.3 is required", hello.Version)
	}

	featuresXID := b.client.nextXID()
	if err := writeMessage(conn, ofpVersion, ofpTypeFeaturesRequest, featuresXID, nil); err != nil {
		_ = conn.Close()
		return nil, nil, nil, fmt.Errorf("failed to send features request: %w", err)
	}
	features, err := b.waitForMessage(ctx, conn, incoming, nil, func(message ofpMessage) bool {
		return message.Type == ofpTypeFeaturesReply && message.XID == featuresXID
	})
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, fmt.Errorf("failed to receive features reply: %w", err)
	}
	if len(features.Payload) < ofp13FeaturesSize {
		_ = conn.Close()
		return nil, nil, nil, fmt.Errorf("features reply is only %d bytes", len(features.Payload))
	}

	ports, err := b.queryPorts(ctx, conn, incoming, nil)
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, incoming, ports, nil
}

func startReader(conn net.Conn) <-chan readResult {
	results := make(chan readResult, 16)
	go func() {
		for {
			message, err := readMessage(conn)
			results <- readResult{message: message, err: err}
			if err != nil {
				return
			}
		}
	}()
	return results
}

func (b *bridgeController) refreshPorts(
	ctx context.Context,
	conn net.Conn,
	incoming <-chan readResult,
	current portMap,
) (portMap, error) {
	return b.queryPorts(ctx, conn, incoming, current)
}

func (b *bridgeController) queryPorts(
	ctx context.Context,
	conn net.Conn,
	incoming <-chan readResult,
	current portMap,
) (portMap, error) {
	xid := b.client.nextXID()
	if err := writeAll(conn, marshalPortDescriptionRequest(xid)); err != nil {
		return nil, fmt.Errorf("failed to request port descriptions: %w", err)
	}
	ports := make(portMap)
	for {
		message, err := b.waitForMessage(ctx, conn, incoming, current, func(message ofpMessage) bool {
			return message.Type == ofpTypeMultipartReply && message.XID == xid
		})
		if err != nil {
			return nil, fmt.Errorf("failed to receive port descriptions: %w", err)
		}
		replyPorts, more, err := parsePortDescriptionReply(message)
		if err != nil {
			return nil, err
		}
		for key, currentPort := range replyPorts {
			if _, found := ports[key]; found {
				return nil, fmt.Errorf("port description reply contains duplicate port %q", key)
			}
			ports[key] = currentPort
		}
		if !more {
			return ports, nil
		}
	}
}

func compileState(desired desiredState, ports portMap) (*compiledState, error) {
	flows, err := parseFlows(desired.flows, ports)
	if err != nil {
		return nil, err
	}
	groups, err := parseGroups(desired.groups, ports)
	if err != nil {
		return nil, err
	}
	return &compiledState{flows: flows, groups: groups}, nil
}

func (b *bridgeController) applyState(
	ctx context.Context,
	conn net.Conn,
	incoming <-chan readResult,
	installed, desired *compiledState,
) error {
	messages := stateChanges(installed, desired)
	if len(messages) == 0 {
		return nil
	}
	stopDeadline, err := watchContext(ctx, conn)
	if err != nil {
		return err
	}
	defer stopDeadline()
	if err := b.sendBundle(ctx, conn, incoming, messages); err != nil {
		// A failed bundle can remain open on the switch. Reconnect before
		// retrying so the next transaction starts from a known state.
		return &stateUpdateError{err: err}
	}
	return nil
}

func stateChanges(installed, desired *compiledState) []stateChange {
	if installed == nil {
		messages := []stateChange{
			{message: deleteAllFlows(), description: "delete all flows"},
			{message: deleteAllGroups(), description: "delete all groups"},
		}
		for _, groupID := range sortedGroupIDs(desired.groups) {
			group := cloneGroup(desired.groups[groupID].message, libof.OFPGC_ADD)
			messages = append(messages, stateChange{
				message:     group,
				description: desired.groups[groupID].text,
			})
		}
		for _, flowText := range sortedFlowTexts(desired.flows) {
			messages = append(messages, stateChange{
				message:     cloneFlow(desired.flows[flowText], libof.FC_ADD),
				description: flowText,
			})
		}
		return messages
	}

	var messages []stateChange
	for _, flowText := range sortedFlowTexts(installed.flows) {
		if _, found := desired.flows[flowText]; !found {
			messages = append(messages, stateChange{
				message:     cloneFlow(installed.flows[flowText], libof.FC_DELETE_STRICT),
				description: "delete " + flowText,
			})
		}
	}
	for _, groupID := range sortedGroupIDs(desired.groups) {
		desiredGroup := desired.groups[groupID]
		installedGroup, found := installed.groups[groupID]
		if !found {
			messages = append(messages, stateChange{
				message:     cloneGroup(desiredGroup.message, libof.OFPGC_ADD),
				description: desiredGroup.text,
			})
		} else if installedGroup.text != desiredGroup.text {
			messages = append(messages, stateChange{
				message:     cloneGroup(desiredGroup.message, libof.OFPGC_MODIFY),
				description: desiredGroup.text,
			})
		}
	}
	for _, flowText := range sortedFlowTexts(desired.flows) {
		if _, found := installed.flows[flowText]; !found {
			messages = append(messages, stateChange{
				message:     cloneFlow(desired.flows[flowText], libof.FC_ADD),
				description: flowText,
			})
		}
	}
	for _, groupID := range sortedGroupIDs(installed.groups) {
		if _, found := desired.groups[groupID]; !found {
			group := cloneGroup(installed.groups[groupID].message, libof.OFPGC_DELETE)
			messages = append(messages, stateChange{
				message:     group,
				description: "delete " + installed.groups[groupID].text,
			})
		}
	}
	return messages
}

func deleteAllFlows() *libof.FlowMod {
	message := libof.NewFlowMod()
	message.TableId = libof.OFPTT_ALL
	message.Command = libof.FC_DELETE
	message.OutPort = libof.P_ANY
	message.OutGroup = libof.OFPG_ANY
	message.Priority = 0
	return message
}

func deleteAllGroups() *libof.GroupMod {
	message := libof.NewGroupMod()
	message.Command = libof.OFPGC_DELETE
	message.GroupId = libof.OFPG_ALL
	return message
}

func cloneFlow(original *libof.FlowMod, command uint8) *libof.FlowMod {
	cloned := *original
	cloned.Command = command
	if command == libof.FC_DELETE || command == libof.FC_DELETE_STRICT {
		cloned.CookieMask = ^uint64(0)
		cloned.Instructions = nil
	}
	return &cloned
}

func cloneGroup(original *libof.GroupMod, command uint16) *libof.GroupMod {
	cloned := *original
	cloned.Command = command
	if command == libof.OFPGC_DELETE {
		cloned.Buckets = nil
	}
	return &cloned
}

func sortedFlowTexts(flows map[string]*libof.FlowMod) []string {
	return slices.Sorted(maps.Keys(flows))
}

func sortedGroupIDs[T any](groups map[uint32]T) []uint32 {
	return slices.Sorted(maps.Keys(groups))
}

func (b *bridgeController) sendBundle(
	ctx context.Context,
	conn net.Conn,
	incoming <-chan readResult,
	messages []stateChange,
) error {
	bundleID := b.client.nextBundleID()
	flags := uint16(libof.OFPBCT_ATOMIC | libof.OFPBCT_ORDERED)
	if err := b.sendBundleControl(ctx, conn, incoming, bundleID, libof.OFPBCT_OPEN_REQUEST, flags); err != nil {
		return fmt.Errorf("failed to open bundle: %w", err)
	}
	descriptionByXID := make(map[uint32]string, len(messages))
	for index, change := range messages {
		xid := b.client.nextXID()
		descriptionByXID[xid] = change.description
		setMessageXID(change.message, xid)
		bundleAdd := libof.NewBundleAdd(&libof.BundleAdd{
			BundleID: bundleID,
			Flags:    flags,
			Message:  change.message,
		})
		bundleAdd.Header.Xid = xid
		if err := writeOpenFlowMessage(conn, bundleAdd); err != nil {
			return fmt.Errorf("failed to add message %d to bundle: %w", index, err)
		}
	}
	if err := b.sendBundleControl(ctx, conn, incoming, bundleID, libof.OFPBCT_CLOSE_REQUEST, flags); err != nil {
		var protocolErr *ProtocolError
		if errors.As(err, &protocolErr) {
			if description, found := descriptionByXID[protocolErr.XID]; found {
				return fmt.Errorf("bundle message %q was rejected: %w", description, err)
			}
		}
		return fmt.Errorf("failed to close bundle: %w", err)
	}
	if err := b.sendBundleControl(ctx, conn, incoming, bundleID, libof.OFPBCT_COMMIT_REQUEST, flags); err != nil {
		return fmt.Errorf("failed to commit bundle: %w", err)
	}
	return nil
}

func setMessageXID(message libofutil.Message, xid uint32) {
	switch typed := message.(type) {
	case *libof.FlowMod:
		typed.Xid = xid
	case *libof.GroupMod:
		typed.Xid = xid
	case *libof.PortMod:
		typed.Xid = xid
	}
}

func (b *bridgeController) sendBundleControl(
	ctx context.Context,
	conn net.Conn,
	incoming <-chan readResult,
	bundleID uint32,
	requestType, flags uint16,
) error {
	request := libof.NewBundleControl(&libof.BundleControl{
		BundleID: bundleID,
		Type:     requestType,
		Flags:    flags,
	})
	request.Header.Xid = b.client.nextXID()
	if err := writeOpenFlowMessage(conn, request); err != nil {
		return err
	}
	expectedType := requestType + 1
	_, err := b.waitForMessage(ctx, conn, incoming, nil, func(message ofpMessage) bool {
		if message.Type != ofpTypeExperimenter || message.XID != request.Header.Xid || len(message.Payload) < 16 {
			return false
		}
		experimenter := binary.BigEndian.Uint32(message.Payload[0:4])
		subtype := binary.BigEndian.Uint32(message.Payload[4:8])
		replyBundleID := binary.BigEndian.Uint32(message.Payload[8:12])
		replyType := binary.BigEndian.Uint16(message.Payload[12:14])
		return experimenter == libof.ONF_EXPERIMENTER_ID &&
			subtype == libof.Type_BundleCtrl &&
			replyBundleID == bundleID &&
			replyType == expectedType
	})
	return err
}

func (b *bridgeController) applyPortModifications(
	ctx context.Context,
	conn net.Conn,
	incoming <-chan readResult,
	ports portMap,
	modifications []PortModification,
) error {
	stopDeadline, err := watchContext(ctx, conn)
	if err != nil {
		return err
	}
	defer stopDeadline()

	portByXID := make(map[uint32]uint32, len(modifications))
	for _, modification := range modifications {
		current, found := ports[strconvFormatUint32(modification.Port)]
		if !found {
			return fmt.Errorf("OpenFlow port %d was not reported by bridge %s", modification.Port, b.bridge)
		}
		configMatches := current.config&modification.Mask == modification.Config&modification.Mask
		advertiseMatches := modification.Advertise == 0 || current.advertised == modification.Advertise
		if configMatches && advertiseMatches {
			continue
		}
		xid := b.client.nextXID()
		portByXID[xid] = modification.Port
		if err := writeAll(conn, marshalPortModification(xid, current, modification)); err != nil {
			return fmt.Errorf("failed to send port %d modification: %w", modification.Port, err)
		}
	}
	if len(portByXID) == 0 {
		return nil
	}
	barrierXID := b.client.nextXID()
	if err := writeMessage(conn, ofpVersion, ofpTypeBarrierRequest, barrierXID, nil); err != nil {
		return fmt.Errorf("failed to send barrier: %w", err)
	}

	var responseErrors []error
	for {
		message, err := b.waitForMessage(ctx, conn, incoming, ports, func(message ofpMessage) bool {
			return message.Type == ofpTypeBarrierReply && message.XID == barrierXID
		})
		if err != nil {
			var protocolErr *ProtocolError
			if errors.As(err, &protocolErr) {
				if portNumber, found := portByXID[protocolErr.XID]; found {
					responseErrors = append(responseErrors,
						fmt.Errorf("port %d modification failed: %w", portNumber, protocolErr))
					continue
				}
				responseErrors = append(responseErrors, protocolErr)
				continue
			}
			return errors.Join(append(responseErrors, err)...)
		}
		if message.Type == ofpTypeBarrierReply {
			return errors.Join(responseErrors...)
		}
	}
}

func (b *bridgeController) waitForMessage(
	ctx context.Context,
	conn net.Conn,
	incoming <-chan readResult,
	ports portMap,
	matches func(ofpMessage) bool,
) (ofpMessage, error) {
	for {
		select {
		case result := <-incoming:
			if result.err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return ofpMessage{}, ctxErr
				}
				var netErr net.Error
				if errors.As(result.err, &netErr) && netErr.Timeout() {
					if deadline, found := ctx.Deadline(); found && !time.Now().Before(deadline) {
						return ofpMessage{}, context.DeadlineExceeded
					}
				}
				return ofpMessage{}, result.err
			}
			message := result.message
			if message.Type == ofpTypeError {
				return ofpMessage{}, parseProtocolError(message)
			}
			if matches(message) {
				return message, nil
			}
			if err := b.handleUnsolicited(conn, ports, message); err != nil {
				return ofpMessage{}, err
			}
		case <-ctx.Done():
			return ofpMessage{}, ctx.Err()
		case <-b.stop:
			return ofpMessage{}, fmt.Errorf("OpenFlow controller is stopped")
		}
	}
}

func (b *bridgeController) handleUnsolicited(conn net.Conn, ports portMap, message ofpMessage) error {
	switch message.Type {
	case ofpTypeEchoRequest:
		return replyToEcho(conn, message)
	case ofpTypeEchoReply:
		return nil
	case ofpTypePortStatus:
		current, deleted, err := parsePortStatus(message)
		if err != nil {
			return err
		}
		if ports == nil {
			return nil
		}
		delete(ports, strconvFormatUint32(current.number))
		if current.name != "" {
			delete(ports, current.name)
		}
		if !deleted {
			ports[strconvFormatUint32(current.number)] = current
			if current.name != "" {
				ports[current.name] = current
			}
		}
	case ofpTypeError:
		return parseProtocolError(message)
	}
	return nil
}

func validateBridgeName(bridge string) error {
	if bridge == "" || bridge == "." || bridge == ".." || filepath.Base(bridge) != bridge {
		return fmt.Errorf("invalid OVS bridge name %q", bridge)
	}
	return nil
}

func validateModifications(modifications []PortModification) error {
	seen := make(map[uint32]struct{}, len(modifications))
	for _, modification := range modifications {
		if modification.Port == 0 || modification.Port >= libof.P_MAX {
			return fmt.Errorf("port %d is not a valid OpenFlow physical port", modification.Port)
		}
		if modification.Mask&^validPortConfig != 0 {
			return fmt.Errorf("port %d has unsupported OpenFlow configuration mask %#x",
				modification.Port, modification.Mask)
		}
		if _, found := seen[modification.Port]; found {
			return fmt.Errorf("port %d has more than one modification", modification.Port)
		}
		seen[modification.Port] = struct{}{}
	}
	return nil
}

func watchContext(ctx context.Context, conn net.Conn) (func(), error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("failed to set OpenFlow connection deadline: %w", err)
		}
	}
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	return func() {
		stop()
		_ = conn.SetDeadline(time.Time{})
	}, nil
}

func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed)
}

func shouldReconnect(err error) bool {
	var updateErr *stateUpdateError
	return errors.As(err, &updateErr) || isConnectionError(err)
}
