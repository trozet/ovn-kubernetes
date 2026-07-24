// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package openflow

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	libof "antrea.io/libOpenflow/openflow13"
)

const defaultFlowPriority = 32768

type portMap map[string]port

type parsedGroup struct {
	text    string
	message *libof.GroupMod
}

type flowProtocol struct {
	etherType uint16
	ipProto   uint8
}

func parseFlows(flows []string, ports portMap) (map[string]*libof.FlowMod, error) {
	parsed := make(map[string]*libof.FlowMod, len(flows))
	for _, flow := range flows {
		flow = canonicalExpression(flow)
		if flow == "" {
			continue
		}
		if _, found := parsed[flow]; found {
			continue
		}
		message, err := parseFlow(flow, ports)
		if err != nil {
			return nil, fmt.Errorf("failed to parse OpenFlow flow %q: %w", flow, err)
		}
		parsed[flow] = message
	}
	return parsed, nil
}

func parseGroups(groups []string, ports portMap) (map[uint32]parsedGroup, error) {
	parsed := make(map[uint32]parsedGroup, len(groups))
	for _, group := range groups {
		group = canonicalExpression(group)
		if group == "" {
			continue
		}
		message, err := parseGroup(group, ports)
		if err != nil {
			return nil, fmt.Errorf("failed to parse OpenFlow group %q: %w", group, err)
		}
		if previous, found := parsed[message.GroupId]; found {
			return nil, fmt.Errorf("group ID %d is defined by both %q and %q",
				message.GroupId, previous.text, group)
		}
		parsed[message.GroupId] = parsedGroup{text: group, message: message}
	}
	return parsed, nil
}

func canonicalExpression(expression string) string {
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(expression), "\n"))
}

func parseFlow(flow string, ports portMap) (*libof.FlowMod, error) {
	matchText, actionsText, found := strings.Cut(flow, "actions=")
	if !found {
		return nil, fmt.Errorf("missing actions")
	}
	matchText = strings.Trim(matchText, " \t,")
	actionsText = strings.TrimSpace(actionsText)

	tokens, err := flowMatchTokens(matchText)
	if err != nil {
		return nil, err
	}
	message := libof.NewFlowMod()
	message.Priority = defaultFlowPriority

	protocol, err := parseProtocol(tokens)
	if err != nil {
		return nil, err
	}
	if protocol.etherType != 0 {
		message.Match.AddField(*libof.NewEthTypeField(protocol.etherType))
	}
	if protocol.ipProto != 0 {
		message.Match.AddField(*libof.NewIpProtoField(protocol.ipProto))
	}

	for _, token := range tokens {
		name, value, hasValue := strings.Cut(token, "=")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if isProtocolToken(name) && !hasValue {
			continue
		}
		switch name {
		case "cookie":
			message.Cookie, err = parseUint64(value)
		case "table":
			var table uint64
			table, err = parseBoundedUint(value, math.MaxUint8)
			message.TableId = uint8(table)
		case "priority":
			var priority uint64
			priority, err = parseBoundedUint(value, math.MaxUint16)
			message.Priority = uint16(priority)
		case "in_port":
			var portNumber uint32
			portNumber, err = parsePort(value, ports)
			if err == nil {
				message.Match.AddField(*libof.NewInPortField(portNumber))
			}
		case "dl_src", "dl_dst":
			err = addEthernetMatch(&message.Match, name, value)
		case "dl_vlan":
			var vlan uint64
			vlan, err = parseBoundedUint(value, 4095)
			if err == nil {
				message.Match.AddField(*libof.NewVlanIdField(uint16(vlan), nil))
			}
		case "nw_src", "ip_src", "ipv6_src":
			err = addIPMatch(&message.Match, true, value)
		case "nw_dst", "ip_dst", "ipv6_dst":
			err = addIPMatch(&message.Match, false, value)
		case "tp_src", "tcp_src", "udp_src", "sctp_src":
			err = addTransportMatch(&message.Match, protocol.ipProto, true, value)
		case "tp_dst", "tcp_dst", "udp_dst", "sctp_dst":
			err = addTransportMatch(&message.Match, protocol.ipProto, false, value)
		case "arp_op":
			var operation uint64
			operation, err = parseBoundedUint(value, math.MaxUint16)
			if err == nil {
				message.Match.AddField(*libof.NewArpOperField(uint16(operation)))
			}
		case "arp_spa":
			err = addARPProtocolAddressMatch(&message.Match, true, value)
		case "arp_tpa":
			err = addARPProtocolAddressMatch(&message.Match, false, value)
		case "ct_state":
			var states *libof.CTStates
			states, err = parseCTStates(value)
			if err == nil {
				message.Match.AddField(*libof.NewCTStateMatchField(states))
			}
		case "ct_mark":
			var field *libof.MatchField
			field, err = parseUint32NXMatch("NXM_NX_CT_MARK", value)
			if err == nil {
				message.Match.AddField(*field)
			}
		case "pkt_mark":
			var field *libof.MatchField
			field, err = parseUint32NXMatch("NXM_NX_PKT_MARK", value)
			if err == nil {
				message.Match.AddField(*field)
			}
		case "reg0":
			var field *libof.MatchField
			field, err = parseUint32NXMatch("NXM_NX_REG0", value)
			if err == nil {
				message.Match.AddField(*field)
			}
		case "nw_frag":
			var field *libof.MatchField
			field, err = parseFragmentMatch(value)
			if err == nil {
				message.Match.AddField(*field)
			}
		case "icmp_type", "icmpv6_type":
			err = addICMPMatch(&message.Match, protocol.ipProto, true, value)
		case "icmp_code", "icmpv6_code":
			err = addICMPMatch(&message.Match, protocol.ipProto, false, value)
		default:
			err = fmt.Errorf("unsupported match field %q", name)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", token, err)
		}
	}

	hasVLAN := false
	for _, token := range tokens {
		name, _, _ := strings.Cut(token, "=")
		if strings.TrimSpace(name) == "dl_vlan" {
			hasVLAN = true
			break
		}
	}
	actions, err := parseActions(actionsText, ports, hasVLAN)
	if err != nil {
		return nil, err
	}
	if len(actions) > 0 {
		instruction := libof.NewInstrApplyActions()
		for _, action := range actions {
			if err := instruction.AddAction(action, false); err != nil {
				return nil, fmt.Errorf("failed to add action: %w", err)
			}
		}
		message.AddInstruction(instruction)
	}
	return message, nil
}

func flowMatchTokens(match string) ([]string, error) {
	commaTokens, err := splitTopLevel(match, ',')
	if err != nil {
		return nil, err
	}
	var tokens []string
	for _, token := range commaTokens {
		for _, field := range strings.Fields(token) {
			field = strings.TrimSpace(field)
			if field != "" {
				tokens = append(tokens, field)
			}
		}
	}
	return tokens, nil
}

func parseProtocol(tokens []string) (flowProtocol, error) {
	var result flowProtocol
	for _, token := range tokens {
		if strings.Contains(token, "=") {
			continue
		}
		var protocol flowProtocol
		switch token {
		case "ip":
			protocol.etherType = 0x0800
		case "ipv6":
			protocol.etherType = 0x86dd
		case "tcp":
			protocol = flowProtocol{etherType: 0x0800, ipProto: 6}
		case "tcp6":
			protocol = flowProtocol{etherType: 0x86dd, ipProto: 6}
		case "udp":
			protocol = flowProtocol{etherType: 0x0800, ipProto: 17}
		case "udp6":
			protocol = flowProtocol{etherType: 0x86dd, ipProto: 17}
		case "sctp":
			protocol = flowProtocol{etherType: 0x0800, ipProto: 132}
		case "sctp6":
			protocol = flowProtocol{etherType: 0x86dd, ipProto: 132}
		case "icmp":
			protocol = flowProtocol{etherType: 0x0800, ipProto: 1}
		case "icmp6":
			protocol = flowProtocol{etherType: 0x86dd, ipProto: 58}
		case "arp":
			protocol.etherType = 0x0806
		default:
			continue
		}
		if result.etherType != 0 && result.etherType != protocol.etherType {
			return flowProtocol{}, fmt.Errorf("conflicting protocol tokens")
		}
		if result.ipProto != 0 && protocol.ipProto != 0 && result.ipProto != protocol.ipProto {
			return flowProtocol{}, fmt.Errorf("conflicting IP protocol tokens")
		}
		result.etherType = protocol.etherType
		if protocol.ipProto != 0 {
			result.ipProto = protocol.ipProto
		}
	}
	return result, nil
}

func isProtocolToken(token string) bool {
	switch token {
	case "ip", "ipv6", "tcp", "tcp6", "udp", "udp6", "sctp", "sctp6", "icmp", "icmp6", "arp":
		return true
	default:
		return false
	}
}

func addEthernetMatch(match *libof.Match, name, value string) error {
	addressText, maskText, hasMask := strings.Cut(value, "/")
	address, err := net.ParseMAC(addressText)
	if err != nil {
		return fmt.Errorf("invalid MAC address: %w", err)
	}
	var mask *net.HardwareAddr
	if hasMask {
		parsedMask, err := net.ParseMAC(maskText)
		if err != nil {
			return fmt.Errorf("invalid MAC mask: %w", err)
		}
		mask = &parsedMask
	}
	if name == "dl_src" {
		match.AddField(*libof.NewEthSrcField(address, mask))
	} else {
		match.AddField(*libof.NewEthDstField(address, mask))
	}
	return nil
}

func addIPMatch(match *libof.Match, source bool, value string) error {
	ip, mask, err := parseIPAndMask(value)
	if err != nil {
		return err
	}
	if ip.To4() != nil {
		if source {
			match.AddField(*libof.NewIpv4SrcField(ip, mask))
		} else {
			match.AddField(*libof.NewIpv4DstField(ip, mask))
		}
		return nil
	}
	if source {
		match.AddField(*libof.NewIpv6SrcField(ip, mask))
	} else {
		match.AddField(*libof.NewIpv6DstField(ip, mask))
	}
	return nil
}

func parseIPAndMask(value string) (net.IP, *net.IP, error) {
	if strings.Contains(value, "/") {
		ip, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid IP network: %w", err)
		}
		mask := net.IP(network.Mask)
		return ip, &mask, nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, nil, fmt.Errorf("invalid IP address %q", value)
	}
	return ip, nil, nil
}

func addTransportMatch(match *libof.Match, protocol uint8, source bool, value string) error {
	portNumber, err := parseBoundedUint(value, math.MaxUint16)
	if err != nil {
		return err
	}
	port := uint16(portNumber)
	switch protocol {
	case 6:
		if source {
			match.AddField(*libof.NewTcpSrcField(port))
		} else {
			match.AddField(*libof.NewTcpDstField(port))
		}
	case 17:
		if source {
			match.AddField(*libof.NewUdpSrcField(port))
		} else {
			match.AddField(*libof.NewUdpDstField(port))
		}
	case 132:
		if source {
			match.AddField(*libof.NewSctpSrcField(port))
		} else {
			match.AddField(*libof.NewSctpDstField(port))
		}
	default:
		return fmt.Errorf("transport port requires tcp, udp, or sctp protocol")
	}
	return nil
}

func addARPProtocolAddressMatch(match *libof.Match, source bool, value string) error {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid ARP IPv4 address %q", value)
	}
	if source {
		match.AddField(*libof.NewArpSpaField(ip))
	} else {
		match.AddField(*libof.NewArpTpaField(ip))
	}
	return nil
}

func parseCTStates(value string) (*libof.CTStates, error) {
	states := libof.NewCTStates()
	for len(value) > 0 {
		sign := value[0]
		if sign != '+' && sign != '-' {
			return nil, fmt.Errorf("state must start with + or -")
		}
		value = value[1:]
		next := strings.IndexAny(value, "+-")
		state := value
		if next >= 0 {
			state = value[:next]
			value = value[next:]
		} else {
			value = ""
		}
		set := sign == '+'
		switch state {
		case "new":
			if set {
				states.SetNew()
			} else {
				states.UnsetNew()
			}
		case "est":
			if set {
				states.SetEst()
			} else {
				states.UnsetEst()
			}
		case "rel":
			if set {
				states.SetRel()
			} else {
				states.UnsetRel()
			}
		case "rpl":
			if set {
				states.SetRpl()
			} else {
				states.UnsetRpl()
			}
		case "inv":
			if set {
				states.SetInv()
			} else {
				states.UnsetInv()
			}
		case "trk":
			if set {
				states.SetTrk()
			} else {
				states.UnsetTrk()
			}
		case "snat":
			if set {
				states.SetSNAT()
			} else {
				states.UnsetSNAT()
			}
		case "dnat":
			if set {
				states.SetDNAT()
			} else {
				states.UnsetDNAT()
			}
		default:
			return nil, fmt.Errorf("unsupported conntrack state %q", state)
		}
	}
	return states, nil
}

func parseUint32NXMatch(fieldName, value string) (*libof.MatchField, error) {
	valueText, maskText, hasMask := strings.Cut(value, "/")
	number, err := parseBoundedUint(valueText, math.MaxUint32)
	if err != nil {
		return nil, err
	}
	field, err := libof.FindFieldHeaderByName(fieldName, hasMask)
	if err != nil {
		return nil, err
	}
	field.Value = &libof.Uint32Message{Data: uint32(number)}
	if hasMask {
		mask, err := parseBoundedUint(maskText, math.MaxUint32)
		if err != nil {
			return nil, err
		}
		field.Mask = &libof.Uint32Message{Data: uint32(mask)}
	}
	return field, nil
}

func parseFragmentMatch(value string) (*libof.MatchField, error) {
	var data, mask byte
	switch value {
	case "no":
		data, mask = 0, 1
	case "yes":
		data, mask = 1, 1
	case "first":
		data, mask = 1, 3
	case "later":
		data, mask = 3, 3
	case "not_later":
		data, mask = 0, 2
	default:
		return nil, fmt.Errorf("unsupported fragment value %q", value)
	}
	field, err := libof.FindFieldHeaderByName("NXM_NX_IP_FRAG", true)
	if err != nil {
		return nil, err
	}
	field.Value = &libof.ByteArrayField{Data: []byte{data}, Length: 1}
	field.Mask = &libof.ByteArrayField{Data: []byte{mask}, Length: 1}
	return field, nil
}

func addICMPMatch(match *libof.Match, protocol uint8, isType bool, value string) error {
	number, err := parseBoundedUint(value, math.MaxUint8)
	if err != nil {
		return err
	}
	var fieldName string
	if protocol == 1 {
		if isType {
			fieldName = "OXM_OF_ICMPV4_TYPE"
		} else {
			fieldName = "OXM_OF_ICMPV4_CODE"
		}
	} else if protocol == 58 {
		if isType {
			fieldName = "OXM_OF_ICMPV6_TYPE"
		} else {
			fieldName = "OXM_OF_ICMPV6_CODE"
		}
	} else {
		return fmt.Errorf("ICMP field requires icmp or icmp6 protocol")
	}
	field, err := libof.FindFieldHeaderByName(fieldName, false)
	if err != nil {
		return err
	}
	if isType {
		field.Value = &libof.IcmpTypeField{Type: uint8(number)}
	} else {
		field.Value = &libof.IcmpCodeField{Code: uint8(number)}
	}
	match.AddField(*field)
	return nil
}

func parseActions(actionsText string, ports portMap, hasVLAN bool) ([]libof.Action, error) {
	actionsText = strings.TrimSpace(actionsText)
	if actionsText == "" || strings.EqualFold(actionsText, "drop") {
		return nil, nil
	}
	tokens, err := splitTopLevel(actionsText, ',')
	if err != nil {
		return nil, err
	}
	actions := make([]libof.Action, 0, len(tokens))
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		var action libof.Action
		switch {
		case strings.EqualFold(token, "NORMAL"), strings.EqualFold(token, "FLOOD"),
			strings.EqualFold(token, "LOCAL"), strings.EqualFold(token, "IN_PORT"),
			strings.HasPrefix(token, "output:"):
			output := token
			if value, found := strings.CutPrefix(token, "output:"); found {
				output = value
			}
			var portNumber uint32
			portNumber, err = parsePort(output, ports)
			if err == nil {
				action = libof.NewActionOutput(portNumber)
			}
		case token == "strip_vlan", token == "pop_vlan":
			action = libof.NewActionPopVlan()
			hasVLAN = false
		case strings.HasPrefix(token, "mod_vlan_vid:"):
			var vlan uint64
			vlan, err = parseBoundedUint(strings.TrimPrefix(token, "mod_vlan_vid:"), 4095)
			if err == nil {
				if !hasVLAN {
					actions = append(actions, libof.NewActionPushVlan(0x8100))
					hasVLAN = true
				}
				action = libof.NewActionSetField(*libof.NewVlanIdField(uint16(vlan), nil))
			}
		case strings.HasPrefix(token, "set_field:"):
			action, err = parseSetFieldAction(strings.TrimPrefix(token, "set_field:"))
		case strings.HasPrefix(token, "move:"):
			action, err = parseMoveAction(strings.TrimPrefix(token, "move:"))
		case strings.HasPrefix(token, "ct(") && strings.HasSuffix(token, ")"):
			action, err = parseConntrackAction(token[3:len(token)-1], ports)
		case strings.HasPrefix(token, "check_pkt_larger("):
			action, err = parseCheckPacketLargerAction(token)
		case strings.HasPrefix(token, "resubmit(") && strings.HasSuffix(token, ")"):
			action, err = parseResubmitAction(token[9:len(token)-1], ports)
		case strings.HasPrefix(token, "group:"):
			var groupID uint64
			groupID, err = parseBoundedUint(strings.TrimPrefix(token, "group:"), libof.OFPG_MAX-1)
			if err == nil {
				action = libof.NewActionGroup(uint32(groupID))
			}
		default:
			err = fmt.Errorf("unsupported action %q", token)
		}
		if err != nil {
			return nil, err
		}
		actions = append(actions, action)
	}
	return actions, nil
}

func parseSetFieldAction(expression string) (libof.Action, error) {
	value, fieldName, found := strings.Cut(expression, "->")
	if !found {
		return nil, fmt.Errorf("invalid set_field action %q", expression)
	}
	value = strings.TrimSpace(value)
	switch strings.TrimSpace(fieldName) {
	case "eth_dst":
		address, err := net.ParseMAC(value)
		if err != nil {
			return nil, fmt.Errorf("invalid destination MAC: %w", err)
		}
		return libof.NewActionSetField(*libof.NewEthDstField(address, nil)), nil
	case "eth_src":
		address, err := net.ParseMAC(value)
		if err != nil {
			return nil, fmt.Errorf("invalid source MAC: %w", err)
		}
		return libof.NewActionSetField(*libof.NewEthSrcField(address, nil)), nil
	case "ct_mark":
		number, err := parseBoundedUint(value, math.MaxUint32)
		if err != nil {
			return nil, err
		}
		return libof.NewActionSetField(*libof.NewCTMarkMatchField(uint32(number), nil)), nil
	default:
		return nil, fmt.Errorf("unsupported set_field destination %q", fieldName)
	}
}

func parseMoveAction(expression string) (libof.Action, error) {
	sourceText, destinationText, found := strings.Cut(expression, "->")
	if !found {
		return nil, fmt.Errorf("invalid move action %q", expression)
	}
	sourceName, sourceStart, sourceBits, err := parseFieldRange(sourceText)
	if err != nil {
		return nil, err
	}
	destinationName, destinationStart, destinationBits, err := parseFieldRange(destinationText)
	if err != nil {
		return nil, err
	}
	if sourceBits != destinationBits {
		return nil, fmt.Errorf("move source and destination ranges have different sizes")
	}
	source, err := libof.FindFieldHeaderByName(sourceName, false)
	if err != nil {
		return nil, err
	}
	destination, err := libof.FindFieldHeaderByName(destinationName, false)
	if err != nil {
		return nil, err
	}
	return libof.NewNXActionRegMove(sourceBits, sourceStart, destinationStart, source, destination), nil
}

func parseCheckPacketLargerAction(expression string) (libof.Action, error) {
	lengthText, destinationText, found := strings.Cut(expression, ")->")
	if !found || !strings.HasPrefix(lengthText, "check_pkt_larger(") {
		return nil, fmt.Errorf("invalid check_pkt_larger action %q", expression)
	}
	packetLength, err := parseBoundedUint(strings.TrimPrefix(lengthText, "check_pkt_larger("), math.MaxUint16)
	if err != nil {
		return nil, err
	}
	destinationName, destinationStart, destinationBits, err := parseFieldRange(destinationText)
	if err != nil {
		return nil, err
	}
	if destinationBits != 1 {
		return nil, fmt.Errorf("check_pkt_larger destination must be one bit")
	}
	destination, err := libof.FindFieldHeaderByName(destinationName, false)
	if err != nil {
		return nil, err
	}
	return newCheckPacketLargerAction(
		uint16(packetLength),
		destinationStart,
		destination.MarshalHeader(),
	), nil
}

func parseResubmitAction(expression string, ports portMap) (libof.Action, error) {
	portText, tableText, found := strings.Cut(expression, ",")
	if !found {
		return nil, fmt.Errorf("resubmit action must specify a table")
	}
	inPort := uint16(libof.OFPP_IN_PORT)
	if portText = strings.TrimSpace(portText); portText != "" {
		portNumber, err := parsePort(portText, ports)
		if err != nil {
			return nil, err
		}
		if portNumber > math.MaxUint16 {
			return nil, fmt.Errorf("resubmit input port %d exceeds 16 bits", portNumber)
		}
		inPort = uint16(portNumber)
	}
	table, err := parseBoundedUint(strings.TrimSpace(tableText), math.MaxUint8)
	if err != nil {
		return nil, err
	}
	return libof.NewNXActionResubmitTableAction(inPort, uint8(table)), nil
}

func parseFieldRange(expression string) (string, uint16, uint16, error) {
	name, rangeText, found := strings.Cut(strings.TrimSpace(expression), "[")
	if !found || !strings.HasSuffix(rangeText, "]") {
		return "", 0, 0, fmt.Errorf("invalid field range %q", expression)
	}
	rangeText = strings.TrimSuffix(rangeText, "]")
	if name == "reg0" {
		name = "NXM_NX_REG0"
	}
	field, err := libof.FindFieldHeaderByName(name, false)
	if err != nil {
		return "", 0, 0, err
	}
	fieldBits := uint16(field.Length) * 8
	if rangeText == "" {
		return name, 0, fieldBits, nil
	}
	startText, endText, found := strings.Cut(rangeText, "..")
	if !found {
		start, err := parseBoundedUint(rangeText, uint64(fieldBits-1))
		return name, uint16(start), 1, err
	}
	start, err := parseBoundedUint(startText, uint64(fieldBits-1))
	if err != nil {
		return "", 0, 0, err
	}
	end, err := parseBoundedUint(endText, uint64(fieldBits-1))
	if err != nil {
		return "", 0, 0, err
	}
	if end < start {
		return "", 0, 0, fmt.Errorf("invalid descending field range")
	}
	return name, uint16(start), uint16(end - start + 1), nil
}

func parseConntrackAction(expression string, ports portMap) (libof.Action, error) {
	commaTokens, err := splitTopLevel(expression, ',')
	if err != nil {
		return nil, err
	}
	var tokens []string
	for _, token := range commaTokens {
		token = strings.TrimSpace(token)
		if strings.HasPrefix(token, "nat(") || strings.HasPrefix(token, "exec(") {
			tokens = append(tokens, token)
			continue
		}
		tokens = append(tokens, strings.Fields(token)...)
	}
	action := libof.NewNXActionConnTrack()
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		switch {
		case token == "commit":
			action.Commit()
		case strings.HasPrefix(token, "zone="):
			zone, err := parseBoundedUint(strings.TrimPrefix(token, "zone="), math.MaxUint16)
			if err != nil {
				return nil, err
			}
			action.ZoneImm(uint16(zone))
		case strings.HasPrefix(token, "table="):
			table, err := parseBoundedUint(strings.TrimPrefix(token, "table="), math.MaxUint8)
			if err != nil {
				return nil, err
			}
			action.Table(uint8(table))
		case token == "nat":
			action.AddAction(libof.NewNXActionCTNAT())
		case strings.HasPrefix(token, "nat(") && strings.HasSuffix(token, ")"):
			nat, err := parseNATAction(token[4 : len(token)-1])
			if err != nil {
				return nil, err
			}
			action.AddAction(nat)
		case strings.HasPrefix(token, "exec(") && strings.HasSuffix(token, ")"):
			nested, err := parseActions(token[5:len(token)-1], ports, false)
			if err != nil {
				return nil, err
			}
			action.AddAction(nested...)
		default:
			return nil, fmt.Errorf("unsupported ct argument %q", token)
		}
	}
	return action, nil
}

func parseNATAction(expression string) (*libof.NXActionCTNAT, error) {
	direction, rangeText, found := strings.Cut(expression, "=")
	if !found {
		return nil, fmt.Errorf("invalid nat range %q", expression)
	}
	action := libof.NewNXActionCTNAT()
	switch strings.TrimSpace(direction) {
	case "src":
		if err := action.SetSNAT(); err != nil {
			return nil, err
		}
	case "dst":
		if err := action.SetDNAT(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported nat direction %q", direction)
	}

	ip, portNumber, err := parseNATRange(strings.TrimSpace(rangeText))
	if err != nil {
		return nil, err
	}
	if ip.To4() != nil {
		action.SetRangeIPv4Min(ip)
	} else {
		action.SetRangeIPv6Min(ip)
	}
	if portNumber != nil {
		action.SetRangeProtoMin(portNumber)
		action.SetRangeProtoMax(portNumber)
	}
	return action, nil
}

func parseNATRange(value string) (net.IP, *uint16, error) {
	if ip := net.ParseIP(value); ip != nil {
		return ip, nil, nil
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		lastColon := strings.LastIndexByte(value, ':')
		if lastColon <= 0 {
			return nil, nil, fmt.Errorf("invalid nat address %q", value)
		}
		host, portText = value[:lastColon], value[lastColon+1:]
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return nil, nil, fmt.Errorf("invalid nat IP address %q", host)
	}
	portNumber, err := parseBoundedUint(portText, math.MaxUint16)
	if err != nil {
		return nil, nil, err
	}
	port := uint16(portNumber)
	return ip, &port, nil
}

func parseGroup(group string, ports portMap) (*libof.GroupMod, error) {
	tokens, err := splitTopLevel(group, ',')
	if err != nil {
		return nil, err
	}
	message := libof.NewGroupMod()
	var idSet, typeSet bool
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		switch {
		case strings.HasPrefix(token, "group_id="):
			groupID, err := parseBoundedUint(strings.TrimPrefix(token, "group_id="), libof.OFPG_MAX-1)
			if err != nil {
				return nil, err
			}
			message.GroupId = uint32(groupID)
			idSet = true
		case strings.HasPrefix(token, "type="):
			switch strings.TrimPrefix(token, "type=") {
			case "all":
				message.Type = libof.OFPGT_ALL
			case "select":
				message.Type = libof.OFPGT_SELECT
			case "indirect":
				message.Type = libof.OFPGT_INDIRECT
			case "ff":
				message.Type = libof.OFPGT_FF
			default:
				return nil, fmt.Errorf("unsupported group type %q", token)
			}
			typeSet = true
		case strings.HasPrefix(token, "bucket="):
			bucket, err := parseBucket(strings.TrimPrefix(token, "bucket="), ports)
			if err != nil {
				return nil, err
			}
			message.AddBucket(*bucket)
		default:
			return nil, fmt.Errorf("unsupported group field %q", token)
		}
	}
	if !idSet {
		return nil, fmt.Errorf("missing group_id")
	}
	if !typeSet {
		return nil, fmt.Errorf("missing group type")
	}
	return message, nil
}

func parseBucket(expression string, ports portMap) (*libof.Bucket, error) {
	if !strings.HasPrefix(expression, "actions=") {
		return nil, fmt.Errorf("unsupported bucket %q", expression)
	}
	actions, err := parseActions(strings.TrimPrefix(expression, "actions="), ports, false)
	if err != nil {
		return nil, err
	}
	bucket := libof.NewBucket()
	for _, action := range actions {
		bucket.AddAction(action)
	}
	return bucket, nil
}

func splitTopLevel(value string, separator rune) ([]string, error) {
	var result []string
	start := 0
	parentheses := 0
	brackets := 0
	for index, current := range value {
		switch current {
		case '(':
			parentheses++
		case ')':
			parentheses--
		case '[':
			brackets++
		case ']':
			brackets--
		}
		if parentheses < 0 || brackets < 0 {
			return nil, fmt.Errorf("unbalanced expression %q", value)
		}
		if current == separator && parentheses == 0 && brackets == 0 {
			result = append(result, value[start:index])
			start = index + 1
		}
	}
	if parentheses != 0 || brackets != 0 {
		return nil, fmt.Errorf("unbalanced expression %q", value)
	}
	result = append(result, value[start:])
	return result, nil
}

func parsePort(value string, ports portMap) (uint32, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "IN_PORT":
		return libof.P_IN_PORT, nil
	case "TABLE":
		return libof.P_TABLE, nil
	case "NORMAL":
		return libof.P_NORMAL, nil
	case "FLOOD":
		return libof.P_FLOOD, nil
	case "ALL":
		return libof.P_ALL, nil
	case "CONTROLLER":
		return libof.P_CONTROLLER, nil
	case "LOCAL":
		return libof.P_LOCAL, nil
	}
	if port, found := ports[value]; found {
		return port.number, nil
	}
	number, err := parseBoundedUint(value, libof.P_MAX-1)
	if err != nil {
		return 0, fmt.Errorf("unknown OpenFlow port %q", value)
	}
	return uint32(number), nil
}

func parseUint64(value string) (uint64, error) {
	number, err := strconv.ParseUint(strings.TrimSpace(value), 0, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid integer %q: %w", value, err)
	}
	return number, nil
}

func parseBoundedUint(value string, maximum uint64) (uint64, error) {
	number, err := parseUint64(value)
	if err != nil {
		return 0, err
	}
	if number > maximum {
		return 0, fmt.Errorf("integer %d exceeds maximum %d", number, maximum)
	}
	return number, nil
}
