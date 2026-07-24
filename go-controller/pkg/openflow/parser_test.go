// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package openflow

import (
	"strings"
	"testing"

	libof "antrea.io/libOpenflow/openflow13"
)

func TestParseGatewayFlows(t *testing.T) {
	ports := portMap{
		"7": {
			number: 7,
			name:   "patch-br-ex",
			mac:    testMAC(7),
		},
		"patch-br-ex": {
			number: 7,
			name:   "patch-br-ex",
			mac:    testMAC(7),
		},
	}
	tests := []string{
		"table=0,priority=0,actions=NORMAL",
		"cookie=0xdeff105,priority=500,in_port=7,ip,nw_src=10.128.0.0/14,nw_dst=10.96.0.0/16," +
			"actions=ct(commit,zone=64001,nat(dst=169.254.169.2),table=4)",
		"cookie=0xdeff105,priority=100,table=1,ip,ct_state=+trk+est,ct_mark=0x2," +
			"actions=strip_vlan,output:LOCAL",
		"cookie=0xdeff105,priority=100,in_port=patch-br-ex,ipv6,ipv6_src=fd00:10:244::/64," +
			"actions=ct(commit,zone=64001,nat(src=fd69::2),exec(set_field:0x2->ct_mark),table=3)",
		"cookie=0xdeff105,table=3,ip," +
			"actions=move:NXM_OF_ETH_DST[]->NXM_OF_ETH_SRC[],set_field:0a:58:0a:80:00:01->eth_dst,output:7",
		"cookie=0xdeff105,priority=110,in_port=7,ip,nw_frag=yes,actions=ct(table=0,zone=64001)",
		"cookie=0xdeff105,priority=110,in_port=7,dl_dst=ff:ff:ff:ff:ff:ff,arp,arp_op=1," +
			"arp_spa=10.0.0.2,actions=output:NORMAL",
		"cookie=0xdeff105,priority=14,table=1,icmp6,icmpv6_type=135 actions=FLOOD",
		"cookie=0xdeff105,priority=10,table=1,dl_vlan=100,ip,dl_dst=0a:58:0a:80:00:01," +
			"actions=mod_vlan_vid:200,output:7",
		"cookie=0x1,priority=110,tcp,nw_dst=192.0.2.10,tp_dst=443,actions=group:100",
		"cookie=0x2,priority=110,udp6,ipv6_dst=2001:db8::10,tp_dst=3784,actions=output:LOCAL",
		"cookie=0x3,priority=110,sctp,nw_dst=192.0.2.11,tp_dst=80,actions=drop",
		"cookie=0x4,priority=700,icmp,in_port=7,nw_dst=192.0.2.1,icmp_type=3,icmp_code=4,actions=drop",
		"cookie=0x5,priority=10,table=11,reg0=0x1,pkt_mark=0x3/0xff,actions=output:7",
		"cookie=0x6,priority=110,tcp,nw_dst=192.0.2.10,tp_dst=443," +
			"actions=ct(commit,zone=64002,nat(dst=192.0.2.20:8443),table=6)",
		"cookie=0x7,priority=110,ip,nw_dst=192.0.2.10," +
			"actions=ct(zone=64002 nat,table=7)",
		"cookie=0x8,priority=100,ip,ct_state=+trk+est,ct_mark=0x2," +
			"actions=check_pkt_larger(1400)->reg0[0],resubmit(,11)",
	}
	for _, test := range tests {
		t.Run(test, func(t *testing.T) {
			message, err := parseFlow(test, ports)
			if err != nil {
				t.Fatalf("parseFlow() error = %v", err)
			}
			data, err := message.MarshalBinary()
			if err != nil {
				t.Fatalf("FlowMod.MarshalBinary() error = %v", err)
			}
			if len(data) != int(message.Len()) {
				t.Fatalf("marshaled length = %d, want %d", len(data), message.Len())
			}
			if data[0] != ofpVersion || data[1] != libof.Type_FlowMod {
				t.Fatalf("unexpected FlowMod header %v", data[:8])
			}
		})
	}
}

func TestParseModVLANVID(t *testing.T) {
	untagged, err := parseFlow("priority=100,actions=mod_vlan_vid:100,output:7", nil)
	if err != nil {
		t.Fatal(err)
	}
	untaggedActions := untagged.Instructions[0].(*libof.InstrActions).Actions
	if len(untaggedActions) != 3 || untaggedActions[0].Header().Type != libof.ActionType_PushVlan {
		t.Fatalf("untagged mod_vlan_vid actions = %#v, want push, set, output", untaggedActions)
	}

	tagged, err := parseFlow("priority=100,dl_vlan=10,actions=mod_vlan_vid:100,output:7", nil)
	if err != nil {
		t.Fatal(err)
	}
	taggedActions := tagged.Instructions[0].(*libof.InstrActions).Actions
	if len(taggedActions) != 2 || taggedActions[0].Header().Type != libof.ActionType_SetField {
		t.Fatalf("tagged mod_vlan_vid actions = %#v, want set, output", taggedActions)
	}
}

func TestParseFlowEmitsPrerequisitesBeforeDependentFields(t *testing.T) {
	message, err := parseFlow("ip,nw_frag=yes,actions=drop", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(message.Match.Fields) != 2 {
		t.Fatalf("match field count = %d, want 2", len(message.Match.Fields))
	}
	if message.Match.Fields[0].Class != libof.OXM_CLASS_OPENFLOW_BASIC ||
		message.Match.Fields[0].Field != libof.OXM_FIELD_ETH_TYPE {
		t.Fatalf("first match field = %#v, want Ethernet type prerequisite", message.Match.Fields[0])
	}
	if message.Match.Fields[1].Class != libof.OXM_CLASS_NXM_1 ||
		message.Match.Fields[1].Field != libof.NXM_NX_IP_FRAG {
		t.Fatalf("second match field = %#v, want IP fragment field", message.Match.Fields[1])
	}
}

func TestCheckPacketLargerWireFormat(t *testing.T) {
	action, err := parseCheckPacketLargerAction("check_pkt_larger(1400)->reg0[0]")
	if err != nil {
		t.Fatal(err)
	}
	data, err := action.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != checkPacketLargerLength ||
		data[1] != 0xff ||
		data[9] != nxActionCheckPacketLarger ||
		data[10] != 0x05 ||
		data[11] != 0x78 {
		t.Fatalf("unexpected NXAST_CHECK_PKT_LARGER encoding: %x", data)
	}
}

func TestParseGatewayGroup(t *testing.T) {
	message, err := parseGroup(
		"group_id=100,type=select,"+
			"bucket=actions=ct(commit,zone=64002,nat(dst=192.0.2.20:8080),table=6),"+
			"bucket=actions=ct(commit,zone=64002,nat(dst=192.0.2.20:8081),table=6)",
		nil,
	)
	if err != nil {
		t.Fatalf("parseGroup() error = %v", err)
	}
	if message.GroupId != 100 || message.Type != libof.OFPGT_SELECT || len(message.Buckets) != 2 {
		t.Fatalf("unexpected parsed group: %#v", message)
	}
	if _, err := message.MarshalBinary(); err != nil {
		t.Fatalf("GroupMod.MarshalBinary() error = %v", err)
	}
}

func TestParserRejectsUnsupportedSyntax(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		want       string
	}{
		{
			name:       "match",
			expression: "priority=100,unsupported=1,actions=drop",
			want:       "unsupported match field",
		},
		{
			name:       "action",
			expression: "priority=100,actions=learn()",
			want:       "unsupported action",
		},
		{
			name:       "port",
			expression: "priority=100,in_port=missing,actions=drop",
			want:       "unknown OpenFlow port",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseFlow(test.expression, nil)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parseFlow() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestSplitTopLevel(t *testing.T) {
	parts, err := splitTopLevel(
		"ct(commit,zone=64001,nat(dst=[2001:db8::1]:80),exec(set_field:0x2->ct_mark)),output:7",
		',',
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 {
		t.Fatalf("splitTopLevel() = %#v, want two actions", parts)
	}
}
