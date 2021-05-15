package node

import (
	"github.com/Kmotiko/gofc"
	"github.com/Kmotiko/gofc/ofprotocol/ofp13"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"k8s.io/klog/v2"
)

type SampleController struct {
	// add any parameter used in controller.
}

func NewSampleController() *SampleController {
	ofc := new(SampleController)
	return ofc
}

func (c *SampleController) HandlePacketIn(msg *ofp13.OfpPacketIn, dp *gofc.Datapath) {
	var outPort uint32
	for _, m := range msg.Match.OxmFields {
		if m.OxmField() == ofp13.OFPXMT_OFB_IN_PORT {
			outPort = m.(*ofp13.OxmInPort).Value
			klog.Infof("TROZET: PKT IN with inport detected: %d", outPort)
			break
		}
		klog.Warningf("TROZET: unknown oxm field: %d", m.OxmField())
	}

	if outPort == 0 {
		klog.Error("TROZET: unable to handle packet in, outport is 0")
		return
	}

	packet := gopacket.NewPacket(msg.Data, layers.LayerTypeEthernet, gopacket.Default)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		klog.Errorf("TROZET: unable to parse ethernet: %v", packet)
	}

	ethHeader := ethLayer.(*layers.Ethernet)

	// TODO handle ipv6
	// ipLayer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		klog.Errorf("TROZET: unknown next layer type: %v", packet.NetworkLayer())
	}

	ipHeader := ipLayer.(*layers.IPv4)

	data := icmp.Message{
		Type: ipv4.ICMPTypeDestinationUnreachable, Code: 4,
		Body: &icmp.DstUnreach{
			Data: []byte("HELLO-R-U-THERE"),
		},
	}

	dataBytes, err := data.Marshal(nil)
	if err != nil {
		klog.Errorf("Error while marshaling data: %v", data)
		return
	}

	//blah := &layers.ICMPv4{
	//	TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable,layers.ICMPv4CodeFragmentationNeeded),
	//}

	ipData := &layers.IPv4{
		SrcIP:    ipHeader.DstIP,
		DstIP:    ipHeader.SrcIP,
		Protocol: 1,
		TTL:      64,
		Length:   uint16(len(dataBytes)),
	}

	tmpBuf := gopacket.NewSerializeBuffer()
	if err := ipData.SerializeTo(tmpBuf, opts); err != nil {
		klog.Errorf("TROZET: error during serializing ipdata: %v", err)
		return
	}
	if err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       ethHeader.DstMAC,
			DstMAC:       ethHeader.SrcMAC,
			EthernetType: ethHeader.EthernetType,
			Length:       uint16(len(tmpBuf.Bytes()) + len(dataBytes)),
		},
		ipData,
		gopacket.Payload(dataBytes)); err != nil {
		klog.Errorf("Unable to serialized full packet out: %v", err)
	}

	if len(msg.Data) > 1418 {
		packetOut := ofp13.NewOfpPacketOut(msg.BufferId, ofp13.OFPP_CONTROLLER,
			[]ofp13.OfpAction{ofp13.NewOfpActionOutput(outPort, 1500)},
			buf.Bytes())
		dp.Send(packetOut)
	}
}

func (c *SampleController) Start() {
	klog.Infof("TROZET: STARTING OF CONTROLLER")
	gofc.GetAppManager().RegistApplication(c)
	go gofc.ServerLoop(gofc.DEFAULT_PORT)
}
