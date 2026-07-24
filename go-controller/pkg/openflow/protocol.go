// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package openflow

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"

	libof "antrea.io/libOpenflow/openflow13"
	libofutil "antrea.io/libOpenflow/util"
)

const (
	ofpVersion        = libof.VERSION
	ofpHeaderLength   = 8
	ofp13PortLength   = 64
	ofp13FeaturesSize = 24

	ofpTypeHello            = libof.Type_Hello
	ofpTypeError            = libof.Type_Error
	ofpTypeEchoRequest      = libof.Type_EchoRequest
	ofpTypeEchoReply        = libof.Type_EchoReply
	ofpTypeFeaturesRequest  = libof.Type_FeaturesRequest
	ofpTypeFeaturesReply    = libof.Type_FeaturesReply
	ofpTypeExperimenter     = libof.Type_Experimenter
	ofpTypePortStatus       = libof.Type_PortStatus
	ofpTypePortMod          = libof.Type_PortMod
	ofpTypeMultipartRequest = libof.Type_MultiPartRequest
	ofpTypeMultipartReply   = libof.Type_MultiPartReply
	ofpTypeBarrierRequest   = libof.Type_BarrierRequest
	ofpTypeBarrierReply     = libof.Type_BarrierReply
)

type ofpMessage struct {
	Version uint8
	Type    uint8
	XID     uint32
	Payload []byte
}

type port struct {
	number     uint32
	name       string
	mac        net.HardwareAddr
	config     PortConfig
	advertised uint32
}

func marshalMessage(version, messageType uint8, xid uint32, payload []byte) []byte {
	message := make([]byte, ofpHeaderLength+len(payload))
	message[0] = version
	message[1] = messageType
	binary.BigEndian.PutUint16(message[2:4], uint16(len(message)))
	binary.BigEndian.PutUint32(message[4:8], xid)
	copy(message[ofpHeaderLength:], payload)
	return message
}

func marshalOpenFlowMessage(message libofutil.Message) ([]byte, error) {
	data, err := message.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(data) < ofpHeaderLength {
		return nil, fmt.Errorf("marshaled OpenFlow message is only %d bytes", len(data))
	}
	if int(binary.BigEndian.Uint16(data[2:4])) != len(data) {
		return nil, fmt.Errorf("marshaled OpenFlow message length is %d, header says %d",
			len(data), binary.BigEndian.Uint16(data[2:4]))
	}
	return data, nil
}

func writeMessage(writer io.Writer, version, messageType uint8, xid uint32, payload []byte) error {
	return writeAll(writer, marshalMessage(version, messageType, xid, payload))
}

func writeOpenFlowMessage(writer io.Writer, message libofutil.Message) error {
	data, err := marshalOpenFlowMessage(message)
	if err != nil {
		return err
	}
	return writeAll(writer, data)
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[written:]
	}
	return nil
}

func readMessage(reader io.Reader) (ofpMessage, error) {
	header := make([]byte, ofpHeaderLength)
	if _, err := io.ReadFull(reader, header); err != nil {
		return ofpMessage{}, err
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < ofpHeaderLength {
		return ofpMessage{}, fmt.Errorf("invalid OpenFlow message length %d", length)
	}
	payload := make([]byte, length-ofpHeaderLength)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return ofpMessage{}, err
	}
	return ofpMessage{
		Version: header[0],
		Type:    header[1],
		XID:     binary.BigEndian.Uint32(header[4:8]),
		Payload: payload,
	}, nil
}

func parseProtocolError(message ofpMessage) *ProtocolError {
	protocolErr := &ProtocolError{
		XID:  message.XID,
		Data: append([]byte(nil), message.Payload...),
	}
	if len(message.Payload) >= 4 {
		protocolErr.Type = binary.BigEndian.Uint16(message.Payload[0:2])
		protocolErr.Code = binary.BigEndian.Uint16(message.Payload[2:4])
		protocolErr.Data = append([]byte(nil), message.Payload[4:]...)
	}
	return protocolErr
}

func replyToEcho(writer io.Writer, request ofpMessage) error {
	if err := writeMessage(writer, ofpVersion, ofpTypeEchoReply, request.XID, request.Payload); err != nil {
		return fmt.Errorf("failed to send echo reply: %w", err)
	}
	return nil
}

func parsePortDescriptionReply(message ofpMessage) (portMap, bool, error) {
	if message.Version != ofpVersion {
		return nil, false, fmt.Errorf("port description reply uses OpenFlow version %d", message.Version)
	}
	if len(message.Payload) < 8 {
		return nil, false, fmt.Errorf("port description reply is only %d bytes", len(message.Payload))
	}
	multipartType := binary.BigEndian.Uint16(message.Payload[0:2])
	if multipartType != libof.MultipartType_PortDesc {
		return nil, false, fmt.Errorf("multipart reply type is %d, expected port description", multipartType)
	}
	more := binary.BigEndian.Uint16(message.Payload[2:4])&libof.OFPMPF_REPLY_MORE != 0
	portData := message.Payload[8:]
	if len(portData)%ofp13PortLength != 0 {
		return nil, false, fmt.Errorf("port description reply has %d trailing port bytes", len(portData))
	}

	ports := make(portMap, len(portData)/ofp13PortLength*2)
	for len(portData) > 0 {
		name := strings.TrimRight(string(portData[16:32]), "\x00")
		current := port{
			number:     binary.BigEndian.Uint32(portData[0:4]),
			name:       name,
			mac:        append(net.HardwareAddr(nil), portData[8:14]...),
			config:     PortConfig(binary.BigEndian.Uint32(portData[32:36])),
			advertised: binary.BigEndian.Uint32(portData[44:48]),
		}
		number := strconvFormatUint32(current.number)
		if _, found := ports[number]; found {
			return nil, false, fmt.Errorf("port description reply contains duplicate port %d", current.number)
		}
		ports[number] = current
		if name != "" {
			if _, found := ports[name]; found {
				return nil, false, fmt.Errorf("port description reply contains duplicate port name %q", name)
			}
			ports[name] = current
		}
		portData = portData[ofp13PortLength:]
	}
	return ports, more, nil
}

func parsePortStatus(message ofpMessage) (port, bool, error) {
	if len(message.Payload) < 8+ofp13PortLength {
		return port{}, false, fmt.Errorf("port status message is only %d bytes", len(message.Payload))
	}
	reason := message.Payload[0]
	portData := message.Payload[8:]
	current := port{
		number:     binary.BigEndian.Uint32(portData[0:4]),
		name:       strings.TrimRight(string(portData[16:32]), "\x00"),
		mac:        append(net.HardwareAddr(nil), portData[8:14]...),
		config:     PortConfig(binary.BigEndian.Uint32(portData[32:36])),
		advertised: binary.BigEndian.Uint32(portData[44:48]),
	}
	return current, reason == 1, nil
}

func marshalPortModification(xid uint32, current port, modification PortModification) []byte {
	payload := make([]byte, 32)
	binary.BigEndian.PutUint32(payload[0:4], current.number)
	copy(payload[8:14], current.mac)
	binary.BigEndian.PutUint32(payload[16:20], uint32(modification.Config))
	binary.BigEndian.PutUint32(payload[20:24], uint32(modification.Mask))
	binary.BigEndian.PutUint32(payload[24:28], modification.Advertise)
	return marshalMessage(ofpVersion, ofpTypePortMod, xid, payload)
}

func marshalPortDescriptionRequest(xid uint32) []byte {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint16(payload[0:2], libof.MultipartType_PortDesc)
	return marshalMessage(ofpVersion, ofpTypeMultipartRequest, xid, payload)
}

func strconvFormatUint32(value uint32) string {
	return fmt.Sprintf("%d", value)
}
