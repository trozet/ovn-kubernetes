// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package openflow

import (
	"encoding/binary"
	"fmt"

	libof "antrea.io/libOpenflow/openflow13"
)

const (
	nxActionCheckPacketLarger = 49
	checkPacketLargerLength   = 24
)

// checkPacketLargerAction implements NXAST_CHECK_PKT_LARGER. libOpenflow does
// not currently expose this Nicira action.
type checkPacketLargerAction struct {
	*libof.NXActionHeader
	packetLength uint16
	offset       uint16
	destination  uint32
}

func newCheckPacketLargerAction(packetLength, offset uint16, destination uint32) *checkPacketLargerAction {
	header := libof.NewNxActionHeader(nxActionCheckPacketLarger)
	header.Length = checkPacketLargerLength
	return &checkPacketLargerAction{
		NXActionHeader: header,
		packetLength:   packetLength,
		offset:         offset,
		destination:    destination,
	}
}

func (a *checkPacketLargerAction) Len() uint16 {
	return checkPacketLargerLength
}

func (a *checkPacketLargerAction) MarshalBinary() ([]byte, error) {
	data := make([]byte, a.Len())
	header, err := a.NXActionHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data, header)
	binary.BigEndian.PutUint16(data[10:12], a.packetLength)
	binary.BigEndian.PutUint16(data[12:14], a.offset)
	binary.BigEndian.PutUint32(data[14:18], a.destination)
	return data, nil
}

func (a *checkPacketLargerAction) UnmarshalBinary(data []byte) error {
	if len(data) < checkPacketLargerLength {
		return fmt.Errorf("check packet larger action is only %d bytes", len(data))
	}
	header := new(libof.NXActionHeader)
	if err := header.UnmarshalBinary(data); err != nil {
		return err
	}
	if header.Subtype != nxActionCheckPacketLarger || header.Length != checkPacketLargerLength {
		return fmt.Errorf("invalid check packet larger action header")
	}
	a.NXActionHeader = header
	a.packetLength = binary.BigEndian.Uint16(data[10:12])
	a.offset = binary.BigEndian.Uint16(data[12:14])
	a.destination = binary.BigEndian.Uint32(data[14:18])
	return nil
}
