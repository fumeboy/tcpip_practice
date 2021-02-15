package main

import (
	"bytes"
	"encoding/binary"
)

const (
	headerSize     = 14
	trailerSize    = 0 // without FCS
	maxPayloadSize = 1500
	minPayloadSize = 46
	minFrameSize   = headerSize + minPayloadSize + trailerSize
	maxFrameSize   = headerSize + maxPayloadSize + trailerSize
)

type ethProtocolType uint16

const (
	ethernetTypeIPv4 ethProtocolType = 0x0800
	ethernetTypeARP  ethProtocolType = 0x0806
	ethernetTypeIPv6 ethProtocolType = 0x86dd
)

type eth struct {
	header struct {
		Dst  [6]byte
		Src  [6]byte
		Type ethProtocolType
	}
	payload []byte
}

func (f *eth) encode() []byte {
	frame := bytes.NewBuffer(make([]byte, 0))
	binary.Write(frame, binary.BigEndian, f.header)
	binary.Write(frame, binary.BigEndian, f.payload)
	if pad := minFrameSize - frame.Len(); pad > 0 {
		binary.Write(frame, binary.BigEndian, bytes.Repeat([]byte{byte(0)}, pad))
	}
	return frame.Bytes()
}

func (f *eth) decode(data []byte) (error) {
	buf := bytes.NewBuffer(data)
	if err := binary.Read(buf, binary.BigEndian, &f.header); err != nil {
		return err
	}
	f.payload = buf.Bytes()
	return nil
}
