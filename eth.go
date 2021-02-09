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

type ethernetType uint16

const (
	ethernetTypeIPv4   ethernetType = 0x0800
	ethernetTypeARP  ethernetType = 0x0806
	ethernetTypeIPv6 ethernetType = 0x86dd
)

type ethHeader struct {
	Dst  [6]byte
	Src  [6]byte
	Type ethernetType
}

type ethFrame struct {
	ethHeader
	payload []byte
}

func (f *ethFrame) encode() []byte {
	frame := bytes.NewBuffer(make([]byte, 0))
	binary.Write(frame, binary.BigEndian, f.ethHeader)
	binary.Write(frame, binary.BigEndian, f.payload)
	if pad := minFrameSize - frame.Len(); pad > 0 {
		binary.Write(frame, binary.BigEndian, bytes.Repeat([]byte{byte(0)}, pad))
	}
	return frame.Bytes()
}

type ethRaw []byte

func (data ethRaw) decode() (*ethFrame, error) {
	frame := ethFrame{}
	buf := bytes.NewBuffer(data)
	if err := binary.Read(buf, binary.BigEndian, &frame.ethHeader); err != nil {
		return nil, err
	}
	frame.payload = buf.Bytes()
	return &frame, nil
}
