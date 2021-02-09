package main

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type HardwareType uint16
type ARPOp uint16 //ARPop 表示ARP的操作码  1 2 3 4

const (
	HardwareTypeLoopback HardwareType = 0x0000
	HardwareTypeEthernet HardwareType = 0x0001

	ARPRequest ARPOp = 1 //arp请求
	ARPReply ARPOp = 2 //arp应答
)

type arpFrame struct {
	HardwareType          HardwareType
	ProtocolType          ethernetType
	HardwareAddressLength uint8
	ProtocolAddressLength uint8
	OperationCode         ARPOp
	SourceHardwareAddress [6]byte // 以太网地址一般就是 6 个字节
	SourceProtocolAddress [4]byte // ipv4 就是 4 个字节， 暂时不考虑 ipv6
	TargetHardwareAddress [6]byte
	TargetProtocolAddress [4]byte
}

func (f *arpFrame) encode() []byte{
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, f)
	return buf.Bytes()
}

type arpRaw []byte

func (data arpRaw) decode() (*arpFrame, error) {
	f := arpFrame{}
	buf := bytes.NewBuffer(data)
	if err := binary.Read(buf, binary.BigEndian, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func handlerARP(dev *device, upper *ethFrame) error{
	frame, err := (arpRaw)(upper.payload).decode()
	if err != nil{
		return err
	}
	if frame.HardwareType != HardwareTypeEthernet{
		return errors.New("UnsupportedHardWareType")
	}
	if frame.ProtocolType != ethernetTypeIPv4 {
		return errors.New("UnsupportedProtocol")
	}
	merge := arpCache.update(frame.SourceProtocolAddress, frame.SourceHardwareAddress)
	if dev.ipv4Addr != frame.TargetProtocolAddress {
		return errors.New("ARP was not for us")
	}
	if !merge && !arpCache.insert(frame.SourceProtocolAddress, frame.SourceHardwareAddress) {
		return errors.New("ERR: No free space in ARP translation table")
	}
	switch frame.OperationCode {
	case ARPRequest:
		// reply
		frame.TargetProtocolAddress = frame.SourceProtocolAddress
		frame.TargetHardwareAddress = frame.SourceHardwareAddress
		frame.SourceHardwareAddress = dev.hardwareAddr
		frame.SourceProtocolAddress = dev.ipv4Addr
		frame.OperationCode = ARPReply
		upper.payload = frame.encode()
		upper.Dst = frame.TargetHardwareAddress
		upper.Src = dev.hardwareAddr
	}
	return nil
}
