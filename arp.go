package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type HardwareType uint16
type arpOperationCode uint16 //ARPop 表示ARP的操作码  1 2 3 4

const (
	HardwareTypeLoopback HardwareType = 0x0000
	HardwareTypeEthernet HardwareType = 0x0001

	ARPRequest arpOperationCode = 1 //arp请求
	ARPReply   arpOperationCode = 2 //arp应答
)

type arp struct {
	HardwareType          HardwareType
	ProtocolType          ethProtocolType
	HardwareAddressLength uint8
	ProtocolAddressLength uint8
	OperationCode         arpOperationCode
	SourceHardwareAddress [6]byte // 以太网地址一般就是 6 个字节
	SourceProtocolAddress [4]byte // ipv4 就是 4 个字节， 暂时不考虑 ipv6
	TargetHardwareAddress [6]byte
	TargetProtocolAddress [4]byte
}

func (f *arp) encode() []byte{
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, f)
	return buf.Bytes()
}

func (f *arp) decode(data []byte) (error) {
	buf := bytes.NewBuffer(data)
	if err := binary.Read(buf, binary.BigEndian, f); err != nil {
		return err
	}
	return nil
}

func (f arp) handle (dev *device, upper *eth) error{
	if err := f.decode(upper.payload);err != nil{
		return err
	}
	fmt.Printf("arp\tsrc: %x %x \tdst: %x %x\n",
		f.SourceHardwareAddress, f.SourceProtocolAddress,
		f.TargetHardwareAddress, f.TargetProtocolAddress)
	if f.HardwareType != HardwareTypeEthernet{
		return errors.New("UnsupportedHardWareType")
	}
	if f.ProtocolType != ethernetTypeIPv4 {
		return errors.New("UnsupportedProtocol")
	}
	merge := arpCache.update(f.SourceProtocolAddress, f.SourceHardwareAddress)
	if dev.ipv4Addr != f.TargetProtocolAddress {
		return errors.New("ARP was not for us")
	}
	if !merge && !arpCache.insert(f.SourceProtocolAddress, f.SourceHardwareAddress) {
		return errors.New("No free space in ARP translation table")
	}
	switch f.OperationCode {
	case ARPRequest:
		// reply
		f.TargetProtocolAddress = f.SourceProtocolAddress
		f.TargetHardwareAddress = f.SourceHardwareAddress
		f.SourceHardwareAddress = dev.hardwareAddr
		f.SourceProtocolAddress = dev.ipv4Addr
		f.OperationCode = ARPReply
		upper.payload = f.encode()
		upper.header.Dst = f.TargetHardwareAddress
	}
	return nil
}
