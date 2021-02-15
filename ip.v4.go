package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
)

type ipv4ProtocolType uint8
const (
	ipv4ProtocolTypeICMP ipv4ProtocolType = 0x01
	ipv4ProtocolTypeTCP  ipv4ProtocolType = 0x06
	ipv4ProtocolTypeUDP  ipv4ProtocolType = 0x11

	ipv4Version = 4

	IPv4FlagMoreFragments = 1 << iota
	IPv4FlagDontFragment
)

type ipv4 struct {
	header struct{
		Version_IHL uint8
		// version 和 ihl(internet header length)
		// 版本号和头部长度， 各占 4 bit
		// 由于 ihl 的大小为4位，因此最多只能保留15个值
		// 因此，IP报头的最大长度为60个八位位组（15乘以32除以8）,32 是 ipv4 默认的机器字长，8即一个字节占8bit
		TOS                  uint8  // type of service
		Len                  uint16 // 数据报文总长
		Id                   uint16
		Flags_FragmentOffset uint16
		// flags , 占 3 bit， 控制标志
		// fragmentOffset ，占 13 bit，指示所述片段在数据报的位置，第一个数据报的索引设置为0
		TTL                uint8 // time to live
		Protocol           ipv4ProtocolType // 传输层协议
		Checksum           uint16 // 首部校验和
		Src                [4]byte
		Dst                [4]byte
	}
	payload []byte
}

func CheckSum16(b []byte, n int, init uint32) uint16 {
	sum := init
	for i := 0; i < n-1; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
		if (sum >> 16) > 0 {
			sum = (sum & 0xffff) + (sum >> 16)
		}
	}
	if n&1 != 0 {
		sum += uint32(b[n-1]) << 8
		if (sum >> 16) > 0 {
			sum = (sum & 0xffff) + (sum >> 16)
		}
	}
	return ^(uint16(sum))
}

func (f *ipv4) decode(data []byte) error {
	if len(data) < int(unsafe.Sizeof(f.header)) {
		return fmt.Errorf("ip packet is too short (%d)", len(data))
	}
	buf := bytes.NewBuffer(data)
	if err := binary.Read(buf, binary.BigEndian, &f.header); err != nil {
		return err
	}
	if f.header.Version_IHL>> 4 != ipv4Version {
		return fmt.Errorf("not ipv4 packet")
	}
	hlen := int((f.header.Version_IHL & 0x0f) << 2) // 左移 2 位表示 乘以32除以8
	if len(data) < hlen {
		return fmt.Errorf("need least header length's data")
	}
	if sum := CheckSum16(data, hlen, 0); sum != 0 {
		return fmt.Errorf("ip checksum error (%x)", sum)
	}
	if len(data) < int(f.header.Len) {
		return fmt.Errorf("ip packet length error")
	}
	if f.header.TTL == 0 {
		return fmt.Errorf("ip packet was dead (TTL=0)")
	}
	f.payload = data[hlen:int(f.header.Len)]
	return nil
}

func (f *ipv4) encode() []byte{
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, &f.header)
	binary.Write(buf, binary.BigEndian, f.payload)
	b := buf.Bytes()
	binary.BigEndian.PutUint16(b[10:12], CheckSum16(b, int((f.header.Version_IHL&0x0f)<<2), 0))
	return b
}

func (f ipv4) handle(dev*device, upper *eth) (err error) {
	if err = f.decode(upper.payload);err != nil{
		return
	}
	switch f.header.Protocol {
	case ipv4ProtocolTypeICMP:
		err = (icmp{}).handle(&f)
	default:
		err = errors.New("TODO")
	}
	if err == nil{
		upper.payload = f.encode()
		upper.header.Dst = upper.header.Src
	}
	return
}

