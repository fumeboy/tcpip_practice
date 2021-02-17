package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
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

/*

0               1               2               3               4
0 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  | Type of Service |        Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Identification(fragment Id)    |Flags|  Fragment Offset      |
|           16 bits               |R|D|M|       13 bits         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Time-To-Live  |   Protocol      |      Header Checksum        |
| ttl(8 bits)   |    8 bits       |          16 bits            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Source IP Address (32 bits)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              Destination Ip Address (32 bits)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options (*** bits)          |  Padding     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

type ipv4 struct {
	header struct{
		Version_IHL uint8
		// version 和 ihl(internet header length)
		// 版本号和头部长度， 各占 4 bit
		// 由于 ihl 的大小为4位，因此最多只能保留15个值
		// 因此，IP报头的最大长度为60个八位位组（15乘以32除以8）,32 是 ipv4 默认的机器字长，8即一个字节占8bit
		TOS                  uint8  // type of service
		Len                  uint16 // 数据报文总长(单位 1 字节)
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

func (f *ipv4) decode(data []byte) error {
	if len(data) < int(unsafe.Sizeof(f.header)) {
		return fmt.Errorf("ip packet is too short (%d)", len(data))
	}
	buf := bytes.NewBuffer(data)
	if err := binary.Read(buf, binary.BigEndian, &f.header); err != nil {
		return err
	}
	if f.header.Version_IHL >> 4 != ipv4Version {
		return fmt.Errorf("not ipv4 packet")
	}
	hlen := int((f.header.Version_IHL & 0x0f) << 2) // 左移 2 位表示 乘以32除以8
	if len(data) < hlen {
		return fmt.Errorf("need least header length's data")
	}
	if sum := CheckSum16(data, hlen, 0); sum != 0 { // ip 校验和只需要校验头部
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
	f.header.Checksum = 0
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, &f.header)
	b := buf.Bytes()
	binary.BigEndian.PutUint16(b[10:12], CheckSum16(b, int((f.header.Version_IHL&0x0f)<<2), 0))
	return append(b, f.payload...)
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  todo: ip数据报重组
  当上层应用数据报过大,超过了MTU,那么在ip层就要进行拆包,将
  大数据拆分成小数据发送出去,对方接收到之后也要进行组包.
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

func (f ipv4) handle(dev*device, upper *eth) (err error) {
	if err = f.decode(upper.payload);err != nil{
		log.Println(err)
		return
	}
	fmt.Printf("%s  ip %s src: %v dst: %v type: %d\n",
		yellow, reset,
		f.header.Src, f.header.Dst, f.header.Protocol)

	if f.header.Dst != dev.ipv4Addr{
		return errors.New("Not us")
	}
	switch f.header.Protocol {
	case ipv4ProtocolTypeICMP:
		err = (icmp{}).handle(&f)
	case ipv4ProtocolTypeTCP:
		err = (tcp{}).handle(&f)
	default:
		err = errors.New("TODO")
	}
	if err == nil{
		fmt.Printf("%s  ip+%s src: %v dst: %v type: %d\n",
			yellow, reset,
			f.header.Src, f.header.Dst, f.header.Protocol)

		upper.payload = f.encode()
		upper.header.Dst = upper.header.Src
	}
	return
}

