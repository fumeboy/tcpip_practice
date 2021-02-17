package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
)

/*

0               1               2               3               4
0 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |  端口号的字段的大小为16位，因此端口值的范围为0到65535
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |  表示 TCP 段在滑动窗口中的索引, 握手时，应当是初始序列号（Initial Sequence Number, ISN）
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |  发送者期望接收的下一个字节的窗口索引。握手后，必须始终填充ACK字段。
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |       |C|E|U|A|P|R|S|F|                               |  Header Length (HL) 记录 tcp 头部的长度
| Offset| rsvd  |W|C|R|C|S|S|Y|I|            Window             |  rsvd(Reserved) 未被使用
| (HL)  |       |R|N|G|K|H|T|N|N|                               |  window 字段用于通告窗口大小，即接收者愿意接受的字节数。由于它是一个16位字段，因此最大窗口大小为65,535字节
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |  当 URG 标志被设置时使用 Urgent Pointer，指示优先数据在流中的位置
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |  data 是可选的，比如，握手时，仅发送 TCP header
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

const (
	flagFin = 1 << iota // FIN 表示发送方已完成发送数据
	flagSyn             // SYN 用于在初始握手中同步序列号
	flagRst             // RST 重置TCP连接
	flagPsh             // PSH 用于指示 receiver 应尽快将数据推送到应用程序
	flagAck             // ACK 字段用于传达TCP握手状态。在TCP连接的后续报文中，它保持打开状态
	flagUrg             // URG, Urgent Pointer 指示该段包含优先数据
	flagECN             // ECN 通知 sender 已收到拥塞通知
	flagCWR             // Congestion Window Reduced 用于通知 sender 降低了其发送速率
)

type tcp struct {
	header struct {
		SrcPort       uint16
		DstPort       uint16
		SeqNum        uint32
		AckNum        uint32
		DataOffset    uint8 // 占 4 位，多占了4位刚好是不用的。单位是 32 位（4字节）， DataOffset = 1， 表示长度 1*4 字节
		Flags         uint8
		WindowSize    uint16
		Checksum      uint16
		UrgentPointer uint16
	}
	payload []byte
}

func (f *tcp) CheckSum(upper *ipv4) uint16 {
	// 首先解释下伪首部的概念，伪首部的数据都是从IP数据报头获取的
	// 其目的是让TCP检查数据是否已经正确到达目的地，只是单纯为了做校验用的。
	var pseudoHeader = struct {
		src   [4]byte
		dst   [4]byte
		_     uint8 // 此处置 0, 和下面的 uint8 组成 16 位
		proto ipv4ProtocolType
		tlen  uint16 // tcp 长度
	}{
		src:   upper.header.Src,
		dst:   upper.header.Dst,
		proto: upper.header.Protocol,
		tlen:  upper.header.Len - (uint16(upper.header.Version_IHL&0x0f)<<2),
	}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, &pseudoHeader)
	binary.Write(buf, binary.BigEndian, &f.header)
	binary.Write(buf, binary.BigEndian, f.payload)
	b := buf.Bytes()
	return CheckSum16(b, len(b), 0)
}

func (f *tcp) decode(upper *ipv4) (err error) {
	var buf = bytes.NewBuffer(upper.payload)
	if err = binary.Read(buf, binary.BigEndian, &f.header); err != nil {
		return
	}
	f.payload = buf.Bytes()
	if sum := f.CheckSum(upper); sum != 0 {
		return fmt.Errorf("tcp checksum error (%x)", sum)
	}
	return
}

func (f *tcp) encode(upper *ipv4) []byte {
	f.header.Checksum = 0
	f.header.Checksum = f.CheckSum(upper)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, &f.header)
	binary.Write(buf, binary.BigEndian, f.payload)
	return buf.Bytes()
}

func (f tcp) handle(upper *ipv4) (err error) {
	if err = f.decode(upper); err != nil {
		log.Println(err)
		return
	}
	fmt.Printf("%s tcp %s src %d dst %d seq %d\n",
		green, reset,
		f.header.SrcPort, f.header.DstPort, f.header.SeqNum)

	f.header.SrcPort, f.header.DstPort = f.header.DstPort, f.header.SrcPort
	if f.header.Flags&flagSyn > 0 {
		f.header.Flags |= flagAck
		f.header.AckNum = f.header.SeqNum + 1
		f.header.SeqNum = 0x12345678 // ISN
	}
	f.header.DataOffset = 5 << 4
	f.payload = nil

	fmt.Printf("%s tcp+%s src %d dst %d seq %d\n",
		green, reset,
		f.header.SrcPort, f.header.DstPort, f.header.SeqNum)

	upper.header.Src, upper.header.Dst = upper.header.Dst, upper.header.Src
	upper.header.Len = uint16(upper.header.Version_IHL&0x0f)<<2 + 20
	upper.payload = f.encode(upper)

	return
}
