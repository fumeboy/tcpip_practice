package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
)

type icmpType uint8

const (
	icmpTypeEchoReply icmpType = 0
	icmpTypeEcho      icmpType = 8
)

type icmp struct {
	// ICMP, Internet Control Message Protocol
	header struct{
		Type icmpType
		// 为type字段保留了42个值，但通常仅使用大约8个，比如 类型0（echo应答），3（目标不可达）和8（echo请求）
		Code uint8
		// 进一步描述了消息的含义，例如，当类型为3（目标无法到达）时，代码字段将说明原因
		CheckSum uint16
		// 字段与IPv4标头中的校验和字段相同，并且可以使用相同的算法来计算它
		// 但是在ICMPv4中，计算校验和时包括 payload
	}
	payload []byte
}

func (f *icmp) decode(data []byte) error{
	if len(data) < int(unsafe.Sizeof(f.header)) {
		return fmt.Errorf("message is too short")
	}
	buf := bytes.NewBuffer(data)
	if err := binary.Read(buf, binary.BigEndian, &f.header); err != nil {
		return err
	}
	f.payload = buf.Bytes()
	return nil
}

func (f *icmp) encode() []byte{
	buf := make([]byte, 4+len(f.payload))
	buf[0] = uint8(f.header.Type)
	buf[1] = uint8(f.header.Code)
	buf[2], buf[3] = 0, 0 // 校验和字段置 0
	copy(buf[4:], f.payload)
	binary.BigEndian.PutUint16(buf[2:4], CheckSum16(buf, len(buf), 0))
	return buf
}

func (f icmp) handle(upper *ipv4) (err error){
	if err = f.decode(upper.payload);err != nil{
		return err
	}
	switch f.header.Type {
		case icmpTypeEcho, icmpTypeEchoReply:
			err = (icmp_echo{}).handle(&f)
		default:
			err = errors.New("TODO")
	}
	if err == nil{
		upper.header.Dst, upper.header.Src = upper.header.Src, upper.header.Dst
		upper.payload = f.encode()
	}
	return
}