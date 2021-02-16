package main

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type icmp_echo struct {
	id   uint16
	// 该字段由发送主机设置，以确定 echo reply 回传给哪个进程。可以是进程ID
	seq  uint16
	// 序号，从零开始并且每当形成新的回显请求时递增。这用于检测回显消息在传输过程中是否消失或重新排序
	payload []byte
	// 该字段是可选的，但通常包含诸如时间戳之类的信息，然后可以将其用于估计主机之间的往返时间
}

func (f *icmp_echo) encode() []byte{
	buf := make([]byte, 4+len(f.payload))
	binary.BigEndian.PutUint16(buf[0:2], f.id)
	binary.BigEndian.PutUint16(buf[2:4], f.seq)
	copy(buf[4:], f.payload)
	return buf
}

func (f *icmp_echo) decode(data []byte) error{
	buf := bytes.NewBuffer(data)
	if err := binary.Read(buf, binary.BigEndian, &f.id); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &f.seq); err != nil {
		return err
	}
	f.payload = buf.Bytes()
	return nil
}

func (f icmp_echo) handle(upper *icmp) error{
	switch upper.header.Type {
	case icmpTypeEchoReply:
		return errors.New("do nothing")
	case icmpTypeEcho:
	}
	if err := f.decode(upper.payload);err != nil{
		return err
	}
	upper.header.Type = icmpTypeEchoReply
	upper.header.Code = 0
	upper.payload = f.encode()
	return nil
}

