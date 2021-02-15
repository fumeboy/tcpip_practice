package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
)

type messageType uint8

const (
	messageTypeEchoReply messageType = 0
	messageTypeEcho      messageType = 8
)

type icmp struct {
	header struct{
		Type messageType
		Code uint8
		Sum  uint16
	}
	payload []byte
}

type icmp_echo struct {
	id   uint16
	seq  uint16
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

func (f *icmp_echo) encode() []byte{
	buf := make([]byte, 4+len(f.payload))
	binary.BigEndian.PutUint16(buf[0:2], uint16(f.id))
	binary.BigEndian.PutUint16(buf[2:4], uint16(f.seq))
	copy(buf[4:], f.payload)
	return buf
}

func (f *icmp) encode() []byte{
	buf := make([]byte, 4+len(f.payload))
	buf[0] = uint8(f.header.Type)
	buf[1] = uint8(f.header.Code)
	binary.BigEndian.PutUint16(buf[2:4], 0)
	copy(buf[4:], f.payload)
	binary.BigEndian.PutUint16(buf[2:4], CheckSum16(buf, len(buf), 0))
	return buf
}

func (f icmp) handle(upper *ipv4) (err error){
	if err = f.decode(upper.payload);err != nil{
		return err
	}
	switch f.header.Type {
		case messageTypeEcho, messageTypeEchoReply:
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

func (f icmp_echo) handle(upper *icmp) error{
	switch upper.header.Type {
	case messageTypeEchoReply:
		return errors.New("do nothing")
	case messageTypeEcho:
	}
	if err := f.decode(upper.payload);err != nil{
		return err
	}
	upper.header.Type = messageTypeEchoReply
	upper.header.Code = 0
	upper.payload = f.encode()
	return nil
}