package main

import (
	"errors"
	"fmt"
)

type tcpConnServer struct {
	conn
}

func (c *tcpConnServer) run() {
	defer func() {
		c.closed = true
		c.output(nil)
		if err := recover(); err != nil {
			c.err = errors.New(fmt.Sprintf("panic: %v", err))
			// 出现异常，上层应该发送 RST 表示要异常释放该连接
			// 丢弃任何待发数据并立即发送复位报文段
		}
	}()

	var datagram, fin *tcp
	var ok bool
LISTEN:
	if datagram, ok = c.input(); !ok { //  !ok 时， 即被动关闭 c.inputCh 时，表示超时
		return
	}
	if datagram.header.Flags&flagRst > 0 || // 检查 RST
		datagram.header.Flags&flagAck > 0 || // 检查 ACK, 应该为 0
		datagram.header.Flags&flagSyn == 0 { // 检查 SYN， 应该为 1
		goto LISTEN // 不处理 即丢弃该数据报
	}
	c.TCB.sender.ISN = 0x1234
	c.TCB.receiver.IRS, c.TCB.receiver.next = datagram.header.SeqNum, datagram.header.SeqNum+1
	datagram.header.Flags = flagAck | flagSyn // 向对方发送 ack 以及 syn
	datagram.header.SeqNum = c.TCB.sender.ISN
	c.output(datagram)
	c.TCB.sender.next, c.TCB.sender.unAck = c.TCB.sender.ISN+1, c.TCB.sender.ISN
SYN_RECV:
	if datagram, ok = c.input(); !ok {
		return
	}
	if datagram.header.Flags&flagRst > 0 {
		goto LISTEN // 如果收到 RST 包，会返回到 LISTEN 状态
	}
	if c.checkSeq(datagram) || // 检查是否是重复发送的包
		datagram.header.Flags&flagAck == 0 || // 检查 ACK 标志, 应该为 1
		datagram.header.Flags&flagSyn > 0 || // 检查 SYN 标志， 应该为 0
		c.checkAckNum(datagram) { // 检查 AckNUM 的值 是否合法
		goto SYN_RECV
	}
	// 到这一步说明 收到了正确的 ACK， 完成握手
ESTABLISHED:
	if datagram, ok = c.input(); !ok {
		return
	}
	if datagram.header.Flags&flagRst > 0 {
		c.err = errors.New("RST when ESTABLISHED")
		goto CLOSED // 如果收到 RST 包，表示对方异常中止该连接
	}
	if c.checkSeq(datagram) ||
		datagram.header.Flags&flagAck == 0 {
		goto ESTABLISHED
	}
	if datagram.header.Flags&flagSyn > 0 ||
		c.checkAckNum(datagram) {
		c.err = errors.New("Except Syn or Ack when ESTABLISHED")
		goto CLOSED
	}
	if datagram.header.Flags&flagFin > 0 && datagram.header.SeqNum == c.TCB.receiver.next {
		goto CLOSE_WAIT
	}
	// TODO 检查URG
	if len(datagram.payload) > 0 { // 有数据
		c.toApplication <- datagram.payload
	}
	goto ESTABLISHED
CLOSE_WAIT:
	datagram.header.Flags = flagAck
	c.output(datagram)
	// 回传一个 ACK 表示 已经接收到你的 FIN. 此时，对方不再发送报文，但可以接收报文

	close(c.toApplication)
	fin = &tcp{}
	fin.header.Flags = flagFin
	c.output(fin) // 主动传一个 FIN 表示这边已经处理完了数据，可以关闭了
LAST_ACK:
	if datagram, ok = c.input(); !ok {
		return
	}
	if datagram.header.Flags&flagRst > 0 {
		c.err = errors.New("RST when LAST_ACK")
		goto CLOSED
	}
	if c.checkSeq(datagram) ||
		datagram.header.Flags&flagAck == 0 {
		goto LAST_ACK
	}
	if datagram.header.Flags&flagSyn > 0 ||
		c.checkAckNum(datagram) {
		c.err = errors.New("Except Syn or Ack when LAST_ACK")
		goto CLOSED
	}
CLOSED:
	return
}
