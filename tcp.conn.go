package main

import (
	"sync"
	"time"
)

type conn struct {
	key           connKey
	inputCh       chan *tcp
	outputCh      chan *tcp
	closed        bool
	toApplication chan []byte
	timer         time.Timer
	err           error
	TCB
}

var ExceptQuit *tcp = nil

func (c *conn) input() (datagram *tcp, ok bool) {
	datagram, ok = <-c.inputCh
	return
}

func (c *conn) output(datagram *tcp) {
	if datagram == ExceptQuit {
		close(c.outputCh)
	} else {
		c.outputCh <- datagram
	}
	HostTCP.output <- c
}

type TCB struct {
	// Transmission Control Block
	sender struct {
		unAck         uint32 // unAcknowledge 尚未被确认的数据的起始序列号
		next          uint32 // 下一个要发送的数据bit对应的序列号,即seq
		window        uint32 // 发送窗口的大小
		urgentPointer uint32
		WL1           uint32 // segment sequence number used for last window update
		WL2           uint32 // segment acknowledgment number used for last window update
		ISN           uint32 // initial send sequence number 初始的序列号(自己产生的)
	}
	receiver struct {
		next          uint32
		window        uint32
		urgentPointer uint32
		IRS           uint32 // initial receive sequence number 接收到的起始序列号(对方的起始序列号)
	}
}

func (c *conn) checkSeq(datagram *tcp) bool {
	tcb := c.TCB
	/*
		接收到的包的序列号如果小于我们期待接收的下一个数据报的序列号(receiver.next),那么这是一个
		重传的数据包,同时,如果序列号大于 receiver.next + receiver.window,表示可能是对方传送太多,
		当然也可能是别的原因.总之这些都是无用的数据报
	*/
	if len(datagram.payload) > 0 && tcb.receiver.window == 0 ||
		datagram.header.SeqNum < tcb.receiver.next ||
		datagram.header.SeqNum > (tcb.receiver.next+tcb.receiver.window) {

		datagram = &tcp{}
		datagram.header.Flags = flagAck // 向对方发送 ack
		datagram.header.SeqNum = tcb.sender.next
		c.output(datagram)
		return true
	}
	return false
}

func (c *conn) checkAckNum(datagram *tcp) bool {
	if !(c.sender.unAck < datagram.header.AckNum && datagram.header.AckNum <= c.sender.next) {
		// 确保对方发过来的 ack_seq 是合法的
		return true
	}
	// 一旦接收到 ack 表示 ackNum 序号之前的数据都已经收到了
	c.sender.unAck = datagram.header.AckNum
	return false
}

type connKey struct { // 一对地址指定一条连接
	aIP, bIP     uint32
	aPort, bPort uint16
}
type tcpHost struct {
	conns     map[connKey]*conn
	connsLock sync.Mutex
	output    chan *conn
	dev *device
}

var HostTCP = tcpHost{}

func (host *tcpHost) run() {
	var datagram *tcp

	for c := range host.output {
		if c.closed {
			host.connsLock.Lock()
			delete(host.conns, c.key)
			host.connsLock.Unlock()
			if c.err != nil{
				datagram = &tcp{}
				datagram.header.Flags = flagRst // 向对端发送 RST
				datagram.header.SeqNum, c.sender.unAck =
					c.sender.next, c.sender.next // rst 不消耗序列号
				/*
					一般来说，无论何时一个报文段出现错误，TCP都会发出一个RST报文段
					RST报文段，接收方不会进行确认。收到RST的一方将终止该连接，并通知应用层连接复位
				*/
			}
		}else{
			for datagram = range c.outputCh{

			}
		}
	}
}

func (host *tcpHost) send(c *conn, datagram *tcp){
	// 因为是异步发送， 所以要自己构造返回的以太网帧
	datagram.header.DstPort, datagram.header.SrcPort =
		c.key.bPort, c.key.aPort

	ip := ipv4{
		header: struct {
			Version_IHL          uint8
			TOS                  uint8
			Len                  uint16
			Id                   uint16
			Flags_FragmentOffset uint16
			TTL                  uint8
			Protocol             ipv4ProtocolType
			Checksum             uint16
			Src                  [4]byte
			Dst                  [4]byte
		}{
			// TODO
		},
	}
	ip.payload = datagram.encode(&ip)

	e := eth{
		header: struct {
			Dst  [6]byte
			Src  [6]byte
			Type ethProtocolType
		}{},
		payload: ip.encode(),
	}

	host.dev.Write(e.encode())
}
