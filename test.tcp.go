// +build tcp

package main

import (
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
)

/*
	在终端 1 执行  sudo go run . -tags tcp
	在终端 2 执行  nmap -Pn 10.1.0.1 -p 1337
	结果是 1337/tcp open  waste 即成功
*/
func main(){
	log.SetFlags(log.Lshortfile)
	dev,err := tap.lazy(1)
	if err != nil{
		log.Println(err)
		return
	}
	defer dev.Close()

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT)

	sig := make(chan struct{})
	go dev.run(sig, func(dev *device, frame *eth) error {
		switch frame.header.Type {
		case ethernetTypeIPv4:
			return (ipv4{}).handle(dev, frame)
		case ethernetTypeARP:
			return (arp{}).handle(dev, frame)
		}
		return errors.New("TODO")
	})
	<- c
	close(sig)
}
