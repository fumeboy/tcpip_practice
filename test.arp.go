// +build arp

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

/*
	在终端 1 执行  sudo go run . -tags arp
	在终端 2 执行  sudo arping -I dev1 10.0.0.1
*/
func main(){
	log.SetFlags(log.Lshortfile)
	dev,err := tap.lazy(1)
	if err != nil{
		fmt.Println(err)
		return
	}
	defer dev.Close()

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT)

	sig := make(chan struct{})
	go dev.run(sig, func(dev *device, frame *eth) error {
		switch frame.header.Type {
		case ethernetTypeARP:
			return (arp{}).handle(dev, frame)
		}
		return errors.New("TODO")
	})
	<- c
	close(sig)
}
