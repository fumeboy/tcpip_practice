// +build linux arp

package main

import (
	"errors"
	"fmt"
)

/*
	在终端 1 执行  sudo go run . -tags arp
	在终端 2 执行  sudo arping -I tap0 10.0.0.3
*/
func main(){
	dev,err := tap.open("tap0", "10.0.0.0/24", [4]byte{1,2,3,4}, [6]byte{1,2,3,4,5,6})
	if err != nil{
		fmt.Println(err)
		return
	}
	dev.run(func(dev *device, frame *ethFrame) error {
		switch frame.Type {
		case ethernetTypeARP:
			return handlerARP(dev, frame)
		}
		return errors.New("TODO")
	})
}
