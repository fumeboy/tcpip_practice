package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

type device struct {
	io.ReadWriteCloser
	hardwareAddr [6]byte
	ipv4Addr [4]byte
}

type tuntap uint16

// IFF_NO_PI 表示不需要包信息
const tun tuntap = syscall.IFF_TUN|syscall.IFF_NO_PI

// 当我们要从第 2 层开始构建网络协议栈时，我们需要 TAP 设备
const tap tuntap = syscall.IFF_TAP|syscall.IFF_NO_PI

// 新建一个 tap/tun 模式的虚拟网卡，然后返回该网卡的文件描述符
// 先打开一个字符串设备，通过系统调用将虚拟网卡和字符串设备fd绑定在一起
func (flags tuntap) open(name string, netmask string, ipv4Addr [4]byte, hardwareAddr [6]byte) (*device, error) {
	//打开tuntap的字符设备，得到字符设备的文件描述字
	fd, err := os.OpenFile("/dev/net/tun", syscall.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	var ifr struct {
		name	[0x10]byte
		flags	uint16
		_	[0x28 - 0x10 - 2]byte
	}
	copy(ifr.name[:], name)
	ifr.flags = uint16(flags)
	//通过ioctl系统调用，将fd和虚拟网卡驱动绑定在一起
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), syscall.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		fd.Close()
		return nil, errno
	}

	if err = SetLinkUp(name);err != nil{
		return nil,err
	}
	if err = SetRoute(name, netmask);err != nil{
		return nil,err
	}

	// 返回的文件描述字 fd 可以用来 read 和 write 该虚拟设备的以太网缓冲区
	return &device{
		ReadWriteCloser: fd,
		hardwareAddr: hardwareAddr,
		ipv4Addr: ipv4Addr,
	}, nil
}

//SetLinkUp 让系统启动该网卡
func SetLinkUp(name string) (err error) {
	//ip link set <device_name> up
	out, cmdErr := exec.Command("ip", "link", "set", name, "up").CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
		return
	}
	return
}

//SetRoute 通过ip命令添加路由
func SetRoute(name, cidr string) (err error) {
	//ip route add 192.168.1.0/24 dev tap0
	out, cmdErr := exec.Command("ip", "route", "add", cidr, "dev", name).CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
		return
	}
	return
}

func (dev *device) run(handler func(dev *device, frame *ethFrame) error) {
	buf := make([]byte, 2 << 12)
	var err error
	var n int
	var frame *ethFrame
	for {
		n, err = dev.Read(buf)
		if n > 0 {
			fmt.Printf("--- %d bytes ---\n", n)
			fmt.Printf("%s\n", hex.Dump(buf[:n]))
		}
		if err != nil {
			if err != io.EOF {
				fmt.Println(err)
			}
			break
		}
		frame, err = (ethRaw)(buf).decode()
		if err != nil {
			break
		}
		if err = handler(dev, frame); err == nil {
			dev.Write(frame.encode())
		}
	}
	fmt.Println(err)
	fmt.Println("good bye")
}



