package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
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
func (flags tuntap) open(name string, cidr string, ipv4Addr [4]byte) (*device, error) {
	//打开tuntap的字符设备，得到字符设备的文件描述字
	fd, err := os.OpenFile("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	var ifr struct {
		name	[0x10]byte
		flags	uint16
		union	[0x28 - 0x10 - 2]byte
	}
	copy(ifr.name[:], name)
	ifr.flags = uint16(flags)
	//通过ioctl系统调用，将fd和虚拟网卡驱动绑定在一起
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), syscall.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)));errno != 0 {
		fd.Close()
		return nil, errno
	}
	if err = SetLinkUp(name);err != nil{
		return nil,err
	}
	if err = SetRouter(name, cidr);err != nil{
		return nil,err
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), syscall.SIOCGIFHWADDR, uintptr(unsafe.Pointer(&ifr))); errno != 0{
		fd.Close()
		return nil, errno
	}
	var hardwareAddr [6]byte
	copy(hardwareAddr[:], ifr.union[:6])

	// 返回的文件描述字 fd 可以用来 read 和 write 该虚拟设备的以太网缓冲区
	return &device{
		ReadWriteCloser: fd,
		hardwareAddr: hardwareAddr,
		ipv4Addr: ipv4Addr,
	}, nil
}

func (flags tuntap) lazy(i int) (*device, error){
	return flags.open("dev"+strconv.Itoa(i), fmt.Sprintf("10.%d.0.0/24", i),  [4]byte{10,byte(i),0,1})
}

//SetLinkUp 让系统启动该网卡
func SetLinkUp(name string) (err error) {
	//ip link set <device_name> up
	if err = exec.Command("ip", "link", "set", name, "up").Run(); err != nil {
		log.Println(err)
	}
	return
}

func SetRouter(name, cidr string) (err error) {
	if out, err := exec.Command("ip", "route", "add", cidr, "dev", name).CombinedOutput(); err != nil {
		log.Println(string(out), err, name, cidr)
		return err
	}
	return
}

func (dev *device) run(sig chan struct{}, handler func(dev *device, frame *eth) error) {
	fmt.Printf("start at %x %v\n", dev.hardwareAddr, dev.ipv4Addr)
	buf := make([]byte, 2 << 12)
	var err error
	var n int
	var frame eth
	L:for {
		select {
		case <- sig:
			break L
		default:
		}
		n, err = dev.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Println(err)
			}
			break
		}
		if err = frame.decode(buf[:n]); err != nil {
			break
		}
		if err = handler(dev, &frame); err == nil {
			frame.header.Src = dev.hardwareAddr
			dev.Write(frame.encode())
		}
	}
	fmt.Println("good bye")
}



