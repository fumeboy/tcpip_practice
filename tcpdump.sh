# 1. 基于IP查找流量
tcpdump host 1.1.1.1
# 解释： host 表示接收的参数是 IP 地址

# 1.2 根据来源和目标进行筛选
tcpdump src 1.1.1.1
tcpdump dst 1.0.0.1

# 1.3 根据网段进行查找
tcpdump net 1.2.3.0/24

# 2. 使用十六进制输出
tcpdump host 1.1.1.1 -X # 大写 X 还会打印对应的 ascii 值， 小写x 不打印
# 解释: 加个 -X 表示 十六进制

# 2.1 同上，但是还显示 ethernet header
tcpdump host 1.1.1.1 -XX

# 2.2 显示 ethernet header
tcpdump host 1.1.1.1 -e

# 2.3 时间戳
tcpdump host 1.1.1.1 -tttt

# 2.4 对地址以数字方式显式，否则显式为主机名，也就是说-n选项不做主机名解析
tcpdump host 1.1.1.1 -n
tcpdump host 1.1.1.1 -nn # 除了-n的作用外，还把端口显示为数值，否则显示端口服务名

# 3 只捕获 x 个包，然后就停止
tcpdump host 1.1.1.1 -c 1

# 3.1 定义包获取的字节大小.使用-s0获取完整的包
tcpdump host 1.1.1.1 -s 1024

# 3.2 -Q 指定要抓取的包是流入还是流出的包，默认为"inout"
tcpdump host 1.1.1.1 -Q in

# 3.3 -i 指定tcpdump需要监听的以太网设备接口
tcpdump host 1.1.1.1 -i tap0

# 4 显示特定端口的流量
tcpdump port 3389
tcpdump src port 1025

# 4.1 查看一个端口段的流量
tcpdump portrange 21-23

# 5. 显示特定协议的流量
tcpdump icmp

# 5.1 只显示 ipv6 的流量
tcpdump ip6

# 基于包大小进行筛选
tcpdump less 32
tcpdump greater 64
tcpdump <= 128

# 读写文件
tcpdump port 80 -w ./1.txt # -w 保存
tcpdump -r capture_file # -r 输入

# 输出可用以太网设备接口
tcpdump -D







