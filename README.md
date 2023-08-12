## dpdk-tool 

dpdk 小工具集合，涉及`多核收发包、pcap抓包、tap/kni 收发包`等示例。


### 编译  
- 安装dpdk库（version >= 20.11） 
默认安装目录/usr/local/dpdk  
```bash
meson -Dexamples=all -Dmax_lcores=256 -Denable_kmods=true --prefix=/usr/local/dpdk build      
cd build && ninja -j8 -v 
ninja install 
```

- 编译工程    
```shell
cmake -B build 
cd build && make -j10
```  

### app  
- dpdkpcap  
dpdk 抓包工具  
```bash
./dpdkpcap -w $pci -l 1 -n 4 -- -h 192.168.100.11 -c 20 -w ./test.pcap
```  

- singlechannel   
arp/icmp协议实现，单核心收包，并响应常用的arp/icmp协议包 

- multichannel   
arp/icmp协议实现，多核心收包，并响应常用的arp/icmp协议包  

- tap
dpdk封装了tap接口，无需要修改任何代码，只需要加上--vdev参数就能创建一个tap虚拟网口。  
本示例支持多个加载多个网口，每个网口对应一个tap虚拟网卡，可设置独立的ip地址。  
```bash
# 启动应用
./tap -w $pci1 -w $pci2 -l 0-1 -n 4 --vdev=net_tap0 --vdev=net_tap1

# 为tap设置ip地址
ifconfig dtap0 hw ether $mac0
ip addr add 192.168.100.11/24 dev dtap0
ip link set dtap0 up

ifconfig dtap1 hw ether $mac1
ip addr add 192.168.200.11/24 dev dtap1
ip link set dtap1 up
```
> 注意：请保持tap网卡mac地址与物理网卡一致，否则会收不到对端发过来的数据包。

- kni  
kni 简单示例，演示与kni设备交互  
```bash
# 加载kni 驱动
rmmod rte_kni
insmod /data/kanesun/rte_kni.ko kthread_mode=multiple carrier=on

# 启动应用  
./kni -l 0-1 -n 2 -- --config="(0,0,1)" 

# 打印统计信息
pkill -USR1 kni
```

- kni_queue  
带队列的kni 示例，通过RING解耦；主进程收包，子进程消费队列数据包并与虚拟网卡交互  
```bash
# 先启动主进程  
./kni_send -w $pci1 -l 0 -n 4 --proc-type=primary

# 再启动子进程  
./kni_recv -w $pci1 -l 0 -n 4 --proc-type=secondary
```
