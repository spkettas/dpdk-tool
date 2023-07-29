## dpdk-tool 

dpdk 小工具集锦  


### 编译  
- 安装dpdk库（version >= 20.11） 
默认目录/usr/local/dpdk  

- 编译  
```shell
cmake -B build 
cd build && make -j10
```  

### app  
- kni  
kni 协议栈交互  
```shell
rmmod rte_kni
insmod ./rte_kni.ko kthread_mode=multiple carrier=on
./kni -l 0-1 -n 2 -- '--config=(0,0,1)'

# 打印统计信息
pkill -USR1 kni
```

- dpdkpcap  
dpdk 抓包工具  

- singlechannel   
arp/icmp协议实现，单核心收包，并响应常用的arp/icmp协议包 

- multichannel   
arp/icmp协议实现，多核心收包，并响应常用的arp/icmp协议包  
