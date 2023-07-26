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
- dpdkpcap  
dpdk 抓包工具  

- singlechannel   
arp/icmp协议实现，单核心收包  

- multichannel   
arp/icmp协议实现，多核心收包  
