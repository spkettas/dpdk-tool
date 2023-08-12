/**
 * Copyright (c) 1998-2020 Inc. All rights reserved.
 *
 * @file simple.c
 * @author kanesun (spkettas@gmail.com)
 * @date 2023-07-28
 *
 * @brief Tap虚拟设备收发包程序
 */
#include <inttypes.h>
#include <rte_arp.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <rte_malloc.h>
#include "generic/rte_cycles.h"
#include "rte_build_config.h"
#include "rte_common.h"
#include "rte_mbuf_core.h"
#include "rte_ring.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS       8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE      32

#define MBUF_NAME "MBUF_POOL"
#define MSG_POOL  "MSG_POOL"

// TODO 从配置中读取
#define LOCAL_IP1 644131008  // ip0="192.168.100.38"
#define LOCAL_IP2 650684608  // ip1="192.168.200.38"

struct port_info {
  uint16_t tap;  // tap port id
  uint16_t nic;  // nic port id
};

struct rte_ether_addr    ether_mac_addr;
unsigned                 nb_ports;
unsigned                 enable_promis = 0;
struct rte_mempool*      message_pool;
struct rte_ring*         tcpip_ring;
static rte_atomic16_t    queue = RTE_ATOMIC32_INIT(-1);
static struct port_info* port_map[RTE_MAX_ETHPORTS];

static int16_t get_queue() { return rte_atomic16_add_return(&queue, 1); }

static const struct rte_eth_conf port_conf_default = {
    .rxmode =
        {
            .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        },
};

struct net_message {
  struct rte_mbuf* mbuf;
  int64_t          port;
};

static int is_stp(const char* hdr) {
  return (hdr[0] == 0x42 && hdr[1] == 0x42);
}

static void enqueue_mbuf(uint16_t port, struct rte_mbuf* mbuf) {
  // rte_ring_sp_enqueue(tcpip_ring, mbuf);
  struct net_message* msg;
  if (rte_mempool_get(message_pool, (void**)&msg) < 0) {
    rte_exit(EXIT_FAILURE, "alloc net_message error\n");
    return;
  }

  msg->port = port;
  msg->mbuf = mbuf;
  if (rte_ring_enqueue(tcpip_ring, msg) < 0) {
    rte_exit(EXIT_FAILURE, "no enough room to alloc\n");
  }
}

static void filter_pkt(uint16_t port, struct rte_mbuf* mbuf) {
  struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
  char*                 cur_hdr = (char*)eth_hdr + sizeof(struct rte_ether_hdr);

  if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {  // arp
    printf("> enq %u arp len %u\n", port, rte_pktmbuf_data_len(mbuf));

    enqueue_mbuf(port, mbuf);
  } else if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
    struct rte_ipv4_hdr* ip_hdr = rte_pktmbuf_mtod_offset(
        mbuf, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
    if ((ip_hdr->dst_addr == LOCAL_IP1 || ip_hdr->dst_addr == LOCAL_IP2) &&
        ip_hdr->next_proto_id == IPPROTO_ICMP) {  // icmp
      printf("> enq %u icmp len %u\n", port, rte_pktmbuf_data_len(mbuf));

      enqueue_mbuf(port, mbuf);
    }
  }
}

static void show_pkt(uint16_t nic_id, struct rte_mbuf* bufs[BURST_SIZE],
                     uint16_t nb_rx) {
  uint16_t i;

  for (i = 0; i < nb_rx; i++) {
    // 过滤本机的arp/icmp包
    // filter_pkt(port, bufs[i]);

    // parse pkt
    struct rte_ether_hdr* eth_hdr =
        rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr*);
    char* cur_hdr = (char*)eth_hdr + sizeof(struct rte_ether_hdr);

    if (eth_hdr->ether_type == rte_be_to_cpu_16(RTE_ETHER_TYPE_ARP)) {
      printf("port %u got arp\n", nic_id);
    } else if (eth_hdr->ether_type == rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4)) {
      struct rte_ipv4_hdr* ip_hdr = rte_pktmbuf_mtod_offset(
          bufs[i], struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
      uint8_t ip_len = rte_ipv4_hdr_len(ip_hdr);
      cur_hdr += ip_len;

      if (ip_hdr->next_proto_id == IPPROTO_ICMP) {
        printf("port %u got icmp\n", nic_id);
      } else if (ip_hdr->next_proto_id == IPPROTO_TCP) {
        struct rte_tcp_hdr* tcp = (struct rte_tcp_hdr*)cur_hdr;
        printf("port %u got tcp dport %u\n", nic_id, htons(tcp->dst_port));
      } else if (ip_hdr->next_proto_id == IPPROTO_UDP) {
        struct rte_udp_hdr* udp = (struct rte_udp_hdr*)cur_hdr;
        printf("port %u got udp dport %u\n", nic_id, htons(udp->dst_port));
      }
    } else if (eth_hdr->ether_type == rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV6)) {
      printf("port %u got ipv6\n", nic_id);
    } else if (is_stp(cur_hdr)) {
      printf("port %u got stp\n", nic_id);
    } else {
      printf("port %u other pkt 0x%x\n", nic_id,
             rte_be_to_cpu_16(eth_hdr->ether_type));
    }
  }
}

static int kni_ingress() {
  printf("Core %u ingress packets\n", rte_lcore_id());
  struct rte_mbuf*  bufs[BURST_SIZE];
  struct port_info* p;
  uint16_t          i, j;
  uint16_t          nb_rx, nb_tx;

  while (1) {
    for (i = 0; i < RTE_MAX_ETHPORTS; ++i) {
      p = port_map[i];
      if (p == NULL) {
        break;
      }

      // from nic
      nb_rx = rte_eth_rx_burst(p->nic, 0, bufs, BURST_SIZE);
      show_pkt(p->nic, bufs, nb_rx);

      // to tap
      if (nb_rx) {
        printf("Sent nic %u len %u to tap %u\n", p->nic,
               rte_pktmbuf_data_len(bufs[0]), p->tap);
        nb_tx = rte_eth_tx_burst(p->tap, 0, bufs, nb_rx);

        if (unlikely(nb_tx < nb_rx)) {
          for (j = nb_tx; j < nb_rx; j++) {
            rte_pktmbuf_free(bufs[j]);
          }
        }
      }
    }
  }

  return 0;
}

static int kni_egress() {
  printf("Core %u egress packets\n", rte_lcore_id());
  struct rte_mbuf*  bufs[BURST_SIZE];
  struct port_info* p;
  uint16_t          i;
  uint16_t          nb_rx, nb_tx;

  while (1) {
    for (i = 0; i < RTE_MAX_ETHPORTS; ++i) {
      p = port_map[i];
      if (p == NULL) {
        break;
      }

      // from tap
      nb_rx = rte_eth_rx_burst(p->tap, 0, bufs, BURST_SIZE);

      if (nb_rx) {
        printf("Sent tap %u to nic %u\n", p->tap, p->nic);

        // to nic
        nb_tx = rte_eth_tx_burst(p->nic, 0, bufs, nb_rx);

        if (unlikely(nb_tx < nb_rx)) {
          for (i = nb_tx; i < nb_rx; i++) {
            rte_pktmbuf_free(bufs[i]);
          }
        }
      }
    }
  }

  return 0;
}

static int lcore_main(__rte_unused void* arg) {
  uint16_t queue = get_queue();

  switch (queue) {
    case 0:
      kni_ingress();
      break;
    case 1:
      kni_egress();
      break;
    default:
      break;
  }

  return 0;
}

static inline int port_init(uint16_t port_id, struct rte_mempool* mbuf_pool) {
  char                    mac_str[18];
  struct rte_eth_conf     port_conf = port_conf_default;
  const uint16_t          rx_rings = 1, tx_rings = 1;  // one queue
  uint16_t                nb_rxd = RX_RING_SIZE;
  uint16_t                nb_txd = TX_RING_SIZE;
  int                     retval;
  uint16_t                q;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_txconf   txconf;

  if (!rte_eth_dev_is_valid_port(port_id)) return -1;

  rte_eth_macaddr_get(port_id, &ether_mac_addr);
  rte_ether_format_addr(mac_str, sizeof(mac_str), &ether_mac_addr);
  printf("Port %d MAC %s\n", port_id, mac_str);

  char name[RTE_ETH_NAME_MAX_LEN];
  int  ret = rte_eth_dev_get_name_by_port(port_id, name);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "Cannot find TAP device: %s\n", rte_strerror(-ret));
  }
  printf("port=%u ether_name=%s\n", port_id, name);

  retval = rte_eth_dev_info_get(port_id, &dev_info);
  if (retval != 0) {
    printf("Error during getting device (port %u) info: %s\n", port_id,
           strerror(-retval));
    return retval;
  }

  // add map
  if (strcmp(dev_info.driver_name, "net_tap") == 0) {
    uint16_t nic_port = port_id - nb_ports / 2;

    if (port_map[nic_port] == NULL) {
      port_map[nic_port] = rte_zmalloc("port_map", sizeof(struct port_info),
                                       RTE_CACHE_LINE_SIZE);
      port_map[nic_port]->tap = port_id;
      port_map[nic_port]->nic = nic_port;
    }
  }

  if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
    port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

  /* Configure the Ethernet device. */
  retval = rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);
  if (retval != 0) return retval;

  retval = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
  if (retval != 0) return retval;

  /* Allocate and set up 1 RX queue per Ethernet port. */
  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(
        port_id, q, nb_rxd, rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
    if (retval < 0) return retval;
  }

  txconf          = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;

  /* Allocate and set up 1 TX queue per Ethernet port. */
  for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port_id, q, nb_txd,
                                    rte_eth_dev_socket_id(port_id), &txconf);
    if (retval < 0) return retval;
  }

  /* Start the Ethernet port. */
  retval = rte_eth_dev_start(port_id);
  if (retval < 0) return retval;

  if (enable_promis) {
    printf("enable promis mode\n");
    retval = rte_eth_promiscuous_enable(port_id);
    if (retval != 0) return retval;
  }

  return 0;
}

int main(int argc, char* argv[]) {
  struct rte_mempool*     mbuf_pool;
  uint16_t                portid;
  struct rte_eth_dev_info dev_info;
  enum rte_proc_type_t    proc_type;
  unsigned                i;

  /* Initialize the Environment Abstraction Layer (EAL). */
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

  /* Check that there is an even number of ports to send/receive on. */
  nb_ports = rte_eth_dev_count_avail();
  printf("available port number: %d\n", nb_ports);

  /* Creates a new mempool in memory to hold the mbufs. */
  mbuf_pool =
      rte_pktmbuf_pool_create(MBUF_NAME, NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE,
                              0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

  if (mbuf_pool == NULL) {
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
  }

  // 主进程创建内存池
  proc_type = rte_eal_process_type();
  printf("proc_type=%d\n", proc_type);
  memset(port_map, 0, sizeof(port_map));

  // 初始化port
  for (i = 0; i < nb_ports; ++i) {
    ret = port_init(i, mbuf_pool);
    if (ret != 0) {
      rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", i);
    }
  }

  // 打印物理网卡与Tap的映射关系
  for (i = 0; i < RTE_MAX_ETHPORTS; ++i) {
    struct port_info* p = port_map[i];
    if (p == NULL) {
      break;
    }

    printf("tap: %u port: %u\n", p->nic, p->tap);
  }

  rte_eal_mp_remote_launch(lcore_main, NULL, CALL_MAIN);
  RTE_LCORE_FOREACH_WORKER(i) {
    if (rte_eal_wait_lcore(i) < 0) return -1;
  }

  /* clean up the EAL */
  rte_eal_cleanup();

  return 0;
}
