/**
 * Copyright (c) 1998-2020 gmail Inc. All rights reserved.
 *
 * @file simple.c
 * @author spkettas (spkettas@gmail.com)
 * @date 2023-07-28
 *
 * @brief kni测试程序（主进程），用来收包并写RING
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
#include "rte_common.h"
#include "rte_mbuf_core.h"
#include "rte_ring.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS       8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE      32

#define NB_MBUFS       64 * 1024 /* use 64k mbufs */
#define MBUF_NAME      "MBUF_POOL"
#define MSG_POOL       "MSG_POOL"
#define _SMP_MBUF_POOL "tcpip_queue"

// TODO 从配置中读取
#define LOCAL_IP1 644131008  // ip0="192.168.100.38"
#define LOCAL_IP2 650684608  // ip1="192.168.200.38"

struct rte_ether_addr ether_mac_addr;
unsigned              nb_ports;
struct rte_mempool*   message_pool;
struct rte_ring*      tcpip_ring;

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

static int lcore_main(__rte_unused void* arg) {
  printf("\nCore %u forwarding packets. \n", rte_lcore_id());
  struct rte_mbuf* bufs[BURST_SIZE];
  uint16_t         i = 0;
  uint16_t         port;
  uint16_t         nb_rx;

  while (1) {
    for (port = 0; port < nb_ports; ++port) {
      /* Get burst of RX packets, from first port of pair. */
      nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

      if (unlikely(nb_rx == 0)) {
        continue;
      }

      for (i = 0; i < nb_rx; i++) {
        // enqueue
        filter_pkt(port, bufs[i]);

        // parse pkt
        struct rte_ether_hdr* eth_hdr =
            rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr*);
        char* cur_hdr = (char*)eth_hdr + sizeof(struct rte_ether_hdr);

        if (eth_hdr->ether_type == rte_be_to_cpu_16(RTE_ETHER_TYPE_ARP)) {
          printf("port %u got arp\n", port);
        } else if (eth_hdr->ether_type ==
                   rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4)) {
          struct rte_ipv4_hdr* ip_hdr = rte_pktmbuf_mtod_offset(
              bufs[i], struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
          uint8_t ip_len = rte_ipv4_hdr_len(ip_hdr);
          cur_hdr += ip_len;

          if (ip_hdr->next_proto_id == IPPROTO_ICMP) {
            printf("port %u got icmp\n", port);
          } else if (ip_hdr->next_proto_id == IPPROTO_TCP) {
            struct rte_tcp_hdr* tcp = (struct rte_tcp_hdr*)cur_hdr;
            printf("port %u got tcp dport %u\n", port, htons(tcp->dst_port));
          } else if (ip_hdr->next_proto_id == IPPROTO_UDP) {
            struct rte_udp_hdr* udp = (struct rte_udp_hdr*)cur_hdr;
            printf("port %u got udp dport %u\n", port, htons(udp->dst_port));
          }
        } else if (eth_hdr->ether_type ==
                   rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV6)) {
          printf("port %u got ipv6\n", port);
        } else if (is_stp(cur_hdr)) {
          printf("port %u got stp\n", port);
        } else {
          printf("port %u other pkt 0x%x\n", port,
                 rte_be_to_cpu_16(eth_hdr->ether_type));
        }
      }
    }

    for (i = 0; i < nb_rx; i++) {
      rte_pktmbuf_free(bufs[i]);
    }
  }
}

static inline int port_init(uint16_t port, struct rte_mempool* mbuf_pool) {
  char                    mac_str[18];
  struct rte_eth_conf     port_conf = port_conf_default;
  const uint16_t          rx_rings = 1, tx_rings = 1;  // one queue
  uint16_t                nb_rxd = RX_RING_SIZE;
  uint16_t                nb_txd = TX_RING_SIZE;
  int                     retval;
  uint16_t                q;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_txconf   txconf;

  if (!rte_eth_dev_is_valid_port(port)) return -1;

  rte_eth_macaddr_get(port, &ether_mac_addr);
  rte_ether_format_addr(mac_str, sizeof(mac_str), &ether_mac_addr);
  printf("Port %d MAC %s\n", port, mac_str);

  retval = rte_eth_dev_info_get(port, &dev_info);
  if (retval != 0) {
    printf("Error during getting device (port %u) info: %s\n", port,
           strerror(-retval));
    return retval;
  }

  if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
    port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

  /* Configure the Ethernet device. */
  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
  if (retval != 0) return retval;

  retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
  if (retval != 0) return retval;

  /* Allocate and set up 1 RX queue per Ethernet port. */
  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(
        port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval < 0) return retval;
  }

  txconf          = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;
  /* Allocate and set up 1 TX queue per Ethernet port. */
  for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                    rte_eth_dev_socket_id(port), &txconf);
    if (retval < 0) return retval;
  }

  /* Start the Ethernet port. */
  retval = rte_eth_dev_start(port);
  if (retval < 0) return retval;

  /* Enable RX in promiscuous mode for the Ethernet device. */
  retval = rte_eth_promiscuous_enable(port);
  if (retval != 0) return retval;

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
  if (proc_type == RTE_PROC_PRIMARY) {
    message_pool =
        rte_mempool_create(MSG_POOL, 8192, sizeof(struct net_message), 32, 0,
                           NULL, NULL, NULL, NULL, rte_socket_id(), 0);

    // rte_ring_create(_SMP_MBUF_POOL, 4096, 0, RING_F_SP_ENQ | RING_F_SC_DEQ);
    tcpip_ring = rte_ring_create(_SMP_MBUF_POOL, 8192, 0,
                                 RING_F_MP_RTS_ENQ | RING_F_MC_RTS_DEQ);
    if (tcpip_ring == NULL) {
      rte_exit(EXIT_FAILURE, "Cannot get memory pool for buffers\n");
    }
  }

  // 初始化port
  for (i = 0; i < nb_ports; ++i) {
    if (port_init(i, mbuf_pool) != 0) {
      rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", i);
    }
  }

  if (rte_lcore_count() > 1) {
    printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");
  }

  rte_eal_mp_remote_launch(lcore_main, NULL, CALL_MAIN);
  RTE_LCORE_FOREACH_WORKER(i) {
    if (rte_eal_wait_lcore(i) < 0) return -1;
  }

  /* clean up the EAL */
  rte_eal_cleanup();

  return 0;
}
