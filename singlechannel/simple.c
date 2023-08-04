/**
 * Copyright (c) 1998-2020  Inc. All rights reserved.
 *
 * @file main1.c
 * @author spkettas (spkettas@gmail.com)
 * @date 2023-07-22
 *
 * @brief 单核收包示例
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
#include "header.h"

#define MBUF_CACHE_SIZE 250
#define BURST_SIZE      32

#define MAX_ARP_ENTRIES   1024
#define ARP_ENTRY_TIMEOUT 300

struct rte_ether_addr ether_mac_addr;
uint16_t              our_port_id = 0;

static const struct rte_eth_conf port_conf_default = {
    .rxmode =
        {
            .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        },
};

static __rte_noreturn void lcore_main(uint16_t port) {
  if (rte_eth_dev_socket_id(port) >= 0 &&
      rte_eth_dev_socket_id(port) != (int)rte_socket_id())
    printf(
        "WARNING, port %u is on remote NUMA node to "
        "polling thread.\n\tPerformance will "
        "not be optimal.\n",
        port);

  printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());
  struct rte_mbuf* bufs[BURST_SIZE];
  uint16_t         i = 0;

  while (1) {
    /* Get burst of RX packets, from first port of pair. */
    const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

    if (unlikely(nb_rx == 0)) {
      continue;
    }

    for (i = 0; i < nb_rx; i++) {
      // print packet info
      show_pktinfo(port, bufs[i]);
    }

    for (i = 0; i < nb_rx; i++) {
      rte_pktmbuf_free(bufs[i]);
    }
  }
}

static inline int port_init(uint16_t port, struct rte_mempool* mbuf_pool) {
  struct rte_eth_conf     port_conf = port_conf_default;
  const uint16_t          rx_rings = 1, tx_rings = 1;
  uint16_t                nb_rxd = RX_RING_SIZE;
  uint16_t                nb_txd = TX_RING_SIZE;
  int                     retval;
  uint16_t                q;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_txconf   txconf;

  if (!rte_eth_dev_is_valid_port(port)) return -1;

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
  char                    mac_str[18];
  struct rte_mempool*     mbuf_pool;
  unsigned                nb_ports;
  uint16_t                portid;
  struct rte_eth_dev_info dev_info;

  /* Initialize the Environment Abstraction Layer (EAL). */
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

  argc -= ret;
  argv += ret;

  /* Check that there is an even number of ports to send/receive on. */
  nb_ports = rte_eth_dev_count_avail();
  printf("available port number: %d\n", nb_ports);

  // 获取指定网卡的MAC地址
  rte_eth_macaddr_get(portid, &ether_mac_addr);
  rte_ether_format_addr(mac_str, sizeof(mac_str), &ether_mac_addr);
  printf("Port %d MAC地址: %s\n", portid, mac_str);

  /* Creates a new mempool in memory to hold the mbufs. */
  mbuf_pool = rte_pktmbuf_pool_create(
      "MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
      RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

  if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

  // 初始化port
  if (port_init(portid, mbuf_pool) != 0)
    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);

  if (rte_lcore_count() > 1)
    printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

  our_port_id = portid;
  lcore_main(portid);

  /* clean up the EAL */
  rte_eal_cleanup();

  return 0;
}
