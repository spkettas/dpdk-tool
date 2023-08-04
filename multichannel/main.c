/**
 * Copyright (c) 1998-2020  Inc. All rights reserved.
 *
 * @file main.c
 * @author spkettas (spkettas@gmail.com)
 * @date 2023-07-22
 *
 * @brief  多核收包示例
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "arp.h"
#include "rte_eal.h"

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = ETHER_MAX_LEN}};

unsigned              nb_ports;
static rte_atomic16_t queue = RTE_ATOMIC32_INIT(-1);
struct rte_ether_addr mac_addr;

static const char* get_ip(uint16_t port) {
  static const char* local_ip1 = "192.168.100.39";  // port 0
  static const char* local_ip2 = "192.168.200.39";  // port 1

  const char* local_ip = local_ip1;
  if (port == 1) {
    local_ip = local_ip2;
  }

  return local_ip;
}

static int16_t get_queue() { return rte_atomic16_add_return(&queue, 1); }

static inline int port_init(uint8_t port, struct rte_mempool* mbuf_pool) {
  struct rte_eth_conf port_conf = port_conf_default;
  char                mac_str[18];
  const uint16_t      rx_rings = rte_lcore_count();  // 核心数
  const uint16_t      tx_rings = rte_lcore_count();  // 核心数
  int                 retval;
  uint16_t            q;

  if (port >= rte_eth_dev_count_avail()) return -1;

  // mac
  rte_eth_macaddr_get(port, &mac_addr);
  rte_ether_format_addr(mac_str, sizeof(mac_str), &mac_addr);
  printf("port %d mac %s\n", port, mac_str);

  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
  if (retval != 0) return retval;

  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(
        port, q, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval < 0) return retval;
  }

  for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                                    rte_eth_dev_socket_id(port), NULL);
    if (retval < 0) return retval;
  }

  retval = rte_eth_dev_start(port);
  if (retval < 0) return retval;

  rte_eth_promiscuous_enable(port);

  return 0;
}

static int lcore_main(__rte_unused void* arg) {
  struct rte_mbuf* bufs[BURST_SIZE];
  uint16_t         nb_rx;
  uint16_t         port;
  uint16_t         queue_id;
  unsigned         i;
  char*            local_ip;

  // 每个核只读一个队列
  queue_id = get_queue();

  /*
   * Check that the port is on the same NUMA node as the polling thread
   * for best performance.
   */
  for (port = 0; port < nb_ports; port++)
    if (rte_eth_dev_socket_id(port) > 0 &&
        rte_eth_dev_socket_id(port) != (int)rte_socket_id())
      printf("WARNING, port %u is on socket %d\n", port,
             rte_eth_dev_socket_id(port));

  printf("Core %u queue %u receiving packets. [Ctrl+C to quit]\n",
         rte_lcore_id(), queue_id);

  /* Run */
  while (1) {
    for (port = 0; port < nb_ports; port++) {
      nb_rx = rte_eth_rx_burst(port, queue_id, bufs, BURST_SIZE);
      if (unlikely(nb_rx == 0)) continue;

      local_ip = (char*)get_ip(port);

      /* Process packets */
      for (i = 0; i < nb_rx; ++i) {
        send_response(port, queue_id, &mac_addr, local_ip, bufs[i]);
      }

      /* Free packets */
      for (i = 0; i < nb_rx; i++) {
        rte_pktmbuf_free(bufs[i]);
      }
    }
  }

  return 0;
}

int main(int argc, char* argv[]) {
  struct rte_mempool* mbuf_pool;
  uint8_t             portid;
  unsigned            nb_lcores;
  unsigned            lcore_id;

  int ret = rte_eal_init(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
  }

  nb_ports = rte_eth_dev_count_avail();
  printf("avail port number: %d\n", nb_ports);

  nb_lcores = rte_lcore_count();
  printf("core number: %u\n", nb_lcores);

  mbuf_pool =
      rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

  if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

  /* Initialize all ports. */
  RTE_ETH_FOREACH_DEV(portid)
  if (port_init(portid, mbuf_pool) != 0)
    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu8 "\n", portid);

  arp_table_init();

  /* Launch per-lcore function on every lcore */
  rte_eal_mp_remote_launch(lcore_main, NULL, CALL_MAIN);

  RTE_LCORE_FOREACH_WORKER(lcore_id) {
    if (rte_eal_wait_lcore(lcore_id) < 0) return -1;
  }

  // clean
  arp_table_cleanup();
  rte_eal_cleanup();

  return 0;
}
