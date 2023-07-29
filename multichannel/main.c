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
#include "header.h"
#include "rte_eal.h"

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = ETHER_MAX_LEN}};

unsigned              nb_ports;
static rte_atomic16_t queue = RTE_ATOMIC32_INIT(-1);
struct rte_ether_addr ether_mac_addr;

static int16_t get_queue() { return rte_atomic16_add_return(&queue, 1); }

static uint32_t get_ip(uint16_t port) {
  static const char* local_ip1 = "192.168.100.39";  // port 0
  static const char* local_ip2 = "192.168.100.40";  // port 1
  struct in_addr     ipv4_addr;
  const char*        local_ip = local_ip1;
  if (port == 1) {
    local_ip = local_ip2;
  }

  inet_pton(AF_INET, local_ip, &ipv4_addr);
  return ipv4_addr.s_addr;
}

static void handle_arp(uint16_t port, uint16_t queue, struct rte_mbuf* pkt,
                       struct rte_ether_hdr* eth_hdr) {
  uint32_t            our_ip  = get_ip(port);
  struct rte_arp_hdr* arp_hdr = rte_pktmbuf_mtod_offset(
      pkt, struct rte_arp_hdr*, sizeof(struct rte_ether_hdr));

  printf("port: %u ARP_TYPE: %u\n", port,
         rte_be_to_cpu_16(arp_hdr->arp_opcode));

  if (rte_be_to_cpu_16(arp_hdr->arp_opcode) == RTE_ARP_OP_REQUEST) {
    struct in_addr in;
    in.s_addr = arp_hdr->arp_data.arp_tip;
    printf("port: %u who has %s\n", port, inet_ntoa(in));

    // Update ARP table with the sender's information
    arp_table_add(arp_hdr->arp_data.arp_sip, &arp_hdr->arp_data.arp_sha);

    // Check if the ARP request is for our IP
    if (arp_hdr->arp_data.arp_tip == our_ip) {
      // Prepare ARP reply
      arp_hdr->arp_opcode       = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
      arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;
      rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha,
                          &arp_hdr->arp_data.arp_tha);
      arp_hdr->arp_data.arp_sip = our_ip;
      rte_ether_addr_copy(&ether_mac_addr, &arp_hdr->arp_data.arp_sha);

      // Update Ethernet header
      rte_ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
      rte_ether_addr_copy(&ether_mac_addr, &eth_hdr->s_addr);

      // Send ARP reply
      rte_eth_tx_burst(port, queue, &pkt, 1);
      printf("ARP reply sent\n");
      //   print_packet_data(pkt);
    }
  } else if (rte_be_to_cpu_16(arp_hdr->arp_opcode) == RTE_ARP_OP_REPLY) {
    // Update ARP table with the sender's information
    arp_table_add(arp_hdr->arp_data.arp_sip, &arp_hdr->arp_data.arp_sha);
  }
}

static void handle_icmp(uint16_t port, uint16_t queue, struct rte_mbuf* pkt,
                        struct rte_ether_hdr* eth_hdr,
                        struct rte_ipv4_hdr*  ip_hdr) {
  struct rte_icmp_hdr* icmp_hdr = rte_pktmbuf_mtod_offset(
      pkt, struct rte_icmp_hdr*,
      sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

  if (icmp_hdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
    // Prepare ICMP echo reply
    icmp_hdr->icmp_type  = RTE_IP_ICMP_ECHO_REPLY;
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = rte_ipv4_icmp_cksum(ip_hdr, icmp_hdr);

    // Update IP header
    uint32_t tmp_ip      = ip_hdr->src_addr;
    ip_hdr->src_addr     = ip_hdr->dst_addr;
    ip_hdr->dst_addr     = tmp_ip;
    ip_hdr->hdr_checksum = 0;
    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

    // Update Ethernet header
    struct rte_ether_addr* dst_mac = arp_table_lookup(tmp_ip);
    if (dst_mac) {
      rte_ether_addr_copy(&eth_hdr->d_addr, &eth_hdr->s_addr);
      rte_ether_addr_copy(dst_mac, &eth_hdr->d_addr);

      // Send ICMP echo reply
      rte_eth_tx_burst(port, queue, &pkt, 1);
      printf("ICMP reply sent\n");
      //   print_packet_data(pkt);
    }
  }
}

static void handle_packet(uint16_t port, uint16_t queue, struct rte_mbuf* buf) {
  //   print_packet_data(bufs[i]);

  struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr*);
  uint32_t              pkt_len = rte_pktmbuf_pkt_len(buf);
  char*                 cur_hdr = (char*)eth_hdr + sizeof(struct rte_ether_hdr);
  // printf("protocol len=%u\n", pkt_len);

  if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_ARP) {
    printf("got arp \n");
    handle_arp(port, queue, buf, eth_hdr);
  } else if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV4) {
    struct rte_ipv4_hdr* ip_hdr = rte_pktmbuf_mtod_offset(
        buf, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));

    uint16_t id     = htons(ip_hdr->packet_id);
    uint16_t ip_len = (ip_hdr->version_ihl & 0x0f) * RTE_IPV4_IHL_MULTIPLIER;
    cur_hdr += ip_len;

    if (ip_hdr->next_proto_id == IPPROTO_ICMP) {
      printf("got icmp id %u\n", id);
      handle_icmp(port, queue, buf, eth_hdr, ip_hdr);
    } else if (ip_hdr->next_proto_id == IPPROTO_TCP) {
      struct rte_tcp_hdr* tcp = (struct rte_tcp_hdr*)cur_hdr;
      printf("got tcp dport %u id %u\n", htons(tcp->dst_port), id);
    } else if (ip_hdr->next_proto_id == IPPROTO_UDP) {
      struct rte_udp_hdr* udp = (struct rte_udp_hdr*)cur_hdr;
      printf("got udp dport %u id %u\n", htons(udp->dst_port), id);
    }
  } else {
    printf("other pkt 0x%x\n", rte_be_to_cpu_16(eth_hdr->ether_type));
  }
}

static inline int port_init(uint8_t port, struct rte_mempool* mbuf_pool) {
  struct rte_eth_conf port_conf = port_conf_default;
  char                mac_str[18];
  const uint16_t      rx_rings = rte_lcore_count();  // 核心数
  const uint16_t      tx_rings = rte_lcore_count();  // 核心数
  int                 retval;
  uint16_t            q;

  if (port >= rte_eth_dev_count_avail()) return -1;

  // mac
  rte_eth_macaddr_get(port, &ether_mac_addr);
  rte_ether_format_addr(mac_str, sizeof(mac_str), &ether_mac_addr);
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

      /* Process packets */
      for (i = 0; i < nb_rx; ++i) {
        handle_packet(port, queue_id, bufs[i]);
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
