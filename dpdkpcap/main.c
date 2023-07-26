/**
 * Copyright (c) 1998-2020  Inc. All rights reserved.
 *
 * @file main1.c
 * @author spkettas (spkettas@gmail.com)
 * @date 2023-07-22
 *
 * @brief 单核抓包示例
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <sys/socket.h>
#include "header.h"
#include "rte_eal.h"

struct rte_ether_addr ether_mac_addr;
uint16_t              our_port_id = 0;
const char*           local_ip    = "192.168.100.39";
char*                 pcap_path   = NULL;
uint32_t              max_size    = 0;  // max flow size
pcap_t*               handle      = NULL;
pcap_dumper_t*        dumpfile    = NULL;  // pcap handle

static const struct rte_eth_conf port_conf_default = {
    .rxmode =
        {
            .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        },
};

// print packet data
static void print_packet_data(struct rte_mbuf* mbuf) {
  uint8_t* data     = rte_pktmbuf_mtod(mbuf, uint8_t*);
  uint32_t data_len = rte_pktmbuf_data_len(mbuf);

  printf("recv:\n");
  uint32_t i;
  for (i = 0; i < data_len; i++) {
    printf("%02X ", data[i]);
    if ((i + 1) % 16 == 0) {
      printf("\n");
    }
  }

  printf("\n");
}

static int parse_args(int argc, char** argv) {
  int                  opt, longindex, ret = 0;
  const char*          prgname    = argv[0];
  static struct option longopts[] = {{"write", required_argument, NULL, 0},
                                     {"count", required_argument, NULL, 0},
                                     {NULL, 0, NULL, 0}};

  /* Disable printing messages within getopt() */
  opterr = 0;

  /* Parse command line */
  while ((opt = getopt_long(argc, argv, "w:c", longopts, &longindex)) != EOF) {
    switch (opt) {
      case 'w':
        pcap_path = optarg;
        break;
      case 'c':
        max_size = strtoul(optarg, NULL, 10);
        break;
      default:
        break;
    }
  }

  // init pcap
  if (pcap_path != NULL) {
    char path[128] = {};
    sprintf(path, "./%s", pcap_path);

    handle   = pcap_open_dead(DLT_EN10MB, 65535);
    dumpfile = pcap_dump_open(handle, path);
    assert(dumpfile != NULL);
  }

  return 0;
}

static int flush_flow(uint32_t count, char* data, uint32_t length) {
  struct timeval timestamp;

  if (dumpfile == NULL) {
    return 1;
  }

  gettimeofday(&timestamp, NULL);
  struct pcap_pkthdr header = {
      .ts     = timestamp,
      .caplen = length,
      .len    = length,
  };

  pcap_dump((u_char*)dumpfile, &header, (const u_char*)data);

  if (max_size > 0 && (++count >= max_size)) {
    pcap_dump_close(dumpfile);
    pcap_close(handle);
  }

  return 0;
}

static void handle_arp(struct rte_mbuf* pkt, struct rte_ether_hdr* eth_hdr) {
  struct in_addr ipv4_addr;
  inet_pton(AF_INET, local_ip, &ipv4_addr);
  uint32_t our_ip = ntohl(ipv4_addr.s_addr);

  // 获取arp头部
  struct rte_arp_hdr* arp_hdr = rte_pktmbuf_mtod_offset(
      pkt, struct rte_arp_hdr*, sizeof(struct rte_ether_hdr));

  printf("ARP_TYPE: %u\n", rte_be_to_cpu_16(arp_hdr->arp_opcode));

  if (rte_be_to_cpu_16(arp_hdr->arp_opcode) == RTE_ARP_OP_REQUEST) {
    struct in_addr in;
    in.s_addr = arp_hdr->arp_data.arp_tip;
    printf("who has %s\n", inet_ntoa(in));

    // Update ARP table with the sender's information
    arp_table_add(arp_hdr->arp_data.arp_sip, &arp_hdr->arp_data.arp_sha);

    // Check if the ARP request is for our IP
    if (arp_hdr->arp_data.arp_tip == rte_cpu_to_be_32(our_ip)) {
      // Prepare ARP reply
      arp_hdr->arp_opcode       = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
      arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;
      rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha,
                          &arp_hdr->arp_data.arp_tha);
      arp_hdr->arp_data.arp_sip = rte_cpu_to_be_32(our_ip);
      rte_ether_addr_copy(&ether_mac_addr, &arp_hdr->arp_data.arp_sha);

      // Update Ethernet header
      rte_ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
      rte_ether_addr_copy(&ether_mac_addr, &eth_hdr->s_addr);

      // Send ARP reply
      rte_eth_tx_burst(our_port_id, 0, &pkt, 1);
      printf("ARP reply sent\n");
      //   print_packet_data(pkt);
    }
  } else if (rte_be_to_cpu_16(arp_hdr->arp_opcode) == RTE_ARP_OP_REPLY) {
    // Update ARP table with the sender's information
    arp_table_add(arp_hdr->arp_data.arp_sip, &arp_hdr->arp_data.arp_sha);
  }
}

static void handle_icmp(struct rte_mbuf* pkt, struct rte_ether_hdr* eth_hdr,
                        struct rte_ipv4_hdr* ip_hdr) {
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
      rte_eth_tx_burst(our_port_id, 0, &pkt, 1);
      printf("ICMP reply sent\n");
      //   print_packet_data(pkt);
    }
  }
}

static __rte_noreturn void lcore_main(uint16_t port) {
  if (rte_eth_dev_socket_id(port) >= 0 &&
      rte_eth_dev_socket_id(port) != (int)rte_socket_id()) {
    printf(
        "WARNING, port %u is on remote NUMA node to "
        "polling thread.\n\tPerformance will "
        "not be optimal.\n",
        port);
  }

  printf("\nCore %u forwarding packets. \n", rte_lcore_id());
  struct rte_mbuf* bufs[BURST_SIZE];
  uint16_t         i     = 0;
  uint32_t         count = 0;
  int              ret   = 0;

  while (1) {
    /* Get burst of RX packets, from first port of pair. */
    const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

    if (unlikely(nb_rx == 0)) {
      continue;
    }

    for (i = 0; i < nb_rx; i++) {
      struct rte_ether_hdr* eth_hdr =
          rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr*);
      uint32_t pkt_len = rte_pktmbuf_pkt_len(bufs[i]);
      char*    cur_hdr = (char*)eth_hdr + sizeof(struct rte_ether_hdr);

      // flush to pcap
      ++count;
      ret = flush_flow(count, (char*)eth_hdr, pkt_len);
      if (ret == 2) {
        printf("get %u pkts\n", count);
        break;
      }

      if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_ARP) {
        handle_arp(bufs[i], eth_hdr);
      } else if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV4) {
        struct rte_ipv4_hdr* ip_hdr = rte_pktmbuf_mtod_offset(
            bufs[i], struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));

        if (ip_hdr->next_proto_id == IPPROTO_ICMP) {
          handle_icmp(bufs[i], eth_hdr, ip_hdr);
        }
      }
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
  unsigned                nb_lcores;
  uint16_t                portid;
  struct rte_eth_dev_info dev_info;

  /* Initialize the Environment Abstraction Layer (EAL). */
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

  argc -= ret;
  argv += ret;

  ret = parse_args(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "Could not parse input parameters\n");
  }

  /* Check that there is an even number of ports to send/receive on. */
  nb_ports = rte_eth_dev_count_avail();
  printf("available port number: %d\n", nb_ports);

  nb_lcores = rte_lcore_count();
  printf("core number: %u\n", nb_lcores);

  //   if (rte_eth_dev_get_port_by_name(pci_device_id, &portid) == 0) {

  // get ether mac addr
  rte_eth_macaddr_get(portid, &ether_mac_addr);
  rte_ether_format_addr(mac_str, sizeof(mac_str), &ether_mac_addr);
  printf("Port %d MAC: %s\n", portid, mac_str);

  /* Creates a new mempool in memory to hold the mbufs. */
  mbuf_pool = rte_pktmbuf_pool_create(
      "MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
      RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

  if (mbuf_pool == NULL) {
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
  }

  // 初始化port
  if (port_init(portid, mbuf_pool) != 0) {
    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
  }

  our_port_id = portid;
  arp_table_init();
  lcore_main(portid);

  arp_table_cleanup();
  /* clean up the EAL */
  rte_eal_cleanup();

  return 0;
}
