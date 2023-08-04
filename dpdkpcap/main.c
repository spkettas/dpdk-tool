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
#include <assert.h>
#include <netinet/in.h>
#include <pcap.h>
#include <sys/socket.h>
#include "arp.h"
#include "rte_eal.h"

struct rte_ether_addr mac_addr;
uint16_t              port_id   = 0;
const char*           local_ip  = "192.168.100.38";
char*                 pcap_path = NULL;
uint32_t              max_size  = 0;  // max pkt size
pcap_t*               handle    = NULL;
pcap_dumper_t*        dumpfile  = NULL;  // pcap handle

static const struct rte_eth_conf port_conf_default = {
    .rxmode =
        {
            .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        },
};

static void print_usage(const char* prgname) {
  printf(
      "\nUsage: %s [EAL options] -- -h $localip -c 10 -w file.pcap "
      "    -h local ip\n"
      "    -c packet count\n"
      "    -w pcap file name\n",
      prgname);
}

static int parse_args(int argc, char** argv) {
  int                  opt, longindex, ret = 0;
  const char*          prgname    = argv[0];
  static struct option longopts[] = {{"host", required_argument, NULL, 0},
                                     {"write", required_argument, NULL, 0},
                                     {"count", required_argument, NULL, 0},
                                     {NULL, 0, NULL, 0}};

  /* Disable printing messages within getopt() */
  opterr = 0;

  /* Parse command line */
  while ((opt = getopt_long(argc, argv, "h:w:c:", longopts, &longindex)) !=
         EOF) {
    switch (opt) {
      case 'h':
        local_ip = optarg;
        break;
      case 'w':  // write
        pcap_path = optarg;
        break;
      case 'c':  // count
        max_size = strtoul(optarg, NULL, 10);
        break;
      default:
        print_usage(prgname);
        rte_exit(EXIT_FAILURE, "Invalid option specified\n");
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
    return 0;
  }

  return 1;
}

static void lcore_main(uint16_t port) {
  printf("Core %u forwarding packets\n", rte_lcore_id());
  uint16_t         i     = 0;
  uint32_t         count = 0;
  int              ret   = 0;
  uint16_t         nb_rx = 0;
  struct rte_mbuf* bufs[BURST_SIZE];
  int              quit_flag = 0;

  while (!quit_flag) {
    nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
    if (unlikely(nb_rx == 0)) {
      continue;
    }

    for (i = 0; i < nb_rx; i++) {
      char*    eth_hdr = rte_pktmbuf_mtod(bufs[i], char*);
      uint32_t pkt_len = rte_pktmbuf_pkt_len(bufs[i]);

      // send arp icmp response
      send_response(port, 0, &mac_addr, (char*)local_ip, bufs[i]);

      // flush to pcap
      ret = flush_flow(count++, (char*)eth_hdr, pkt_len);
      if (ret == 0) {
        quit_flag = 1;
        printf("INFO: get %u pkts and exit\n", count);
        break;
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

  int ret = rte_eal_init(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
  }

  argc -= ret;
  argv += ret;

  ret = parse_args(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "Could not parse input parameters\n");
  }

  nb_ports = rte_eth_dev_count_avail();
  printf("available port number: %d\n", nb_ports);

  nb_lcores = rte_lcore_count();
  printf("core number: %u\n", nb_lcores);

  rte_eth_macaddr_get(portid, &mac_addr);
  rte_ether_format_addr(mac_str, sizeof(mac_str), &mac_addr);
  printf("port %d mac %s\n", portid, mac_str);

  mbuf_pool = rte_pktmbuf_pool_create(
      "MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
      RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (mbuf_pool == NULL) {
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
  }

  if (port_init(portid, mbuf_pool) != 0) {
    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
  }

  port_id = portid;
  arp_table_init();
  lcore_main(portid);

  arp_table_cleanup();
  /* clean up the EAL */
  rte_eal_cleanup();

  return 0;
}
