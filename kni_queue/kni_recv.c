/**
 * Copyright (c) 1998-2020 gmail Inc. All rights reserved.
 *
 * @file kni_recv.c
 * @author spkettas (spkettas@gmail.com)
 * @date 2023-07-28
 *
 * @brief kni测试程序（子进程），用来消费RING并与虚拟网卡交互
 */
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_bus_pci.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_kni.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_ring.h>
#include <rte_string_fns.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "generic/rte_cycles.h"
#include "rte_ring_core.h"

/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

/* Max size of a single packet */
#define MAX_PACKET_SZ 2048

/* Size of the data buffer in each mbuf */
#define MBUF_DATA_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
#define NB_MBUF (8192 * 16)

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ 32

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ PKT_BURST_SZ

/* Number of RX ring descriptors */
#define NB_RXD 1024

/* Number of TX ring descriptors */
#define NB_TXD 1024

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE 14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE 4

#define KNI_MAX_KTHREAD 32
#define MSG_POOL        "MSG_POOL"
#define MBUF_NAME       "MBUF_POOL"
#define _SMP_MBUF_POOL  "tcpip_queue"

/*
 * Structure of port parameters
 */
struct kni_port_params {
  uint32_t        port_id; /* Port ID */
  uint32_t        nb_kni;  /* Number of KNI devices to be created */
  struct rte_kni* kni;
} __rte_cache_aligned;

struct net_message {
  struct rte_mbuf* mbuf;
  int64_t          port;
};

/* Options for configuring ethernet port */
static struct rte_eth_conf port_conf = {
    .txmode =
        {
            .mq_mode = ETH_MQ_TX_NONE,
        },
};

/* Mempool for mbufs */
static uint16_t                nb_ports;
static struct rte_mempool*     pktmbuf_pool = NULL;
static struct rte_mempool*     message_pool = NULL;
static struct rte_ring*        tcpip_ring;
static struct kni_port_params* kni_port_params_array[RTE_MAX_ETHPORTS];
static int                     promiscuous_on = 1;

/* Structure type for recording kni interface specific stats */
struct kni_interface_stats {
  /* number of pkts received from NIC, and sent to KNI */
  uint64_t rx_packets;

  /* number of pkts received from NIC, but failed to send to KNI */
  uint64_t rx_dropped;

  /* number of pkts received from KNI, and sent to NIC */
  uint64_t tx_packets;

  /* number of pkts received from KNI, but failed to send to NIC */
  uint64_t tx_dropped;
};

/* kni device statistics array */
static struct kni_interface_stats kni_stats[RTE_MAX_ETHPORTS];

static int kni_change_mtu(uint16_t port_id, unsigned int new_mtu);
static int kni_config_network_interface(uint16_t port_id, uint8_t if_up);
static int kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[]);

static rte_atomic32_t kni_stop  = RTE_ATOMIC32_INIT(0);
static rte_atomic32_t kni_pause = RTE_ATOMIC32_INIT(0);
static rte_atomic16_t queue     = RTE_ATOMIC32_INIT(-1);

static int16_t get_queue() { return rte_atomic16_add_return(&queue, 1); }

/* Print out statistics on packets handled */
static void print_stats(void) {
  uint16_t i;
  printf("\n");

  for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
    if (!kni_port_params_array[i]) continue;

    printf(
        "port=%d rx_pkt=%lu rx_drop=%lu tx_pkt=%lu tx_drop=%lu "
        "mem_pool=%d ring_pool=%d\n",
        i, kni_stats[i].rx_packets, kni_stats[i].rx_dropped,
        kni_stats[i].tx_packets, kni_stats[i].tx_dropped,
        rte_mempool_avail_count(message_pool), rte_ring_free_count(tcpip_ring));
  }

  printf("\n");
}

/* Custom handling of signals to handle stats and kni processing */
static void signal_handler(int signum) {
  /*
   * When we receive a RTMIN or SIGINT or SIGTERM signal,
   * stop kni processing
   */
  if (signum == SIGINT || signum == SIGTERM) {
    printf(
        "\nSIGRTMIN/SIGINT/SIGTERM received. "
        "KNI processing stopping.\n");
    rte_atomic32_inc(&kni_stop);
    return;
  }
}

static void kni_burst_free_mbufs(struct rte_mbuf** pkts, unsigned num) {
  unsigned i;

  if (pkts == NULL) return;

  for (i = 0; i < num; i++) {
    rte_pktmbuf_free(pkts[i]);
    pkts[i] = NULL;
  }
}

/**
 * Interface to burst rx and enqueue mbufs into rx_q
 */
static void kni_ingress() {
  uint8_t                 i;
  unsigned                ret, num;
  struct kni_port_params* p;
  struct net_message*     msg;
  struct rte_mbuf*        pkts_burst[PKT_BURST_SZ];

  /* Burst rx from ring */
  ret = rte_ring_mc_dequeue(tcpip_ring, (void**)&msg);

  /* Burst tx to kni */
  for (i = 0; i < nb_ports; ++i) {
    p = kni_port_params_array[i];
    if (p == NULL) return;

    if (ret == 0 && i == msg->port) {  // 有数据
      printf("recv queue port %lu len %u\n", msg->port,
             rte_pktmbuf_data_len(msg->mbuf));

      pkts_burst[0] = msg->mbuf;
      num           = rte_kni_tx_burst(p->kni, pkts_burst, 1);
      if (num > 0) {
        kni_stats[i].rx_packets += num;
      } else {
        kni_burst_free_mbufs(&pkts_burst[num], 1);
        kni_stats[i].rx_dropped += 1;
      }

      rte_kni_handle_request(p->kni);
      rte_mempool_put(message_pool, msg);
    } else {  // 无数据
      rte_kni_tx_burst(p->kni, NULL, 0);

      // 未收到包时也要执行kni handler，避免: RTNETLINK answers: Timer expired
      rte_kni_handle_request(p->kni);
    }
  }
}

/**
 * Interface to dequeue mbufs from tx_q and burst tx
 */
static void kni_egress() {
  uint8_t                 i;
  unsigned                nb_tx, num;
  struct kni_port_params* p;
  struct rte_mbuf*        pkts_burst[PKT_BURST_SZ];

  for (i = 0; i < nb_ports; ++i) {
    p = kni_port_params_array[i];
    if (p == NULL) return;

    /* Burst rx from kni */
    num = rte_kni_rx_burst(p->kni, pkts_burst, PKT_BURST_SZ);
    if (unlikely(num > PKT_BURST_SZ)) {
      RTE_LOG(ERR, APP, "Error receiving from KNI\n");
      continue;
    }

    if (num) printf("recv kni port %u num %u\n", p->port_id, num);

    /* Burst tx to eth */
    nb_tx = rte_eth_tx_burst(p->port_id, 0, pkts_burst, (uint16_t)num);
    if (nb_tx) kni_stats[p->port_id].tx_packets += nb_tx;

    if (unlikely(nb_tx < num)) {
      /* Free mbufs not tx to NIC */
      kni_burst_free_mbufs(&pkts_burst[nb_tx], num - nb_tx);
      kni_stats[p->port_id].tx_dropped += num - nb_tx;
    }
  }
}

static int lcore_main(__rte_unused void* arg) {
  uint16_t       i;
  int32_t        f_stop;
  int32_t        f_pause;
  const unsigned lcore_id = rte_lcore_id();
  int16_t        flag     = get_queue();

  if (flag == 0) {  // rx
    RTE_LOG(INFO, APP, "Lcore %u is reading from port\n", lcore_id);
    while (1) {
      f_stop  = rte_atomic32_read(&kni_stop);
      f_pause = rte_atomic32_read(&kni_pause);
      if (f_stop) break;
      if (f_pause) continue;

      kni_ingress();
    }
  } else if (flag == 1) {  // tx
    RTE_LOG(INFO, APP, "Lcore %u is writing to port\n", lcore_id);
    while (1) {
      f_stop  = rte_atomic32_read(&kni_stop);
      f_pause = rte_atomic32_read(&kni_pause);
      if (f_stop) break;
      if (f_pause) continue;

      kni_egress();
    }
  } else {  // nothing
    RTE_LOG(INFO, APP, "Lcore %u has nothing to do\n", lcore_id);
  }

  RTE_LOG(INFO, APP, "Lcore %u exit\n", lcore_id);
  return 0;
}

static void* monitor_all_ports_link_status(void* arg) {
  int32_t        f_stop;
  uint32_t       i;
  char           eth_name[32];
  char           cmd[128];
  uint64_t       tsc;
  uint64_t       tsc_last = rte_get_tsc_cycles();
  const uint64_t period   = rte_get_tsc_hz() * 60;

  // sleep(2);
  printf("set kni port ip\n");

  // set kni ip
  for (i = 0; i < nb_ports; ++i) {
    // system("ifconfig vEth0 192.168.100.38/24 up");
    sprintf(eth_name, "vEth%u", i);

    sprintf(cmd, "ip addr add 192.168.%d00.38/24 dev %s", i + 1, eth_name);
    system(cmd);

    sprintf(cmd, "ip link set %s up", eth_name);
    system(cmd);
  }

  // show statistic
  while (1) {
    tsc    = rte_get_tsc_cycles();
    f_stop = rte_atomic32_read(&kni_stop);
    if (f_stop) break;

    if ((tsc - tsc_last) >= period) {
      tsc_last = tsc;

      // TODO 存在同步问题，建议加锁
      memset(&kni_stats, 0, sizeof(kni_stats));
    }

    print_stats();
    rte_delay_ms(2000);
  }

  printf("lcore monitor exit\n");
  return NULL;
}

/* Display usage instructions */
static void print_usage(const char* prgname) {
  RTE_LOG(INFO, APP,
          "\nUsage: %s [EAL options] -- -p PORTMASK -P -m "
          "[--config (port,lcore_rx,lcore_tx,lcore_kthread...)"
          "[,(port,lcore_rx,lcore_tx,lcore_kthread...)]]\n"
          "    -p PORTMASK: hex bitmask of ports to use\n"
          "    -P : enable promiscuous mode\n"
          "    -m : enable monitoring of port carrier state\n"
          "    --config (port,lcore_rx,lcore_tx,lcore_kthread...): "
          "port and lcore configurations\n",
          prgname);
}

/* Initialize KNI subsystem */
static void init_kni(void) {
  unsigned int             num_of_kni_ports = 0, i;
  struct kni_port_params** params           = kni_port_params_array;

  /* Calculate the maximum number of KNI interfaces that will be used */
  for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
    if (kni_port_params_array[i]) {
      num_of_kni_ports += params[i]->nb_kni;
    }
  }

  /* Invoke rte KNI init to preallocate the ports */
  rte_kni_init(num_of_kni_ports);
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint32_t port_mask) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
  uint16_t            portid;
  uint8_t             count, all_ports_up, print_flag = 0;
  struct rte_eth_link link;
  int                 ret;
  char                link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

  printf("\nChecking link status\n");
  fflush(stdout);
  for (count = 0; count <= MAX_CHECK_TIME; count++) {
    all_ports_up = 1;
    RTE_ETH_FOREACH_DEV(portid) {
      if ((port_mask & (1 << portid)) == 0) continue;
      memset(&link, 0, sizeof(link));
      ret = rte_eth_link_get_nowait(portid, &link);
      if (ret < 0) {
        all_ports_up = 0;
        if (print_flag == 1)
          printf("Port %u link get failed: %s\n", portid, rte_strerror(-ret));
        continue;
      }
      /* print link status if flag set */
      if (print_flag == 1) {
        rte_eth_link_to_str(link_status_text, sizeof(link_status_text), &link);
        printf("Port %d %s\n", portid, link_status_text);
        continue;
      }
      /* clear all_ports_up flag if any link down */
      if (link.link_status == ETH_LINK_DOWN) {
        all_ports_up = 0;
        break;
      }
    }
    /* after finally printing all link status, get out */
    if (print_flag == 1) break;

    if (all_ports_up == 0) {
      printf(".");
      fflush(stdout);
      rte_delay_ms(CHECK_INTERVAL);
    }

    /* set the print_flag if all ports up or timeout */
    if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
      print_flag = 1;
      printf("done\n");
    }
  }
}

static void log_link_state(struct rte_kni* kni, int prev,
                           struct rte_eth_link* link) {
  char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];
  if (kni == NULL || link == NULL) return;

  rte_eth_link_to_str(link_status_text, sizeof(link_status_text), link);
  if (prev != link->link_status)
    RTE_LOG(INFO, APP, "%s NIC %s\n", rte_kni_get_name(kni), link_status_text);
}

static int kni_change_mtu_(uint16_t port_id, unsigned int new_mtu) {
  int                     ret;
  uint16_t                nb_rxd = NB_RXD;
  uint16_t                nb_txd = NB_TXD;
  struct rte_eth_conf     conf;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_rxconf   rxq_conf;
  struct rte_eth_txconf   txq_conf;

  if (!rte_eth_dev_is_valid_port(port_id)) {
    RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
    return -EINVAL;
  }

  RTE_LOG(INFO, APP, "Change MTU of port %d to %u\n", port_id, new_mtu);

  /* Stop specific port */
  ret = rte_eth_dev_stop(port_id);
  if (ret != 0) {
    RTE_LOG(ERR, APP, "Failed to stop port %d: %s\n", port_id,
            rte_strerror(-ret));
    return ret;
  }

  memcpy(&conf, &port_conf, sizeof(conf));
  /* Set new MTU */
  if (new_mtu > RTE_ETHER_MAX_LEN)
    conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
  else
    conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_JUMBO_FRAME;

  /* mtu + length of header + length of FCS = max pkt length */
  conf.rxmode.max_rx_pkt_len =
      new_mtu + KNI_ENET_HEADER_SIZE + KNI_ENET_FCS_SIZE;
  ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
  if (ret < 0) {
    RTE_LOG(ERR, APP, "Fail to reconfigure port %d\n", port_id);
    return ret;
  }

  ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
  if (ret < 0)
    rte_exit(EXIT_FAILURE,
             "Could not adjust number of descriptors "
             "for port%u (%d)\n",
             (unsigned int)port_id, ret);

  ret = rte_eth_dev_info_get(port_id, &dev_info);
  if (ret != 0) {
    RTE_LOG(ERR, APP, "Error during getting device (port %u) info: %s\n",
            port_id, strerror(-ret));

    return ret;
  }

  rxq_conf          = dev_info.default_rxconf;
  rxq_conf.offloads = conf.rxmode.offloads;
  ret =
      rte_eth_rx_queue_setup(port_id, 0, nb_rxd, rte_eth_dev_socket_id(port_id),
                             &rxq_conf, pktmbuf_pool);
  if (ret < 0) {
    RTE_LOG(ERR, APP, "Fail to setup Rx queue of port %d\n", port_id);
    return ret;
  }

  txq_conf          = dev_info.default_txconf;
  txq_conf.offloads = conf.txmode.offloads;
  ret               = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
                                             rte_eth_dev_socket_id(port_id), &txq_conf);
  if (ret < 0) {
    RTE_LOG(ERR, APP, "Fail to setup Tx queue of port %d\n", port_id);
    return ret;
  }

  /* Restart specific port */
  ret = rte_eth_dev_start(port_id);
  if (ret < 0) {
    RTE_LOG(ERR, APP, "Fail to restart port %d\n", port_id);
    return ret;
  }

  return 0;
}

/* Callback for request of changing MTU */
static int kni_change_mtu(uint16_t port_id, unsigned int new_mtu) {
  int ret;

  rte_atomic32_inc(&kni_pause);
  ret = kni_change_mtu_(port_id, new_mtu);
  rte_atomic32_dec(&kni_pause);

  return ret;
}

/* Callback for request of configuring network interface up/down */
static int kni_config_network_interface(uint16_t port_id, uint8_t if_up) {
  int ret = 0;

  if (!rte_eth_dev_is_valid_port(port_id)) {
    RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
    return -EINVAL;
  }

  RTE_LOG(INFO, APP, "Configure network interface of %d %s\n", port_id,
          if_up ? "up" : "down");

  rte_atomic32_inc(&kni_pause);
  ret = (if_up) ? rte_eth_dev_set_link_up(port_id)
                : rte_eth_dev_set_link_down(port_id);
  rte_atomic32_dec(&kni_pause);

  return ret;
}

static void print_ethaddr(const char* name, struct rte_ether_addr* mac_addr) {
  char buf[RTE_ETHER_ADDR_FMT_SIZE];
  rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, mac_addr);
  RTE_LOG(INFO, APP, "\t%s%s\n", name, buf);
}

/* Callback for request of configuring mac address */
static int kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[]) {
  int ret = 0;

  if (!rte_eth_dev_is_valid_port(port_id)) {
    RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
    return -EINVAL;
  }

  RTE_LOG(INFO, APP, "Configure mac address of %d\n", port_id);
  print_ethaddr("Address:", (struct rte_ether_addr*)mac_addr);

  ret = rte_eth_dev_default_mac_addr_set(port_id,
                                         (struct rte_ether_addr*)mac_addr);
  if (ret < 0)
    RTE_LOG(ERR, APP, "Failed to config mac_addr for port %d\n", port_id);

  return ret;
}

static int kni_alloc(uint16_t port_id) {
  struct rte_kni*         kni;
  struct rte_kni_conf     conf;
  struct rte_kni_ops      ops;
  struct rte_eth_dev_info dev_info;
  struct kni_port_params* p;
  int                     ret;

  p = kni_port_params_array[port_id];
  if (port_id >= RTE_MAX_ETHPORTS || !p) return -1;

  p->port_id = port_id;
  p->nb_kni  = 1;
  p->kni     = NULL;

  /* Clear conf at first */
  memset(&conf, 0, sizeof(conf));
  snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", port_id);

  ret = rte_eth_dev_info_get(port_id, &dev_info);
  if (ret != 0) {
    rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n",
             port_id, strerror(-ret));
  }

  /* Get the interface default mac address */
  ret = rte_eth_macaddr_get(port_id, (struct rte_ether_addr*)&conf.mac_addr);
  if (ret != 0)
    rte_exit(EXIT_FAILURE, "Failed to get MAC address (port %u): %s\n", port_id,
             rte_strerror(-ret));

  rte_eth_dev_get_mtu(port_id, &conf.mtu);

  conf.group_id  = port_id;
  conf.mbuf_size = MAX_PACKET_SZ;
  conf.min_mtu   = dev_info.min_mtu;
  conf.max_mtu   = dev_info.max_mtu;

  memset(&ops, 0, sizeof(ops));
  ops.port_id = port_id;
  // ops.change_mtu         = kni_change_mtu;
  // ops.config_network_if  = kni_config_network_interface;
  ops.config_mac_address = kni_config_mac_address;
  ops.change_mtu         = rte_eth_dev_set_mtu;
  ops.config_network_if  = kni_config_network_interface;

  kni = rte_kni_alloc(pktmbuf_pool, &conf, &ops);
  if (!kni) {
    rte_exit(EXIT_FAILURE, "Fail to create kni for port: %d\n", port_id);
  }

  p->kni = kni;

  return 0;
}

static int kni_free_kni(uint16_t port_id) {
  uint8_t                  i;
  int                      ret;
  struct kni_port_params** p = kni_port_params_array;

  printf("free kni port %u\n", port_id);
  if (port_id >= RTE_MAX_ETHPORTS || !p[port_id]) return -1;

  if (rte_kni_release(p[port_id]->kni)) {
    printf("Fail to release kni\n");
  }

  p[port_id]->kni = NULL;

  // oops: 不能在子进程中关闭端口，会影响主进程收包
  // ret = rte_eth_dev_stop(port_id);
  return 0;
}

/* Initialise ports/queues etc. and start main loop on each core */
int main(int argc, char** argv) {
  int       ret;
  uint16_t  port;
  unsigned  i, j;
  void*     retval;
  pthread_t kni_link_tid;
  int       pid;

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  /* Initialise EAL */
  ret = rte_eal_init(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "Could not initialise EAL (%d)\n", ret);
  }

  /* Get number of ports found in scan */
  nb_ports = rte_eth_dev_count_avail();
  if (nb_ports == 0) {
    rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");
  }

  // 子进程共享内存
  if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
    tcpip_ring   = rte_ring_lookup(_SMP_MBUF_POOL);
    pktmbuf_pool = rte_mempool_lookup(MBUF_NAME);
    message_pool = rte_mempool_lookup(MSG_POOL);
  } else {
    rte_exit(EXIT_FAILURE, "Please startup by secondary");
  }

  /* Check if the configured port ID is valid */
  for (i = 0; i < RTE_MAX_ETHPORTS; i++)
    if (kni_port_params_array[i] && !rte_eth_dev_is_valid_port(i))
      rte_exit(EXIT_FAILURE,
               "Configured invalid "
               "port ID %u\n",
               i);

  /* Initialize KNI subsystem */
  init_kni();

  memset(&kni_port_params_array, 0, sizeof(kni_port_params_array));

  /* Initialise each port */
  for (port = 0; port < nb_ports; ++port) {
    // init_port(port);

    if (port >= RTE_MAX_ETHPORTS)
      rte_exit(EXIT_FAILURE, "Can not use more than %d ports for kni\n",
               RTE_MAX_ETHPORTS);

    kni_port_params_array[port] = rte_zmalloc(
        "KNI_port_params", sizeof(struct kni_port_params), RTE_CACHE_LINE_SIZE);

    kni_alloc(port);
  }
  //   check_all_ports_link_status(ports_mask);

  ret = rte_ctrl_thread_create(&kni_link_tid, "set kni ip", NULL,
                               monitor_all_ports_link_status, NULL);
  if (ret < 0) rte_exit(EXIT_FAILURE, "Could not create link status thread!\n");

  /* Launch per-lcore function on every lcore */
  rte_eal_mp_remote_launch(lcore_main, NULL, CALL_MAIN);
  RTE_LCORE_FOREACH_WORKER(i) {
    if (rte_eal_wait_lcore(i) < 0) return -1;
  }
  pthread_join(kni_link_tid, &retval);

  /* Release resources */
  for (port = 0; port < nb_ports; ++port) {
    kni_free_kni(port);
  }

  for (i = 0; i < RTE_MAX_ETHPORTS; i++)
    if (kni_port_params_array[i]) {
      rte_free(kni_port_params_array[i]);
      kni_port_params_array[i] = NULL;
    }

  /* clean up the EAL */
  rte_eal_cleanup();

  return 0;
}
