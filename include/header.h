/**
 * Copyright (c) 1998-2020  Inc. All rights reserved.
 *
 * @file header.h
 * @author spkettas (spkettas@gmail.com)
 * @date 2023-07-22
 *
 * @brief  公共函数
 */
#pragma once

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_interrupts.h>
#include <rte_jhash.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_random.h>
#include "generic/rte_atomic.h"

#define RX_RING_SIZE      128
#define TX_RING_SIZE      512
#define NUM_MBUFS         ((64 * 1024) - 1)
#define MBUF_CACHE_SIZE   250
#define BURST_SIZE        32
#define MAX_ARP_ENTRIES   1024
#define ARP_ENTRY_TIMEOUT 300

struct arp_entry {
  uint32_t              ip;
  struct rte_ether_addr mac;
  uint64_t              last_update;
};

struct arp_table {
  struct rte_hash* hash;
  struct arp_entry entries[MAX_ARP_ENTRIES];
};

static struct arp_table arp_table;

// print hex data
static void print_data(struct rte_mbuf* mbuf);
// show packet info
static void show_pktinfo(uint16_t port, struct rte_mbuf* mbuf);
// check stp
static int is_stp(const char* hdr);

void print_data(struct rte_mbuf* mbuf) {
  uint32_t i;
  uint8_t* data     = rte_pktmbuf_mtod(mbuf, uint8_t*);
  uint32_t data_len = rte_pktmbuf_data_len(mbuf);

  for (i = 0; i < data_len; i++) {
    printf("%02X ", data[i]);
    if ((i + 1) % 16 == 0) {
      printf("\n");
    }
  }

  printf("\n");
}

static void arp_table_init(void) {
  struct rte_hash_parameters hash_params = {
      .name               = "arp_table",
      .entries            = MAX_ARP_ENTRIES,
      .key_len            = sizeof(uint32_t),
      .hash_func          = rte_jhash,
      .hash_func_init_val = 0,
      .socket_id          = (int)rte_socket_id(),
  };

  arp_table.hash = rte_hash_create(&hash_params);
  if (!arp_table.hash) {
    rte_exit(EXIT_FAILURE, "Failed to create ARP table hash\n");
  }
}

static void arp_table_add(uint32_t ip, struct rte_ether_addr* mac) {
  int32_t index = rte_hash_add_key(arp_table.hash, &ip);
  if (index >= 0) {
    arp_table.entries[index].ip = ip;
    rte_ether_addr_copy(mac, &arp_table.entries[index].mac);
    arp_table.entries[index].last_update = rte_get_timer_cycles();
  }
}

static struct rte_ether_addr* arp_table_lookup(uint32_t ip) {
  int32_t index = rte_hash_lookup(arp_table.hash, &ip);
  if (index >= 0) {
    return &arp_table.entries[index].mac;
  }

  return NULL;
}

static void arp_table_cleanup(void) {
  uint64_t now            = rte_get_timer_cycles();
  uint64_t timeout_cycles = rte_get_timer_hz() * ARP_ENTRY_TIMEOUT;
  int      i;

  for (i = 0; i < MAX_ARP_ENTRIES; i++) {
    if (arp_table.entries[i].ip != 0 &&
        now - arp_table.entries[i].last_update > timeout_cycles) {
      rte_hash_del_key(arp_table.hash, &arp_table.entries[i].ip);
      arp_table.entries[i].ip = 0;
    }
  }
}

static inline uint16_t rte_ipv4_icmp_cksum(const struct rte_ipv4_hdr* ipv4_hdr,
                                           const void*                l4_hdr) {
  uint32_t cksum;
  uint32_t l3_len, l4_len;
  uint8_t  ip_hdr_len;

  // ip_hdr_len = rte_ipv4_hdr_len(ipv4_hdr);
  ip_hdr_len =
      (ipv4_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;
  l3_len = rte_be_to_cpu_16(ipv4_hdr->total_length);
  if (l3_len < ip_hdr_len) return 0;

  l4_len = l3_len - ip_hdr_len;

  cksum = rte_raw_cksum(l4_hdr, l4_len);

  cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
  cksum = (~cksum) & 0xffff;

  return (uint16_t)cksum;
}

uint16_t icmp_checksum(uint8_t* buf, uint16_t len) {
  uint32_t sum = 0;
  uint32_t i   = 0;
  for (i = 0; i < len; i++) {
    printf("%02x ", buf[i]);
  }
  printf("\n");

  for (i = 0; i < len; i += 2) {
    uint16_t word = (buf[i] << 8) + (i + 1 < len ? buf[i + 1] : 0);
    sum += word;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return (uint16_t)(~sum);
}

int is_stp(const char* hdr) { return (hdr[0] == 0x42 && hdr[1] == 0x42); }

void show_pktinfo(uint16_t port, struct rte_mbuf* mbuf) {
  struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
  char*                 cur_hdr = (char*)eth_hdr + sizeof(struct rte_ether_hdr);

  if (eth_hdr->ether_type == rte_be_to_cpu_16(RTE_ETHER_TYPE_ARP)) {  // arp
    printf("port %u got arp\n", port);
  } else if (eth_hdr->ether_type ==
             rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4)) {  // ipv4
    struct rte_ipv4_hdr* ip_hdr = rte_pktmbuf_mtod_offset(
        mbuf, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
    uint8_t ip_len = rte_ipv4_hdr_len(ip_hdr);
    cur_hdr += ip_len;

    if (ip_hdr->next_proto_id == IPPROTO_ICMP) {  // icmp
      printf("port %u got icmp\n", port);
    } else if (ip_hdr->next_proto_id == IPPROTO_TCP) {  // tcp
      struct rte_tcp_hdr* tcp = (struct rte_tcp_hdr*)cur_hdr;
      printf("port %u got tcp dport %u\n", port, htons(tcp->dst_port));
    } else if (ip_hdr->next_proto_id == IPPROTO_UDP) {  // udp
      struct rte_udp_hdr* udp = (struct rte_udp_hdr*)cur_hdr;
      printf("port %u got udp dport %u\n", port, htons(udp->dst_port));
    }
  } else if (eth_hdr->ether_type ==
             rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV6)) {  // ipv6
    printf("port %u got ipv6\n", port);
  } else if (is_stp(cur_hdr)) {
    printf("port %u got stp\n", port);
  } else {  // other
    printf("port %u other pkt 0x%x\n", port,
           rte_be_to_cpu_16(eth_hdr->ether_type));
  }
}
