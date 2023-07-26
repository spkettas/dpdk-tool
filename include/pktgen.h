/**
 * Copyright (c) 1998-2020  Inc. All rights reserved.
 *
 * @file pktgen.h
 * @author spkettas (spkettas@gmail.com)
 * @date 2023-07-26
 *
 * @brief generate packet
 */
#pragma once

#include <net/ethernet.h>
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

/**
 * @brief generate a arp packet
 *
 * @param portid   port id
 * @param out_mbuf  output mbuf
 * @return int  return value
 */
static int create_arp(uint16_t portid, struct rte_mempool* mbuf_pool,
                      struct rte_mbuf** out_mbuf) {
  struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbuf_pool);
  if (mbuf == NULL) {
    printf("Failed to allocate mbuf\n");
    return 1;
  }

  printf("send arp pkt\n");
  struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
  struct rte_arp_hdr*   arp_hdr =
      (struct rte_arp_hdr*)((char*)eth_hdr + sizeof(struct rte_ether_hdr));

  // 获取指定网卡的MAC地址
  rte_eth_macaddr_get(portid, &eth_hdr->s_addr);
  eth_hdr->ether_type           = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
  eth_hdr->d_addr.addr_bytes[0] = 0x11;
  eth_hdr->d_addr.addr_bytes[1] = 0x22;
  eth_hdr->d_addr.addr_bytes[2] = 0x33;
  eth_hdr->d_addr.addr_bytes[3] = 0x44;
  eth_hdr->d_addr.addr_bytes[4] = 0x55;
  eth_hdr->d_addr.addr_bytes[5] = 0x66;

  // 组包
  arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
  arp_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
  arp_hdr->arp_hlen     = ETHER_ADDR_LEN;
  arp_hdr->arp_plen     = sizeof(uint32_t);
  arp_hdr->arp_opcode   = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
  rte_ether_addr_copy(&eth_hdr->s_addr, &arp_hdr->arp_data.arp_sha);
  arp_hdr->arp_data.arp_sip = rte_cpu_to_be_32(RTE_IPV4(192, 168, 0, 1));
  rte_ether_addr_copy(&eth_hdr->d_addr, &arp_hdr->arp_data.arp_tha);
  arp_hdr->arp_data.arp_tip = rte_cpu_to_be_32(RTE_IPV4(192, 168, 0, 2));

  mbuf->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
  mbuf->pkt_len  = mbuf->data_len;

  //   print_packet_data(mbuf);

  *out_mbuf = mbuf;
  return 0;
}

/**
 * @brief generate udp packet
 *
 * @param portid
 * @param mbuf_pool
 * @param out_mbuf
 */
static int create_udp(uint16_t portid, struct rte_mempool* mbuf_pool,
                      struct rte_mbuf** out_mbuf) {
  struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbuf_pool);
  if (mbuf == NULL) {
    printf("Failed to allocate mbuf\n");
    return 1;
  }

  struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
  struct rte_ipv4_hdr*  ipv4_hdr =
      (struct rte_ipv4_hdr*)((char*)eth_hdr + sizeof(struct rte_ether_hdr));
  struct rte_udp_hdr* udp_hdr =
      (struct rte_udp_hdr*)((char*)ipv4_hdr + sizeof(struct rte_ipv4_hdr));

  // 获取指定网卡的MAC地址, 并设置以太网头
  rte_eth_macaddr_get(portid, &eth_hdr->s_addr);
  eth_hdr->ether_type           = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
  eth_hdr->d_addr.addr_bytes[0] = 0x3c;
  eth_hdr->d_addr.addr_bytes[1] = 0xfd;
  eth_hdr->d_addr.addr_bytes[2] = 0xfe;
  eth_hdr->d_addr.addr_bytes[3] = 0xcd;
  eth_hdr->d_addr.addr_bytes[4] = 0x41;
  eth_hdr->d_addr.addr_bytes[5] = 0xa8;

  // 设置IP头
  ipv4_hdr->version_ihl     = RTE_IPV4_VHL_DEF;
  ipv4_hdr->type_of_service = 0;
  ipv4_hdr->total_length    = rte_cpu_to_be_16(28);
  ipv4_hdr->packet_id       = 0;
  ipv4_hdr->fragment_offset = 0;
  ipv4_hdr->time_to_live    = 64;
  ipv4_hdr->next_proto_id   = IPPROTO_UDP;
  ipv4_hdr->hdr_checksum    = 0;
  ipv4_hdr->src_addr        = rte_cpu_to_be_32(RTE_IPV4(192, 168, 0, 1));
  ipv4_hdr->dst_addr        = rte_cpu_to_be_32(RTE_IPV4(192, 168, 0, 2));
  ipv4_hdr->hdr_checksum    = rte_ipv4_cksum(ipv4_hdr);

  // 设置UDP头
  udp_hdr->src_port    = rte_cpu_to_be_16(6666);
  udp_hdr->dst_port    = rte_cpu_to_be_16(80);
  udp_hdr->dgram_len   = rte_cpu_to_be_16(8);
  udp_hdr->dgram_cksum = 0;

  mbuf->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                   sizeof(struct rte_udp_hdr);
  mbuf->pkt_len = mbuf->data_len;

  *out_mbuf = mbuf;
  return 0;
}
