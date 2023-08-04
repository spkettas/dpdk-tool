/**
 * Copyright (c) 1998-2020 TENCENT Inc. All rights reserved.
 *
 * @file arp.h
 * @author kanesun (kanesun@tencent.com)
 * @date 2023-08-04
 *
 * @brief handle arp/icmp response
 */
#include <arpa/inet.h>
#include "header.h"

// handle arp protocol
static void handle_arp(uint16_t port_id, uint16_t queue,
                       struct rte_ether_addr* mac_addr, char* local_ip,
                       struct rte_mbuf* pkt, struct rte_ether_hdr* eth_hdr);

// handle icmp protocol
static void handle_icmp(uint16_t port_id, uint16_t queue, struct rte_mbuf* pkt,
                        struct rte_ether_hdr* eth_hdr,
                        struct rte_ipv4_hdr*  ip_hdr);

// handle
static void send_response(uint16_t port, uint16_t queue,
                          struct rte_ether_addr* mac_addr, char* local_ip,
                          struct rte_mbuf* buf);

void handle_arp(uint16_t port_id, uint16_t queue,
                struct rte_ether_addr* mac_addr, char* local_ip,
                struct rte_mbuf* pkt, struct rte_ether_hdr* eth_hdr) {
  uint32_t our_ip = inet_addr(local_ip);

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
    if (arp_hdr->arp_data.arp_tip == our_ip) {
      arp_hdr->arp_opcode       = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
      arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;
      rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha,
                          &arp_hdr->arp_data.arp_tha);
      arp_hdr->arp_data.arp_sip = our_ip;
      rte_ether_addr_copy(mac_addr, &arp_hdr->arp_data.arp_sha);

      // Update Ethernet header
      rte_ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
      rte_ether_addr_copy(mac_addr, &eth_hdr->s_addr);

      printf("ARP reply sent\n");
      rte_eth_tx_burst(port_id, queue, &pkt, 1);
    }
  } else if (rte_be_to_cpu_16(arp_hdr->arp_opcode) == RTE_ARP_OP_REPLY) {
    // Update ARP table with the sender's information
    arp_table_add(arp_hdr->arp_data.arp_sip, &arp_hdr->arp_data.arp_sha);
  }
}

void handle_icmp(uint16_t port_id, uint16_t queue, struct rte_mbuf* pkt,
                 struct rte_ether_hdr* eth_hdr, struct rte_ipv4_hdr* ip_hdr) {
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

      printf("ICMP reply sent\n");
      rte_eth_tx_burst(port_id, queue, &pkt, 1);
    }
  }
}

void send_response(uint16_t port, uint16_t queue,
                   struct rte_ether_addr* mac_addr, char* local_ip,
                   struct rte_mbuf* buf) {
  struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr*);
  uint32_t              pkt_len = rte_pktmbuf_pkt_len(buf);
  char*                 cur_hdr = (char*)eth_hdr + sizeof(struct rte_ether_hdr);

  if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_ARP) {
    printf("got arp \n");
    handle_arp(port, queue, mac_addr, local_ip, buf, eth_hdr);
  } else if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV4) {
    struct rte_ipv4_hdr* ip_hdr = rte_pktmbuf_mtod_offset(
        buf, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));

    uint16_t id     = htons(ip_hdr->packet_id);
    uint16_t ip_len = (ip_hdr->version_ihl & 0x0f) * RTE_IPV4_IHL_MULTIPLIER;
    cur_hdr += ip_len;

    if (ip_hdr->next_proto_id == IPPROTO_ICMP) {
      printf("got icmp id %u\n", id);
      handle_icmp(port, queue, buf, eth_hdr, ip_hdr);
    }
  }
}
