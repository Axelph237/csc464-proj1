#define _BSD_SOURCE

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/eth.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "checksum.h"

#define IP_ADDR_SIZE 4
#define MAC_ADDR_SIZE 6
#define PORT_SIZE 2
#define OCTET 1
#define WORD 4

/* Ethernet constants */
#define ETHER_HDR_SIZE 14
#define ETYPE_SIZE 2
#define ARP_ETYPE 0x0806
#define IPV4_ETYPE 0x0800

/* ARP constants */
#define ARP_HDR_SIZE 28
#define ARP_HARDWARE_SIZE 6
#define ARP_OPCODE_SIZE 2
#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002
#define ARP_SENDER_MAC_IDX ARP_HARDWARE_SIZE + ARP_OPCODE_SIZE
#define ARP_SENDER_IP_IDX ARP_SENDER_MAC_IDX + MAC_ADDR_SIZE
#define ARP_TARGET_MAC_IDX ARP_SENDER_IP_IDX + IP_ADDR_SIZE
#define ARP_TARGET_IP_IDX ARP_TARGET_MAC_IDX + MAC_ADDR_SIZE

/* IP constants */
#define IP_HDR_MIN_SIZE 20
#define IP_TTL_SIZE 1
#define IP_PROTOCOL_SIZE 1
#define IP_CHECKSUM_SIZE 2
#define IP_ICMP_PROTOCOL 1
#define IP_TCP_PROTOCOL 6
#define IP_UDP_PROTOCOL 17
#define IP_PSEUDO_HDR_SIZE WORD * 3

/* ICMP constants */
#define ICMP_NECESSARY_SIZE 1
#define ICMP_REPLY 0x0000
#define ICMP_REQUEST 0x0008

/* UDP constants */
#define UDP_NECESSARY_SIZE 4
#define UDP_PORT_SIZE 2
#define DNS_PORT 53
#define HTTP_PORT 80

/* TCP constants */
#define TCP_SEQ_NUM_SIZE 4
#define TCP_ACK_NUM_SIZE 4
#define TCP_SYN_FLAG 0x02
#define TCP_RST_FLAG 0x04
#define TCP_FIN_FLAG 0x01
#define TCP_ACK_FLAG 0x10
#define TCP_WIN_SIZE 2

void tcp(const uint8_t tcp_hdr[], const int seg_len,
         const uint8_t ip_pseudo_hdr[]) {

  printf("\tTCP Header\n");

  // Segment Length
  printf("\t\tSegment Length: %u\n", seg_len);

  // Source Port
  uint16_t source_port_no = 0;
  memcpy(&source_port_no, tcp_hdr, PORT_SIZE);
  uint16_t source_port = ntohs(source_port_no);

  printf("\t\tSource Port:  ");
  if (source_port == DNS_PORT) {
    printf("DNS\n");
  } else if (source_port == HTTP_PORT) {
    printf("HTTP\n");
  } else {
    printf("%u\n", source_port);
  }

  // Dest Port
  uint16_t dest_port_no = 0;
  memcpy(&dest_port_no, &tcp_hdr[PORT_SIZE], PORT_SIZE);
  uint16_t dest_port = ntohs(dest_port_no);
  printf("\t\tDest Port:  ");
  if (dest_port == DNS_PORT) {
    printf("DNS\n");
  } else if (dest_port == HTTP_PORT) {
    printf("HTTP\n");
  } else {
    printf("%u\n", dest_port);
  }
  // Sequence Number
  uint32_t seq_num_no = 0;
  memcpy(&seq_num_no, &tcp_hdr[WORD], TCP_SEQ_NUM_SIZE);
  uint32_t seq_num = ntohl(seq_num_no);
  printf("\t\tSequence Number: %u\n", seq_num);

  // ACK Number
  uint32_t ack_num_no = 0;
  memcpy(&ack_num_no, &tcp_hdr[WORD * 2], TCP_ACK_NUM_SIZE);
  uint32_t ack_num = ntohl(ack_num_no);
  printf("\t\tACK Number: %u\n", ack_num);

  // FLAGS
  uint8_t tcp_flags = 0;
  memcpy(&tcp_flags, &tcp_hdr[(WORD * 3) + 1], 1);

  // SYN Flag
  printf("\t\tSYN Flag: ");
  if ((tcp_flags & TCP_SYN_FLAG) > 0) {
    printf("Yes\n");
  } else {
    printf("No\n");
  }

  // RST Flag
  printf("\t\tRST Flag: ");
  if ((tcp_flags & TCP_RST_FLAG) > 0) {
    printf("Yes\n");
  } else {
    printf("No\n");
  }

  // FIN Flag
  printf("\t\tFIN Flag: ");
  if ((tcp_flags & TCP_FIN_FLAG) > 0) {
    printf("Yes\n");
  } else {
    printf("No\n");
  }

  // ACK Flag
  printf("\t\tACK Flag: ");
  if ((tcp_flags & TCP_ACK_FLAG) > 0) {
    printf("Yes\n");
  } else {
    printf("No\n");
  }

  // Window Size
  uint16_t win_size_no = 0;
  memcpy(&win_size_no, &tcp_hdr[(WORD * 3) + 2], TCP_WIN_SIZE);
  uint16_t win_size = ntohs(win_size_no);
  printf("\t\tWindow Size: %u\n", win_size);

  // Checksum
  uint16_t tcp_cksum_no = 0;
  memcpy(&tcp_cksum_no, &tcp_hdr[(WORD * 4)], 2);
  uint16_t tcp_cksum = ntohs(tcp_cksum_no);

  int tcp_pseudo_hdr_size = IP_PSEUDO_HDR_SIZE + seg_len;
  uint8_t *tcp_pseudo_hdr = (uint8_t *)malloc(tcp_pseudo_hdr_size);
  if (tcp_pseudo_hdr == NULL) {
    printf("FAILED CREATING TCP PSUEDO HEADER\n");
    exit(1);
  }

  // Copy ip psuedo header
  memcpy(tcp_pseudo_hdr, ip_pseudo_hdr, IP_PSEUDO_HDR_SIZE);
  // Copy tcp psuedo header
  memcpy(&tcp_pseudo_hdr[IP_PSEUDO_HDR_SIZE], tcp_hdr, seg_len);

  printf("\t\tChecksum: ");
  if (in_cksum((unsigned short *)tcp_pseudo_hdr, tcp_pseudo_hdr_size) == 0) {
    printf("Correct (0x%04x)\n", tcp_cksum);
  } else {
    printf("Incorrect (0x%04x)\n", tcp_cksum);
  }
  free(tcp_pseudo_hdr);
}

void udp(const uint8_t udp_hdr[]) {
  printf("\tUDP Header\n");
  uint16_t source_port_no = 0;
  uint16_t dest_port_no = 0;

  memcpy(&source_port_no, udp_hdr, UDP_PORT_SIZE);
  memcpy(&dest_port_no, &udp_hdr[UDP_PORT_SIZE], UDP_PORT_SIZE);

  uint16_t source_port = ntohs(source_port_no);
  uint16_t dest_port = ntohs(dest_port_no);

  printf("\t\tSource Port: ");
  if (source_port == DNS_PORT) {
    printf(" DNS\n");
  } else if (source_port == HTTP_PORT) {
    printf("HTTP\n");
  } else {
    printf(" %u\n", source_port);
  }
  printf("\t\tDest Port: ");
  if (dest_port == DNS_PORT) {
    printf(" DNS\n");
  } else if (dest_port == HTTP_PORT) {
    printf("HTTP\n");
  } else {
    printf(" %u\n", dest_port);
  }
}

void icmp(const uint8_t icmp_hdr) {
  printf("\tICMP Header\n\t\tType: ");
  if (icmp_hdr == ICMP_REPLY) {
    printf("Reply\n");
  } else if (icmp_hdr == ICMP_REQUEST) {
    printf("Request\n");
  } else {
    printf("%u\n", icmp_hdr);
  }
}

/* ethernet()
 * returns: the payload type bytes, or 0 if there was an error */
uint16_t ethernet(const uint8_t ethr_hdr[]) {
  printf("\tEthernet Header\n");

  // Destination MAC
  struct ether_addr mac_addr;
  memcpy(&mac_addr, ethr_hdr, MAC_ADDR_SIZE);
  printf("\t\tDest MAC: %s\n", ether_ntoa(&mac_addr));

  // Source MAC
  memcpy(&mac_addr, &ethr_hdr[MAC_ADDR_SIZE], MAC_ADDR_SIZE);
  printf("\t\tSource MAC: %s\n", ether_ntoa(&mac_addr));

  // Payload Type
  uint16_t type_no;
  memcpy(&type_no, &ethr_hdr[MAC_ADDR_SIZE * 2], ETYPE_SIZE);
  uint16_t type = ntohs(type_no);

  printf("\t\tType: ");
  if (type == IPV4_ETYPE) {
    printf("IP\n");
    return type;
  } else if (type == ARP_ETYPE) {
    printf("ARP\n");
    return type;
  } else {
    printf("ERROR, got: %c\n", ethr_hdr[(MAC_ADDR_SIZE) + 1]);
    return 0x0000;
  }

  return 0;
}

void arp(const uint8_t arp_hdr[]) {
  printf("\tARP header\n");

  // Opcode
  uint16_t opcode_no;
  memcpy(&opcode_no, &arp_hdr[ARP_HARDWARE_SIZE], ARP_OPCODE_SIZE);
  uint16_t opcode = ntohs(opcode_no);

  printf("\t\tOpcode: ");
  if (opcode == ARP_REQUEST) {
    printf("Request\n");
  } else if (opcode == ARP_REPLY) {
    printf("Reply\n");
  } else {
    printf("ERROR\n");
  }

  struct ether_addr mac_addr;
  struct in_addr ip_addr;
  // Sender MAC
  memcpy(&mac_addr, &arp_hdr[ARP_SENDER_MAC_IDX], MAC_ADDR_SIZE);
  printf("\t\tSender MAC: %s\n", ether_ntoa(&mac_addr));

  // Sender IP
  memcpy(&ip_addr, &arp_hdr[ARP_SENDER_IP_IDX], IP_ADDR_SIZE);
  printf("\t\tSender IP: %s\n", inet_ntoa(ip_addr));

  // Target MAC
  memcpy(&mac_addr, &arp_hdr[ARP_TARGET_MAC_IDX], MAC_ADDR_SIZE);
  printf("\t\tTarget MAC: %s\n", ether_ntoa(&mac_addr));

  // Target IP
  memcpy(&ip_addr, &arp_hdr[ARP_TARGET_IP_IDX], IP_ADDR_SIZE);
  printf("\t\tTarget IP: %s\n", inet_ntoa(ip_addr));
}

void ip(const uint8_t *ip_hdr) {
  /*
  IP Header
          IP PDU Len: 60
          Header Len (bytes): 20
          TTL: 128
          Protocol: ICMP
          Checksum: Correct (0xf12f)
          Sender IP: 192.168.1.102
          Dest IP: 199.181.132.250
   */
  printf("\tIP Header\n");

  // Header len
  uint8_t ip_top_byte = 0;
  memcpy(&ip_top_byte, ip_hdr, 1);
  uint8_t ip_hdr_len = (ip_top_byte & 0x0F) * WORD;

  // PDU len
  uint16_t ip_total_len_no = 0;
  memcpy(&ip_total_len_no, &ip_hdr[2], 2);
  uint16_t ip_total_len = ntohs(ip_total_len_no);

  printf("\t\tIP PDU Len: %u\n", ip_total_len);

  printf("\t\tHeader Len (bytes): %u\n", ip_hdr_len);

  // TTL
  uint8_t ip_ttl = 0;
  memcpy(&ip_ttl, &ip_hdr[WORD * 2], IP_TTL_SIZE);
  printf("\t\tTTL: %u\n", ip_ttl);

  // Protocol
  printf("\t\tProtocol: ");
  uint8_t ip_protocol = 0;
  memcpy(&ip_protocol, &ip_hdr[(WORD * 2) + IP_TTL_SIZE], IP_PROTOCOL_SIZE);
  if (ip_protocol == IP_ICMP_PROTOCOL) {
    printf("ICMP\n");
  } else if (ip_protocol == IP_TCP_PROTOCOL) {
    printf("TCP\n");
  } else if (ip_protocol == IP_UDP_PROTOCOL) {
    printf("UDP\n");
  } else {
    printf("Unknown\n");
  }

  // Checksum
  printf("\t\tChecksum: ");
  unsigned short answer = in_cksum((unsigned short *)ip_hdr, ip_hdr_len);
  if (answer == 0) {
    printf("Correct ");
  } else {
    printf("Incorrect ");
  }
  uint16_t ip_cksum = 0;
  memcpy(&ip_cksum, &ip_hdr[((WORD * 2) + 2)], IP_CHECKSUM_SIZE);
  printf("(0x%04x)\n", ntohs(ip_cksum));

  // Sender IP
  struct in_addr ip_source_addr;
  memcpy(&ip_source_addr, &ip_hdr[(WORD * 3)], IP_ADDR_SIZE);
  printf("\t\tSender IP: %s\n", inet_ntoa(ip_source_addr));

  // Dest IP
  struct in_addr ip_dest_addr;
  memcpy(&ip_dest_addr, &ip_hdr[(WORD * 4)], IP_ADDR_SIZE);
  printf("\t\tDest IP: %s\n\n", inet_ntoa(ip_dest_addr));

  // Call next parse function
  if (ip_protocol == IP_ICMP_PROTOCOL) {
    icmp(ip_hdr[ip_hdr_len]);
  } else if (ip_protocol == IP_TCP_PROTOCOL) {
    uint16_t tcp_seg_len = htons(ip_total_len - ip_hdr_len);

    uint8_t ip_pseudo_hdr[IP_PSEUDO_HDR_SIZE];
    memset(ip_pseudo_hdr, 0x00, IP_PSEUDO_HDR_SIZE);
    memcpy(ip_pseudo_hdr, &ip_hdr[(WORD * 3)], IP_ADDR_SIZE);
    memcpy(&ip_pseudo_hdr[IP_ADDR_SIZE], &ip_hdr[(WORD * 4)], IP_ADDR_SIZE);
    memcpy(&ip_pseudo_hdr[(WORD * 2) + 1], &ip_protocol, IP_PROTOCOL_SIZE);
    memcpy(&ip_pseudo_hdr[(WORD * 2) + 2], &tcp_seg_len, 2);

    tcp(&ip_hdr[ip_hdr_len], ip_total_len - ip_hdr_len, ip_pseudo_hdr);

  } else if (ip_protocol == IP_UDP_PROTOCOL) {
    uint8_t udp_hdr[UDP_NECESSARY_SIZE];
    memcpy(&udp_hdr, &ip_hdr[ip_hdr_len], UDP_NECESSARY_SIZE);
    udp(udp_hdr);
  } else {
  }
}

void parse(struct pcap_pkthdr *hdr, const u_char *data) {
  // Parse order:
  //
  // 1) Ethernet
  // 2) ARP or IP
  // 3) ICMP
  // 4) TCP or UDP

  // 1) Ethernet
  int rem_len = hdr->caplen;
  uint16_t ether_payload_type = 0x0000;
  if ((rem_len -= ETHER_HDR_SIZE) >= 0) {
    // parse ethernet
    u_char ethr_hdr[ETHER_HDR_SIZE];
    memcpy(&ethr_hdr, data, ETHER_HDR_SIZE);

    ether_payload_type = ethernet(ethr_hdr);
    printf("\n");
  }

  // 2.A) ARP
  if (ether_payload_type == ARP_ETYPE && (rem_len -= ARP_HDR_SIZE) >= 0) {
    u_char arp_hdr[ARP_HDR_SIZE];
    memcpy(arp_hdr, &data[ETHER_HDR_SIZE], ARP_HDR_SIZE);

    arp(arp_hdr);
    printf("\n");
  }
  // 2.B) IPV4
  else if (ether_payload_type == IPV4_ETYPE &&
           (rem_len -= IP_HDR_MIN_SIZE) >= 0) {
    ip(&data[ETHER_HDR_SIZE]); // Pass full header offset by Ethernet header

    // IP handles calling parse functions for ICMP, TCP, & UDP
  }
}

int main(int argc, char *argv[]) {

  // Read cmd args
  if (argc != 2) {
    printf("trace: Missing args. Usage: trace <path/to/file>\n");
    exit(1);
  }

  char *path = argv[1];

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *capt = pcap_open_offline(path, errbuf);
  if (capt == NULL) {
    printf("%s\n", errbuf); // errbuff is text
    return 1;
  }

  struct pcap_pkthdr *header;
  const u_char *data;
  int ret;

  u_int pkt_cnt = 0;
  while ((ret = pcap_next_ex(capt, &header, &data)) > 0) {
    pkt_cnt++;

    printf("\nPacket number: %u  Packet Len: %u\n\n", pkt_cnt, header->len);

    parse(header, data);
  }

  if (ret == -1) {
    printf("trace: Error capturing packet: %s\n", pcap_geterr(capt));
  }

  pcap_close(capt);
  return 0;
}
