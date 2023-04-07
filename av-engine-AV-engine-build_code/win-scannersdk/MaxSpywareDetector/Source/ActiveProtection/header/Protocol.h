// Protocol.h : header file
//

#pragma once

#include <pcap.h>

//  define the tcp flags....
#define OFFSET(th)	(((th)->offset & 0xf0) >> 4)
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ACE 0x40
#define TH_CWR 0x80

#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ACE|TH_CWR)

//define header lengths

#define ETHER_LENGTH 14
#define IP_LENGTH    20
#define TCP_LENGTH   20
#define UDP_LENGTH   8


// Ethernet Header
struct eth_header   // 14 bytes
{
   u_char dmac[6]; //destination mac address
   u_char smac[6]; //source mac address
   u_short type;   //IP ,ARP , RARP
};

// IPV4 Address
struct ip_address
{
   u_char byte1;
   u_char byte2;
   u_char byte3;
   u_char byte4;
};

// 6 byte MAC Address
typedef struct tagMacAddr
{
   u_char byte1;
   u_char byte2;
   u_char byte3;
   u_char byte4;
   u_char byte5;
   u_char byte6;
}MACADDR;

// ARP header
struct arp_header   //28 bytes
{
   u_short hrd;       //hardware address space=0x0001
   u_short eth_type;  //Ethernet type ....=0x0800
   u_char maclen;     //Length of mac address=6
   u_char iplen;      //Length of ip addres=4
   u_short opcode;    //Request =1 Reply=2 (highbyte)
   u_char smac[6];    //source mac address
   ip_address saddr;  //Source ip address
   u_char dmac[6];    //Destination mac address
   ip_address daddr;  //Destination ip address
};

typedef arp_header rarp_header;


/* IPv4 header */
 struct ip_header
{
   u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
   u_char  tos;            // Type of service 
   u_short tlen;           // Total length 
   u_short identification; // Identification
   u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
   u_char  ttl;            // Time to live
   u_char  proto;          // Protocol
   u_short crc;            // Header checksum
   ip_address  saddr;      // Source address
   ip_address  daddr;      // Destination address
   // u_int   op_pad;         // Option + Padding
};

// UDP header
struct udp_header   //8 bytes
{
   u_short sport;          // Source port
   u_short dport;          // Destination port
   u_short len;            // Datagram length
   u_short crc;            // Checksum
};

// TCP header
struct tcp_header  //20 bytes : default
{
   u_short sport;      //Source port
   u_short dport;      //Destination port
   u_long seqno;       //Sequence no
   u_long ackno;       //Ack no
   u_char offset;      //Higher level 4 bit indicates data offset
   u_char flag;        //Message flag
   u_short win;
   u_short checksum;
   u_short uptr;
};

