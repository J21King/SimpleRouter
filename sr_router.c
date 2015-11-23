/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  int cksumtemp = 0;
  int cksumcalculated = 0;
  struct sr_arpentry *entry;
  struct sr_arpreq *req;
  struct sr_arpcache *arp_cache = &(sr->cache);

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("\n*** -> Received packet of length %d \n",len);

  /* fill in code here */
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  if (len < sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  if(ethertype(packet) == ethertype_arp) { /* ARP */
    if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else {
      printf("ARP packet\n");
	if(ntohs(arphdr->ar_op) == arp_op_request) { /* ARP request */
	  printf("ARP request\n");
	  entry = sr_arpcache_lookup(arp_cache,ntohs(arphdr->ar_tip));
	  if(entry) {
	    /* sr_send_packet(sr,packettosend,len,interface); forward packet */
	    /* send arp reply */
	    free(entry);
	  }
	  else {
	    req = sr_arpcache_queuereq(arp_cache,ntohs(arphdr->ar_tip),packet,len,interface);
	    handle_arpreq(arp_cache,req);
	  }
	}
	else if(ntohs(arphdr->ar_op) == arp_op_reply) /* ARP reply */
	  printf("ARP reply\n");
	else
	  printf("Unknown ARP opcode\n");
    }
  }
  else if(ethertype(packet) == ethertype_ip) { /* IP */
    if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }
    else {
      printf("IP packet\n");
      cksumtemp = iphdr->ip_sum;
      iphdr->ip_sum = 0;
      cksumcalculated = cksum((void *)iphdr,iphdr->ip_len);
      if(cksumtemp == cksumcalculated) {
	printf("Checksum good!");
	/* send echo reply */
      }
      else if(cksumtemp != cksumcalculated) {
	printf("Checksum bad!");
	/* drop packet */
      }
      else { /* error handling */
	if(iphdr->ip_ttl <= 1)
	  printf("ICMP time exceeded"); /* ICMP time exceeded */
	else
	  iphdr->ip_ttl -= 1;
	  /* perform LPM and then forward packet */
      }
    }
  }
  else /* not IP or ARP */
    printf("Unrecognized Ethernet Type 0x%X\n",ethertype(packet));
}
/* end sr_ForwardPacket */

