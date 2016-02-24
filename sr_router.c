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
  uint8_t buf[len];
  int cksumtemp = 0;
  int cksumcalculated = 0;
  struct sr_arpentry *entry;
  struct sr_arpreq *req;
  struct sr_arpcache *arp_cache = &(sr->cache);
  struct sr_if *sr_interface;
  struct sr_rt *rt_walker = 0;
  char *temp_if;

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("\n*** -> Received packet of length %d \n",len);

  /* fill in code here */
  sr_ethernet_hdr_t *ethhdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  sr_ethernet_hdr_t *arpreply_ethhdr = (sr_ethernet_hdr_t *)buf;
  sr_arp_hdr_t *arpreply_arphdr = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *tempreq;

  if (len < sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr, "ETHERNET header is insufficient length\n");
    return;
  }

  if(ethertype(packet) == ethertype_arp) { /* ARP */
    if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))) {
      /* todo: call sr_arp_req_not_for_us, maybe later */
      fprintf(stderr, "ARP header is insufficient length\n");
      return;
    }
    else {
      printf("ARP packet received\n");
      if(ntohs(arphdr->ar_op) == arp_op_request) { /* ARP request */
	printf("\tARP request\n");
	/* send ARP reply */
	sr_interface = sr_get_interface(sr,interface);
	memcpy(buf,packet,len);

	memset(arpreply_ethhdr->ether_dhost,0xff,6);
	memcpy(arpreply_ethhdr->ether_shost,sr_interface->addr,6);
	arpreply_ethhdr->ether_type = htons(ethertype_arp);

	arpreply_arphdr->ar_op = htons(arp_op_reply);
	memcpy(arpreply_arphdr->ar_sha,sr_interface->addr,6);
	arpreply_arphdr->ar_sip = arphdr->ar_tip;
	memcpy(arpreply_arphdr->ar_tha,arphdr->ar_sha,6);
	arpreply_arphdr->ar_tip = arphdr->ar_sip;
	sr_send_packet(sr,buf,len,interface);

	printf("\tARP reply sent\n");
		/* sr_arpcache_dump(arp_cache); */
      }
      else if(ntohs(arphdr->ar_op) == arp_op_reply) { /* ARP reply */
	printf("\tARP reply\n");
	/* cache IP->MAC mapping and check if arp req in queue */
	req = sr_arpcache_insert(arp_cache,arphdr->ar_sha,ntohs(arphdr->ar_sip));
	tempreq = (sr_ethernet_hdr_t *)req->packets->buf;
	memcpy(tempreq->ether_dhost,ethhdr->ether_shost,6);
	if(req != NULL) {
	  /* send outstanding packets by call */
	  printf("\tARP req in queue\n");
	  sr_send_packet(sr,req->packets->buf,req->packets->len,interface);
	  sr_arpreq_destroy(arp_cache,req);
	}
	else
	  printf("\tARP req not in queue\n");
      }
      else /* not ARP request or reply */
	fprintf(stderr, "Unknown ARP opcode\n");
    }
  }

  else if(ethertype(packet) == ethertype_ip) { /* IP */
    if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))) {
      fprintf(stderr, "IP header is insufficient length\n");
      return;
    }
    else {
      printf("IP packet received\n");
      /* check checksum */
      cksumtemp = iphdr->ip_sum;
      iphdr->ip_sum = 0;
      cksumcalculated = cksum((void *)iphdr,4*iphdr->ip_hl);

      if(cksumtemp == cksumcalculated) {
	printf("\tChecksum good!\n");

	/* this part should not be here, it should be called though */
	if(iphdr->ip_ttl <= 1) {
	  fprintf(stderr, "ICMP time exceeded\n"); /* ICMP time exceeded */
	  return;
	}
	else
	  iphdr->ip_ttl -= 1; 
	
	/* update checksum */
	iphdr->ip_sum = cksum((void *)iphdr,4*iphdr->ip_hl);

	/* todo: LPM and find next hop ip, if no match ICMP net unreachable  */

	/* check routing table, save interface */
	rt_walker = sr->routing_table;
	while(rt_walker != NULL) {
	  if(iphdr->ip_dst == (uint32_t)rt_walker->dest.s_addr) { /* checks for dest IP addr, should be LPM ip not ip_dst */
	    temp_if = rt_walker->interface;
	  }
	  rt_walker = rt_walker->next;
	}
	sr_interface = sr_get_interface(sr,temp_if);

	/* check cache to avoid unnecessary arp req */
	entry = sr_arpcache_lookup(arp_cache,ntohs(iphdr->ip_dst)); /* should be LPM ip not ip_dst, but since next hop is destination... */

	if(entry != NULL) { /* cache hit, just send ip packet to next hop*/
	  printf("\tIP->MAC hit\n");
	  sr_send_packet(sr,packet,len,sr_interface);
	  free(entry);
	}
	else { /* cache miss, send ARP req and wait for reply */
	  printf("\tIP->MAC miss\n");
	  if(sr_interface == 0) { /* no match in routing table */
	    fprintf(stderr, "ICMP host unreachable\n");
	    return;
	  }
	  else { /* match in routing table */
	    /* construct arp req with new interface */
	    memset(arpreply_ethhdr->ether_dhost,0xff,6);
	    memcpy(arpreply_ethhdr->ether_shost,sr_interface->addr,6);
	    arpreply_ethhdr->ether_type = htons(ethertype_arp);

	    arpreply_arphdr->ar_hrd = htons(arp_hrd_ethernet);
	    arpreply_arphdr->ar_pro = htons(ethertype_ip);
	    arpreply_arphdr->ar_hln = 0x6;
	    arpreply_arphdr->ar_pln = 0x4;
	    arpreply_arphdr->ar_op = htons(arp_op_request);
	    memcpy(arpreply_arphdr->ar_sha,sr_interface->addr,6);
	    arpreply_arphdr->ar_sip = sr_interface->ip;
	    memset(arpreply_arphdr->ar_tha,0x00,6);
	    arpreply_arphdr->ar_tip = iphdr->ip_dst;

	    memcpy(ethhdr->ether_shost,sr_interface->addr,6);

	    printf("\tARP request sent\n");
	    /* add packet to queue list */
	    req = sr_arpcache_queuereq(arp_cache,ntohs(iphdr->ip_dst),packet,len,sr_interface);
	    handle_arpreq(arp_cache,sr,req,buf,sr_interface);
	  }
	}
      }
      else {
	/* drop packet */
	fprintf(stderr, "\tChecksum bad!\n");
	return;
      }
    }
  }

  else /* not IP or ARP */
    printf("Unrecognized Ethernet Type 0x%X\n",ethertype(packet));
}
/* end sr_ForwardPacket */
