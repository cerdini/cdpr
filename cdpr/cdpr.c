/*
* cdpr - Cisco Discovery Protocol Reporter
* Copyright <c) 2002 MonkeyMental.com
*
* This program will show you which Cisco device your machine is
* connected to based on CDP packets received.
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*
* Version History:
*
* 1.0.0	LO	02-06-30	Initial Release
* 1.0.1	LO	02-07-01	ifdef/endif DLT types to deal with older bpf.h headers
*/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cdp.h"


void
dump_ip (const u_char *ip, int len)
{
	printf ("%d.%d.%d.%d",
		(int) ip[0], (int) ip[1], (int) ip[2], (int) ip[3]);
}

void
dump_hex (const u_char *p, int len)
{
	while (len--)
	{
		printf ("%02X ", *p++);
	}
}

void
dump_ascii (const u_char *p, int len)
{
	while (len--)
	{
		printf ("%c", (*p < ' ' || *p > '~') ? '.' : *p);
		++p;
	}
}

void
dump_data (const u_char *p, int len)
{
	int i;

	for (i = 0; i < len; i += 16, p += 16)
	{
		printf ("%p:  ", p);
		dump_hex (p, 16);
		printf (" ");
		dump_ascii (p, 16);
		printf ("\n");
	}
}
char *
get_cdp_type (int type)
{
    int i;

    for (i = 0; type_vals[i].type != 0; ++i)
    {
    	if (type == type_vals[i].type)
    	{
    		return type_vals[i].val;
    	}
    }
    return "Unknown type";
}

void
print_cdp_address (u_char *v, int vlen, int verbose)
{
	int i;
	u_int32_t number = ntohl (*((u_int32_t *) v));

	if (verbose > 0)
	{
		printf ("  number: %d\n", number);
	}

	v += sizeof (u_int32_t);
	for (i = 0; i < number; ++i)
	{
		u_char protocol      = *v;
		u_char protocol_len  = *(v+1);
		u_char *protocol_val = v+2;
		int    address_len   = ntohs(*((u_int16_t *)(v+2+protocol_len)));
		u_char *address_val  = v+2+protocol_len+2;
		
		if (verbose > 0)
		{
			printf ("  protocol: %02x\n", protocol);
			printf ("  protocol len: %02x\n", protocol_len);
			printf ("  protocol val: ");
			dump_hex (protocol_val, protocol_len);
			printf ("\n");
		
			printf ("  address len: %02x\n", address_len);
			printf ("  address val: ");
		}
		else
		{
			printf ("  value:  ");
		}
		if (protocol_len == 1 && *protocol_val == 0xCC && address_len == 4)
			dump_ip (address_val, address_len);
		else
			dump_hex (address_val, address_len);
		printf ("\n");

		v += (2+protocol_len+2+address_len);
	}
}

void
print_cdp_capabilities (u_char *v, int vlen)
{
	u_int32_t cap = ntohl (*((u_int32_t *) v));

	printf ("  value:  %08x\n", cap);
	if (cap & 0x01) printf ("          Performs level 3 routing for at least one network layer protocol.\n");
	if (cap & 0x02) printf ("          Performs level 2 transparent bridging.\n");
	if (cap & 0x04) printf ("          Performs level 2 source-route bridging.\n");
	if (cap & 0x08) printf ("          Performs level 2 switching.\n");
	if (cap & 0x10) printf ("          Sends and receives packets for at least one network layer protocol.\n");
	if (cap & 0x20) printf ("          The bridge or switch does not forward IGMP Report packets on nonrouter ports.\n");
	if (cap & 0x40) printf ("          Provides level 1 functionality.\n");
}

void
print_cdp_packet (const u_char *p, int plen, int verbose)
{
	CDP_HDR *h;
	CDP_DATA *d;

	h = (CDP_HDR *) p;

	// dump_data (p, 128);

	if (verbose > 1 )
	{
		printf ("\ncdp packet:\n");
		printf ("  version:      %02x\n", h->version);
		printf ("  time to live: %02x\n", h->time_to_live);
		printf ("  checksum:     %04x\n", ntohs (h->checksum));
	}

	d = (CDP_DATA *) (p + sizeof (CDP_HDR));
	plen -= sizeof (CDP_HDR);

	while (plen > sizeof (CDP_DATA))
	{
		int type = ntohs (d->type);
		int length = ntohs (d->length);
		u_char *v = (u_char *) d + sizeof (CDP_DATA);
		int vlen = length - sizeof (CDP_DATA);
		

		//	printf ("\ncdp type/len/val:\n");
		if(verbose > 0 )
		{
			printf ("  type:   %04x - %s\n", type, get_cdp_type (type));
		}
		if(verbose > 0)
		{
			printf ("  length: %04x\n", length);
		}
		switch (type)
		{
		case TYPE_DEVICE_ID:
			printf ("%s\n", get_cdp_type (type));
		    printf ("  value:  %.*s\n", vlen, v);
			break;

		case TYPE_ADDRESS:
			printf ("%s\n", get_cdp_type (type));
			print_cdp_address (v, vlen, verbose);
			break;

		case TYPE_PORT_ID:
			printf ("%s\n", get_cdp_type (type));
			printf ("  value:  %.*s\n", vlen, v);
			break;

		case TYPE_CAPABILITIES:
			if(verbose > 0)
			{
				printf ("%s\n", get_cdp_type (type));
				print_cdp_capabilities (v, vlen);
			}
			break;

		case TYPE_IOS_VERSION:
			if(verbose > 0)
			{
				printf ("%s\n", get_cdp_type (type));
				printf ("  value:  %.*s\n", vlen, v);
			}
			break;

		case TYPE_PLATFORM:
			if(verbose > 0)
			{
				printf ("%s\n", get_cdp_type (type));
				printf ("  value:  %.*s\n", vlen, v);
			}
			break;

		case TYPE_IP_PREFIX:
			if(verbose > 0)
			{
				printf ("%s\n", get_cdp_type (type));
				printf ("  value:  ");
				dump_hex (v, vlen);
				printf ("\n");
			}
			break;

		case TYPE_VTP_MGMT_DOMAIN:
			if(verbose > 0)
			{
				printf ("%s\n", get_cdp_type (type));
				printf ("  value:  %.*s\n", vlen, v);
			}
			break;

		case TYPE_NATIVE_VLAN:
			if(verbose > 0)
			{
				printf ("%s\n", get_cdp_type (type));
				printf ("  value:  ");
				dump_hex (v, vlen);
				printf ("\n");
			}
			break;
		
		case TYPE_DUPLEX:
			if(verbose > 0)
			{
				printf ("%s\n", get_cdp_type (type));
				printf ("  value:  ");
				dump_hex (v, vlen);
				printf ("\n");
			}
			break;

		default:
			if(verbose > 1)
			{
				printf ("%s\n", get_cdp_type (type));
				printf ("  value:  ");
				dump_hex (v, vlen);
				printf ("\n");
			}
		}

	    plen -= length;
	    d = (CDP_DATA *) ((u_char *) d + length);
	}
}


int
print_dlt(pcap_t *handle)
{
	int type;

	/* Print the DLL Type*/
	switch(type = pcap_datalink(handle))
	{
#ifdef DLT_NULL
		case DLT_NULL:
			printf("Data Link Type: BSD Loopback encapsulation.\n");
			break;
#endif
#ifdef DLT_EN10MB
		case DLT_EN10MB:
			printf("Data Link Type: Ethernet (10MB, 100MB, 1000MB and up).\n");
			break;
#endif
#ifdef DLT_IEEE802
		case DLT_IEEE802:
			printf("Data Link Type: IEEE 802.5 Token Ring.\n");
			break;
#endif
#ifdef DLT_ARCNET
		case DLT_ARCNET:
			printf("Data Link Type: ARCNET.\n");
			break;
#endif
#ifdef DLT_PPP
		case DLT_PPP:
			printf("Data Link Type: PPP (Point-to-Point Protocol).\n");
			break;
#endif
#ifdef DLT_FDDI
		case DLT_FDDI:
			printf("Data Link Type: FDDI.\n");
			break;
#endif
#ifdef DLT_ATM_RFC1483
		case DLT_ATM_RFC1483:
			printf("Data Link Type: RFC 1483 LLC/SNAP-encapsulated ATM.\n");
			break;
#endif
#ifdef DLT_RAW
		case DLT_RAW:
			printf("Data Link Type: raw IP.\n");
			break;
#endif
#ifdef DLT_PPP_SERIAL
		case DLT_PPP_SERIAL:
			printf("Data Link Type: PPP in HDLC-like framing.\n");
			break;
#endif
#ifdef DLT_PPP_ETHER
		case DLT_PPP_ETHER:
			printf("Data Link Type: PPPoE.\n");
			break;
#endif
#ifdef DLT_C_HDLC
		case DLT_C_HDLC:
			printf("Data Link Type: Cisco PPP with HDLC framing.\n");
			break;
#endif
#ifdef DLT_IEEE802_11
		case DLT_IEEE802_11:
			printf("Data Link Type: IEEE 802.11 wireless LAN.\n");
			break;
#endif
#ifdef DLT_LOOP
		case DLT_LOOP:
			printf("Data Link Type: OpenBSD loopback encapsulation.\n");
			break;
#endif
#ifdef DLT_LTALK
		case DLT_LTALK:
			printf("Data Link Type: Apple LocalTalk.\n");
			break;
#endif
		default:
			printf("%d is an unknown Data Link Transport\n", type);
	}

	return 0;
}

int
usage(void)
{
	puts("d: Specify device to use (eth0, hme0, etc.)");
	puts("v: Set verbose mode");
	puts("h: Print this usage");

	exit(0);
}

int
main(int argc, char *argv[])
{
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE]="";
	struct bpf_program filter;
	/*
	** Filter Expression: 01:00:0c:cc:cc:cc Multicast Mac Address
	** ether[20:2] = 0x2000: CDP signature in LLC
	*/
	char filter_app[] = "ether host 01:00:0c:cc:cc:cc and ether[20:2] = 0x2000";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;
	char version[] = "1.0.2";

	int c,sd=0,verbose=0;


	/* Print out header */
	printf("cdpr - Cisco Discovery Protocol Reporter Version %s\n", version);
	printf("Copyright (c) 2002 - MonkeyMental.com\n\n");

	/* Check command-line options */
	while((c = getopt(argc, argv, "d:vh")) !=EOF)
		switch(c)
		{
			case 'd':
				sd = 1;
				dev = optarg;
				break;
			case 'v':
				verbose++;
				break;
			case 'h':
			case '?':
				usage();
				break;
		}

	/* Get a pcap capable device */
	if(sd != 1)
	{
		if((dev = pcap_lookupdev(errbuf)) == NULL)
		{
			printf("Error finding device (%s)\n", errbuf);
			exit(1);
		}
	}

    printf("Using Device: %s\n", dev);

	/* Get the network number and netmask */
	pcap_lookupnet(dev, &net, &mask, errbuf);

	/* Open the pcap device */
	if((handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf)) == NULL)
	{
		printf("Error opening device (%s)\n", errbuf);
		exit(1);
	}
	else if (strlen(errbuf))
	{
		printf("Warning opening device (%s)\n", errbuf);
	}

	/* Compile the pcap filter */
	pcap_compile(handle, &filter, filter_app, 0, net);

	/* Activate the pcap filter */
	pcap_setfilter(handle, &filter);

	/* Get the next packet that comes in, we only need one */
	printf("Waiting for CDP advertisement, default config is to transmit CDP packets every 60 seconds\n");
	packet = pcap_next(handle, &header);

	/* Print its length */
	if(verbose > 0)
	{
		printf("Received a CDP packet, header length: %d\n", header.len);
	}

	// print cdp packet, 22 bytes into packet
	print_cdp_packet (packet+22, header.len-22, verbose);

	if (verbose > 1)
	{
		print_dlt(handle);
	}
	
	pcap_close(handle);
	return(0);
}
