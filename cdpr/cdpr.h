/*
* cdpr - Cisco Discovery Protocol Reporter
* Copyright (c) 2002-2003 MonkeyMental.com
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
*/

#ifndef CDPR_H
#define CDPR_H

/*
** Includes
*/
#include "pcap.h"

/*
** Defines
*/
#define CDPRS_INIT 1
#define CDPRS_SETIP 2
#define CDPRS_DATA 3
#define CDPRS_SEND 4

struct singleton
{
	struct pcap_pkthdr *hdr;
	const u_char *pkt;
};

/*
** Global variables
*/
int timeout;
int cdprs;
pcap_t *handle;

/*
** Function Prototypes
*/
int	cdprs_action(int action, char *string, int verbose);
void set_location(char *loc);
void get_hostname(int nameoverride, char *name);
void read_file(char *file);
char * urlencode(char *s, int slen, int *new_len);
int enable_timeout(void);
int set_timeout(unsigned int seconds);
const u_char * pkt_next(pcap_t *p, struct pcap_pkthdr *h);
void do_something_with(char *ip, char *url);


#endif
