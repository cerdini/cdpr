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

#ifndef WIN32
#include <netinet/in.h>
#endif

/* Define the constants and text values for the 'type' field: */
#define TYPE_DEVICE_ID			0x0001
#define TYPE_ADDRESS			0x0002
#define TYPE_PORT_ID			0x0003
#define TYPE_CAPABILITIES		0x0004
#define TYPE_IOS_VERSION		0x0005
#define TYPE_PLATFORM			0x0006
#define TYPE_IP_PREFIX			0x0007

#define TYPE_VTP_MGMT_DOMAIN		0x0009
#define TYPE_NATIVE_VLAN		0x000a
#define TYPE_DUPLEX			0x000b

struct
{
    int type;
    char *val;
}
type_vals[] = {
	{ TYPE_DEVICE_ID,       "Device ID" },
	{ TYPE_ADDRESS,         "Addresses" },
	{ TYPE_PORT_ID,         "Port ID" },
	{ TYPE_CAPABILITIES,    "Capabilities" },
	{ TYPE_IOS_VERSION,     "Software version" },
	{ TYPE_PLATFORM,        "Platform" },
	{ TYPE_IP_PREFIX,       "IP Prefix (used for ODR)" },
	{ TYPE_VTP_MGMT_DOMAIN, "VTP Management Domain" },
	{ TYPE_NATIVE_VLAN,     "Native VLAN" },
	{ TYPE_DUPLEX,          "Duplex" },
	{ 0,                    NULL },
};

typedef struct _cdp_packet_header
{
	u_int8_t  version;		// always one
	u_int8_t  time_to_live;	// in seconds
	u_int16_t checksum;		// ip checksum
} CDP_HDR;

typedef struct _cfp_packet_data
{
	u_int16_t type;			// see TYPE_ above
	u_int16_t length;		// total length of type/length/value
	//        value;		// variable length value
} CDP_DATA;

