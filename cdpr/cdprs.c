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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if WIN32
#include "Winsock2.h"
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include "cdpr.h"

#ifdef WIN32
void
win32_socket_init()
{
	WSADATA wsaData;

	if(WSAStartup(MAKEWORD(1, 1), &wsaData) != 0)
	{
		puts("WSAStartup Failed");
		exit(1);
	}
}

void
win32_socket_cleanup()
{
    WSACleanup();
}
#endif

void
cdprs_footer(void)
{
	char *footer=" HTTP/1.0\r\n\r\n";
	cdprs_action(CDPRS_DATA, footer,1);
//	strcat(msg,footer);
}

void
get_hostname(int nameoverride, char *name)
{
	char *hheader="&host=";

	cdprs_action(CDPRS_DATA, hheader, 0);

	if(!nameoverride)
	{
		char uname[256];
		gethostname(uname, sizeof(uname));
		cdprs_action(CDPRS_DATA, uname, 0);
	}
	else
	{
		cdprs_action(CDPRS_DATA, name, 0);
	}
		
}

void
set_location(char *loc)
{
	char location[500]={0};
	int loc_len = 0;
	char *url = urlencode (loc, strlen (loc), &loc_len);
	if (url)
    {
        sprintf(location, "&loc=%s", url);
        free (url);
    }
	cdprs_action(CDPRS_DATA, location, 0);
}

char *
urlencode(char *s, int slen, int *new_len)
{
	register int x, y;
	unsigned char *str;
	static unsigned const char hexchars[] = "0123456789ABCDEF";

	str = (unsigned char *) malloc(3 * slen + 1);
	if(str==NULL)
	{
		puts("malloc failed");
		exit(1);
	}
	else
	{
		memset(str, 0, (3*slen+1));
	}

	for (x = 0, y = 0; slen--; x++, y++)
	{
		str[y] = (unsigned char) s[x];
		if ((str[y] < '0' && str[y] != '-' && str[y] != '.') ||
			(str[y] < 'A' && str[y] > '9') ||
			(str[y] > 'Z' && str[y] < 'a' && str[y] != '_') ||
			(str[y] > 'z'))
			{
				str[y++] = '%';
				str[y++] = hexchars[(unsigned char) s[x] >> 4];
				str[y] = hexchars[(unsigned char) s[x] & 15];
			}
	}

	str[y] = '\0';
	if (new_len)
	{
		*new_len = y;
	}
	return ((char *) str);
}

int
send_update(char *ip, char *msg, int port, int verbose)
{
	int sockfd, msg_len, bytes_sent;
	struct sockaddr_in cdprs_addr;
	
	sockfd=socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0)
	{
		perror("socket");
		return 1;
	}
	
	cdprs_addr.sin_family = AF_INET;
	cdprs_addr.sin_port = htons(port);
	cdprs_addr.sin_addr.s_addr = inet_addr(ip);
	memset(&(cdprs_addr.sin_zero), '\0', 8);
	
	if(verbose >=2)
	{
		printf("Message: %s\n", msg);
	}
	if(connect(sockfd, (struct sockaddr *)&cdprs_addr, sizeof(struct sockaddr)) < 0)
	{
		perror("connect");
		return 1;
	}
	
	msg_len = strlen(msg);
	bytes_sent = send(sockfd, msg, msg_len, 0);
	if(bytes_sent < 0)
	{
		perror("send");
		return 1;
	}
	
	if(verbose >=2)
	{
		printf("Sent %d of %d bytes\n", bytes_sent, msg_len);
	}
	
	if(shutdown(sockfd,2) < 0)
	{
		perror("shutdown");
		return 1;
	}


	
	return 0;
}

int
cdprs_action(int action, char *string, int verbose)
{
	static char *msg;
	static char *ip;
	static int port;
	static int init_done = 0;
	const char http_hdr[] = "GET ";

	switch(action)
	{
		case CDPRS_INIT:
			/* Init msg buffer, malloc mem, put in header, etc.*/
			if(!init_done)
			{
				msg=malloc(4096);
				if(msg == NULL)
				{
					printf("malloc failed\n");
					exit(1);
				}
				else
				{
					memset(msg, 0, 4096);
					strcpy(msg, http_hdr);
#ifdef WIN32
					win32_socket_init();
#endif
					/* Get the IP and URL from the config file */
					if(strlen(string))
					{
						read_file(string);
					}
					init_done = 1;
				}
			}
			break;
		case CDPRS_SETIP:
			/* Set IP Address */
			ip = string;
			break;
		case CDPRS_SETPORT:
			/* Set the network port */
			port = verbose;
			break;
		case CDPRS_DATA:
			/* Append string to msg */
			strcat(msg,string);
			break;
		case CDPRS_SEND:
			/* Tack on the hostname and footer and send data to server */
//			get_hostname();
			cdprs_footer();
			send_update(ip,msg,port,verbose);
			/* We have sent the msg to the server, free the mem used by msg */
			free(msg);
#ifdef WIN32
			win32_socket_cleanup();
#endif
			break;
		default:
			/* No default action */
			break;
	}

	return 0;
}


