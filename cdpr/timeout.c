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
*/

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "cdpr.h"

void
timeout_recvd(int signum)
{
	printf("Timeout received. (signal: %d)\n", signum);
	exit(1);
}

int
enable_timeout(void)
{
	struct sigaction sastruct;

	sastruct.sa_handler = (void *)timeout_recvd;
	sastruct.sa_flags = SA_RESETHAND;
	
	return sigaction(SIGALRM, &sastruct, NULL);
}

int
set_timeout(unsigned int seconds)
{
	/*
	** Set the alarm time. CDPR will have ~seconds to get a CDP
	** packet before the alarm goes off. It should be a sufficient
	** time to do whatever needs to be done before searching for a
	** packet plus the time to search for a packet.
	*/

	return alarm(seconds);
}
