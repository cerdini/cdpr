#include "stdio.h"
#include "string.h"
#include "cdpr.h"

#if WIN32
#include "Winsock2.h"
#else
#include "sys/socket.h"
#include "netinet/in.h"
#include "arpa/inet.h"
#include "netdb.h"
#endif

int
is_ip (char *cp)
{
	// Return true if we can convert cp into an ip address, false if not.
	// This test may be too simplistic as inet_addr() accepts "1.2.3.4",
	// "1.2.3", "1.2", and "1" as valid ip addresses.

	if (cp && *cp)
	{
		return inet_addr (cp) != INADDR_NONE;
	}
	return 0;
}

void
do_something_with (char *ip, char *url)
{
	struct hostent *h;

	if (ip && url)
	{
		if (is_ip (ip))
		{
/*			printf ("ip addr  = \"%s\", url = \"%s\"\n", ip, url); */
			cdprs_action(CDPRS_SETIP, ip, 1);
			cdprs_action(CDPRS_DATA, url, 1);
			/* Add the ? to the end of the url */
			cdprs_action(CDPRS_DATA, "?", 1);
		}
		else
		{
/*			printf ("hostname = \"%s\", url = \"%s\"\n", ip, url); */
			/* Get the IP of the hostname */
			if((h=gethostbyname(ip)) == NULL)
			{
				herror("gethostbyname");
				exit(1);
			}
			else
			{
				cdprs_action(CDPRS_SETIP, inet_ntoa(*((struct in_addr *)h->h_addr)), 1);
				cdprs_action(CDPRS_DATA, url, 1);
				/* Add the ? to the end of the url */
				cdprs_action(CDPRS_DATA, "?", 1);
			}

		}
	}
}

void
process_line (char *buf)
{
	if (buf)
	{
		char *ip = strtok (buf, " \t");
		if (ip)
		{
			if (*ip == '#')
			{
				// Ignore lines beginning with '#' as comments
			}
			else
			{
				char *url = strtok (NULL, " \t\n");
				if (url)
				{
					do_something_with (ip, url);
				}
			}
		}
	}
}

void
read_fp (FILE *fp)
{
	// Read the file line by line

	if (fp)
	{
		char buf[666] = {0};

		while (fgets (buf, sizeof (buf)-1, fp) != NULL)
		{
			process_line (buf);
		}
	}
}

void
read_file (char *file)
{
	// Open the file

	if (file && *file)
	{
		FILE *fp = fopen (file, "r");
		if (fp == NULL)
		{
			printf ("Can't open ");
			perror (file);
		}
		else
		{
			read_fp (fp);
			fclose (fp);
		}
	}
}

/*
int
main (int argc, char **argv)
{
	if (argc == 1)
	{
		// If no command line arguments, put up help
		puts ("usage: ReadWebIp [config filenames]");
	}
	else
	{
		// Read each file on command line
		while (--argc)
		{
			read_file (*++argv);
		}
	}
	return 0;
}
*/
