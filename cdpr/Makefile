# Seems that RedHat keeps the pcap headers elsewhere...
# Uncomment the below line for RH systems.
#CFLAGS=-Wall -ggdb -lpcap -I/usr/include/pcap

# Standard build with pcap installed on the system
CFLAGS = -Wall -W -O2 -ggdb

# Build for the Zaurus with the pcap headers/libs one dir up
#CFLAGS = -DZAURUS -Wall -I. -I../libpcap-0.7.1 -L../libpcap-0.7.1 -ggdb

# Build for Solaris with the pcap headers/libs one dir up
#CFLAGS = -DSOLARIS -Wall -I. -I../libpcap-0.7.1 -L../libpcap-0.7.1 -ggdb

LDFLAGS = -lpcap

# Build for Solaris
#LDFLAGS = -lsocket -lnsl -lpcap

cdpr: cdpr.c cdprs.c conffile.c timeout.c pktcap.c cdp.h cdpr.h
	gcc $(CFLAGS) cdpr.c cdprs.c conffile.c timeout.c pktcap.c $(LDFLAGS) -o cdpr

clean:
	rm -f cdpr

