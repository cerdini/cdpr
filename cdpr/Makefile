# Slackware keeps pcap headers in /usr/include
#CFLAGS = -Wall -ggdb

# Seems that RedHat keeps the pcap headers elsewhere...
# This doesn't break Slackware, and fixes RH and possible others.
CFLAGS=-Wall -ggdb -I/usr/include/pcap

LDFLAGS = -lpcap

cdpr: cdpr.c cdp.h
	gcc $(CFLAGS) cdpr.c $(LDFLAGS) -o cdpr

clean:
	rm -f cdpr

