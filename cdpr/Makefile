# Seems that RedHat keeps the pcap headers elsewhere...
# Uncomment the below line for RH systems.
#CFLAGS=-Wall -ggdb -lpcap -I/usr/include/pcap

CFLAGS = -Wall -ggdb
LDFLAGS = -lpcap

cdpr: cdpr.c cdp.h
	gcc $(CFLAGS) cdpr.c $(LDFLAGS) -o cdpr

clean:
	rm -f cdpr

