
packetfilter: main.c PacketFilter.c
	gcc -o PacketFilter main.c PacketFilter.c -lpcap
