#ifndef IPK_SNIFFER_SNIFFER_H
#define IPK_SNIFFER_SNIFFER_H


#include "config.h"

class Sniffer
{
private:
	Config *config;

	static void print_interfaces();
	static void packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *payload);

public:
	Sniffer(int argc, char *argv[]);
	virtual ~Sniffer();

	void run();
};


#endif //IPK_SNIFFER_SNIFFER_H
