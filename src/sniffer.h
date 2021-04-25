#ifndef IPK_SNIFFER_SNIFFER_H
#define IPK_SNIFFER_SNIFFER_H

#include "config.h"
#include <pcap/pcap.h>

class Sniffer
{
private:
	Config *config;
	int header_type;

	static void print_interfaces();
	static void packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *payload);

public:
	Sniffer(int argc, char *argv[]);
	virtual ~Sniffer();

	struct bpf_program set_filter(pcap_t *pcap);
	void run();
};


#endif //IPK_SNIFFER_SNIFFER_H
