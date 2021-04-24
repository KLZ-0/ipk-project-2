#include <iostream>
#include <ifaddrs.h>
#include <net/if.h>
#include <pcap.h>
#include <functional>
#include "sniffer.h"

static Config *glob_config;

Sniffer::Sniffer(int argc, char **argv) {
	config = new Config(argc, argv);
	glob_config = config;
	if (config->only_interfaces) {
		print_interfaces();
		delete config;
		std::exit(EXIT_SUCCESS);
	}
}

Sniffer::~Sniffer() {
	delete config;
}

void Sniffer::print_interfaces() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *dev;

	// NOTE: pcap_findalldevs in C++ does some weird allocations which cause SyscallParam warnings in valgrind
	if (pcap_findalldevs(&dev, errbuf) == PCAP_ERROR) {
		std::cerr << "PCAP error: " << errbuf << std::endl;
		return;
	}

	std::cout << "Available interfaces: " << std::endl;
	while (dev != nullptr) {
		std::cout << dev->name << std::endl;
		dev = dev->next;
	}

	pcap_freealldevs(dev);
}

void Sniffer::run() {
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *pcap = pcap_create(config->interface.c_str(), errbuf);
	if (pcap == nullptr) {
		throw std::runtime_error(errbuf);
	}

	pcap_set_snaplen(pcap, 16);
	pcap_set_promisc(pcap, 0);
	pcap_set_rfmon(pcap, 0);
	pcap_set_timeout(pcap, 0);
	pcap_set_immediate_mode(pcap, 1);

	int pa = pcap_activate(pcap);
	if (pa < 0) {
		throw std::runtime_error(pcap_geterr(pcap));
	} else if (pa > 0) {
		std::cerr << "PCAP warning: " << pcap_geterr(pcap) << std::endl;
	}

	pcap_loop(pcap, config->num, packet_callback, nullptr);

	pcap_close(pcap);
}

void Sniffer::packet_callback(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes) {
	std::cout << "Packet size: " << header->caplen << "/" << header->len << std::endl;
}
