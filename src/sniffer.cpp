#include <iostream>
#include <ifaddrs.h>
#include <net/if.h>
#include <pcap.h>
#include "sniffer.h"

Sniffer::Sniffer(int argc, char **argv) {
	config = new Config(argc, argv);
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

	if (pcap_findalldevs(&dev, errbuf) == PCAP_ERROR) {
		std::cerr << "PCAP eror: " << errbuf << std::endl;
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
	config->print();
}
