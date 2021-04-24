#include <iostream>
#include <ifaddrs.h>
#include <net/if.h>
#include <pcap.h>
#include <functional>
#include <net/ethernet.h>
#include "sniffer.h"

#include <netinet/ip_icmp.h>

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
		pcap_close(pcap);
		throw std::runtime_error(pcap_geterr(pcap));
	} else if (pa > 0) {
		std::cerr << "PCAP warning: " << pcap_geterr(pcap) << std::endl;
	}

	if (pcap_set_datalink(pcap, DLT_EN10MB)) {
		pcap_close(pcap);
		throw std::runtime_error(pcap_geterr(pcap));
	}

	if (pcap_loop(pcap, config->num, packet_callback, (u_char*) this)) {
		pcap_close(pcap);
		throw std::runtime_error(pcap_geterr(pcap));
	}

	pcap_close(pcap);
}

void Sniffer::packet_callback(u_char *user, const struct pcap_pkthdr *header, const u_char *payload) {
	auto *sniffer = (Sniffer*) user;

	std::cout << "Packet (";

	auto *eth_header = (struct ether_header *) payload;
	uint16_t packet_type = ntohs(eth_header->ether_type);

	switch (packet_type) {
		case ETHERTYPE_IP:
			std::cout << "IP";
			break;
		case ETHERTYPE_IPV6:
			std::cout << "IPv6";
			break;
		case ETHERTYPE_ARP:
			std::cout << "ARP";
			break;
		case ETHERTYPE_REVARP:
			std::cout << "Reverse ARP";
			break;
		default:
			std::cout << "Other";
	}

	std::cout << "), size: " << header->caplen << "/" << header->len << std::endl;
}
