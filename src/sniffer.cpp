#include <iostream>
#include <ifaddrs.h>
#include <pcap.h>
#include <functional>
#include <net/ethernet.h>
#include "sniffer.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <pcap/sll.h>

#define RFC3339_BUFLEN 128

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

	pcap_set_snaplen(pcap, 1024);
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

	header_type = pcap_datalink(pcap);
	switch (header_type) {
		case DLT_EN10MB:
		case DLT_LINUX_SLL2:
		case DLT_LINUX_SLL:
			break;
		default:
			pcap_close(pcap);
			throw std::runtime_error("unsupported link-layer header type");
	}

	struct bpf_program program = set_filter(pcap);

	if (pcap_loop(pcap, config->num, packet_callback, (u_char*) this)) {
		pcap_freecode(&program);
		pcap_close(pcap);
		throw std::runtime_error(pcap_geterr(pcap));
	}

	pcap_freecode(&program);
	pcap_close(pcap);
}

struct bpf_program Sniffer::set_filter(pcap_t *pcap) {
	// TODO: Optimize this
	std::string program_str;

	if (config->arp) {
		program_str = "arp";
	}

	if (config->icmp) {
		if (!program_str.empty()) {
			program_str += " or ";
		}
		program_str += "icmp or icmp6";
	}

	if (config->tcp) {
		if (!program_str.empty()) {
			program_str += " or ";
		}
		program_str += "tcp";
	}

	if (config->udp) {
		if (!program_str.empty()) {
			program_str += " or ";
		}
		program_str += "udp";
	}

	if (program_str.empty()) {
		program_str = "arp or icmp or tcp or udp";
	}

	if (config->port >= 0) {
		program_str += " && port " + std::to_string(config->port);
	}

	struct bpf_program program = {0};
	if (pcap_compile(pcap, &program, program_str.c_str(), 0, PCAP_NETMASK_UNKNOWN)) {
		pcap_close(pcap);
		throw std::runtime_error(pcap_geterr(pcap));
	}

	if (pcap_setfilter(pcap, &program)) {
		pcap_freecode(&program);
		pcap_close(pcap);
		throw std::runtime_error(pcap_geterr(pcap));
	}

	return program;
}

void print_time(struct timeval timeval) {
	struct tm *timestruct = localtime(&timeval.tv_sec);
	char buf[RFC3339_BUFLEN];
	size_t l;

	l = strftime(buf, RFC3339_BUFLEN - 1, "%FT%T", timestruct);
	if (l == 0) {
		return;
	}

	std::cout << buf << "." << std::to_string(timeval.tv_usec % 1000);

	l = strftime(buf, RFC3339_BUFLEN - 1, "%z", timestruct);
	if (l != 5) {
		std::cout << std::endl;
		return;
	}

	std::cout << buf[0] << buf[1] << buf[2] << ":" << buf[3] << buf[4]; // +-\d\d:\d\d
}

void Sniffer::packet_callback(u_char *user, const struct pcap_pkthdr *header, const u_char *payload) {
	auto *sniffer = (Sniffer*) user;

//	čas IP : port > IP : port, length délka
//	offset_vypsaných_bajtů:  výpis_bajtů_hexa výpis_bajtů_ASCII

	print_time(header->ts);
	std::cout << std::endl;

	std::cout << "Packet (";

	// also remove header by incrementing the data pointer
	uint16_t packet_type = 0;
	if (sniffer->header_type == DLT_EN10MB) {
		auto *eth_header = (struct ether_header *) payload;
		packet_type = ntohs(eth_header->ether_type);
		payload += sizeof(struct ether_header);
	} else if (sniffer->header_type == DLT_LINUX_SLL) {
		auto *eth_header = (struct sll_header *) payload;
		packet_type = ntohs(eth_header->sll_protocol);
		payload += sizeof(struct sll_header);
	} else if (sniffer->header_type == DLT_LINUX_SLL2) {
		auto *eth_header = (struct sll2_header *) payload;
		packet_type = ntohs(eth_header->sll2_protocol);
		payload += sizeof(struct sll2_header);
	} else {
		std::cerr << "warning: unsupported link-layer header type" << std::endl;
	}

	// link layer protocols

	uint8_t packet_prot = 0;
	char src_addr[INET6_ADDRSTRLEN] = {0};
	char dst_addr[INET6_ADDRSTRLEN] = {0};
	if (packet_type == ETHERTYPE_IP) {
		auto *packet = (struct iphdr *) payload;
		packet_prot = packet->protocol;
		inet_ntop(AF_INET, &packet->saddr, src_addr, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET, &packet->daddr, dst_addr, INET6_ADDRSTRLEN);
		std::cout << "IP";
	} else if (packet_type == ETHERTYPE_IPV6) {
		auto *packet = (struct ip6_hdr *) payload;
		packet_prot = packet->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		inet_ntop(AF_INET6, &packet->ip6_src, src_addr, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &packet->ip6_dst, dst_addr, INET6_ADDRSTRLEN);
		std::cout << "IPv6";
	} else if (packet_type == ETHERTYPE_ARP) {
		std::cout << "ARP";
	} else {
		std::cout << "Other (" << packet_type << ")";
	}

	std::cout << "), size: " << header->caplen << "/" << header->len << std::endl;

//	std::cout << "from: " << ether_ntoa((struct ether_addr *) eth_header->ether_shost) << std::endl;
//	std::cout << "to: " << ether_ntoa((struct ether_addr *) eth_header->ether_dhost) << std::endl;

	std::cout << "protocol: ";

	// transport layer protocols

	switch (packet_prot) {
		case IPPROTO_TCP:
			std::cout << "TCP";
			break;
		case IPPROTO_UDP:
			std::cout << "UDP";
			break;
		case IPPROTO_ICMPV6:
		case IPPROTO_ICMP:
			std::cout << "ICMP";
			break;
		default:
			std::cout << "other";
			break;
	}

	std::cout << std::endl;

	std::cout << "from: " << src_addr << std::endl;
	std::cout << "to: " << dst_addr << std::endl;
	std::cout << std::endl;
}
