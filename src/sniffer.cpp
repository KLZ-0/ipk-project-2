#include <iostream>
#include <ifaddrs.h>
#include <pcap.h>
#include <functional>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include "sniffer.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <pcap/sll.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ether.h>
#include <iomanip>

#define RFC3339_BUFLEN 128
#define PCAP_DEFAULT_SNAPLEN 65535
#define DATA_PER_LINE 0x0010u
#define DUMP_CHUNKSIZE 8

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

	pcap_set_snaplen(pcap, PCAP_DEFAULT_SNAPLEN);
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

	std::cout << buf << ".";
	std::cout << std::setfill('0') << std::setw(3) << timeval.tv_usec % 1000;

	l = strftime(buf, RFC3339_BUFLEN - 1, "%z", timestruct);
	if (l != 5) {
		std::cout << std::endl;
		return;
	}

	std::cout << buf[0] << buf[1] << buf[2] << ":" << buf[3] << buf[4]; // +-\d\d:\d\d
}

void Sniffer::packet_callback(u_char *user, const struct pcap_pkthdr *header, const u_char *payload) {
	const u_char *data_ptr = payload;
	auto *sniffer = (Sniffer*) user;

	char src_addr[INET6_ADDRSTRLEN] = {0};
	char dst_addr[INET6_ADDRSTRLEN] = {0};

	// also remove header by incrementing the data pointer
	struct ether_header eth_header = {0};
	if (sniffer->header_type == DLT_EN10MB) {
		eth_header = *(struct ether_header *) payload;
		payload += sizeof(struct ether_header);
	} else if (sniffer->header_type == DLT_LINUX_SLL) {
		eth_header.ether_type = ((struct sll_header *) payload)->sll_protocol;
		payload += sizeof(struct sll_header);
	} else if (sniffer->header_type == DLT_LINUX_SLL2) {
		eth_header.ether_type = ((struct sll2_header *) payload)->sll2_protocol;
		payload += sizeof(struct sll2_header);
	} else {
		std::cerr << "warning: unsupported link-layer header type" << std::endl;
	}

	// link layer

	uint16_t packet_type = ntohs(eth_header.ether_type);
	uint8_t packet_prot = 0;
	if (packet_type == ETHERTYPE_IP) {
		auto *packet = (struct iphdr *) payload;
		packet_prot = packet->protocol;
		inet_ntop(AF_INET, &packet->saddr, src_addr, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET, &packet->daddr, dst_addr, INET6_ADDRSTRLEN);
		payload += sizeof(struct iphdr);
	} else if (packet_type == ETHERTYPE_IPV6) {
		auto *packet = (struct ip6_hdr *) payload;
		packet_prot = packet->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		inet_ntop(AF_INET6, &packet->ip6_src, src_addr, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &packet->ip6_dst, dst_addr, INET6_ADDRSTRLEN);
		payload += sizeof(struct ip6_hdr);
	} else if (packet_type == ETHERTYPE_ARP) {
		char *tmp;
		tmp = ether_ntoa((struct ether_addr *) &eth_header.ether_shost);
		strncpy(src_addr, tmp, INET6_ADDRSTRLEN);
		tmp = ether_ntoa((struct ether_addr *) &eth_header.ether_dhost);
		strncpy(dst_addr, tmp, INET6_ADDRSTRLEN);
		payload += sizeof(struct arphdr);
	} else {
		std::cerr << "warning: unsupported header type" << std::endl;
	}

	// transport layer
	uint16_t *sport = nullptr;
	uint16_t *dport = nullptr;

	switch (packet_prot) {
		case IPPROTO_TCP:
			sport = &((struct tcphdr *) payload)->th_sport;
			dport = &((struct tcphdr *) payload)->th_dport;
			payload += sizeof(struct tcphdr);
			break;
		case IPPROTO_UDP:
			sport = &((struct udphdr *) payload)->uh_sport;
			dport = &((struct udphdr *) payload)->uh_dport;
			payload += sizeof(struct udphdr);
			break;
		case IPPROTO_ICMPV6:
			payload += sizeof(struct icmp6_hdr);
		case IPPROTO_ICMP:
			payload += sizeof(struct icmphdr);
		default:
			break;
	}

	// print the packet info
	// čas IP : port > IP : port, length délka

	print_time(header->ts);

	std::cout << " " << src_addr;
	if (sport != nullptr) {
		std::cout << " : " << *sport;
	}

	std::cout << " > " << dst_addr;
	if (dport != nullptr) {
		std::cout << " : " << *dport;
	}

	std::cout << ", length " << header->len << " bytes" << std::endl;

	// print the packet data
	// offset_vypsaných_bajtů:  výpis_bajtů_hexa výpis_bajtů_ASCII

	for (unsigned int offset = 0; offset < header->len; offset += DATA_PER_LINE) {
		printf("0x%04x: ", offset);
		unsigned int remaining = header->len - offset;

		// hex
		for (unsigned int in_offset = 0; in_offset < DATA_PER_LINE && in_offset < remaining; in_offset++) {
			if (in_offset % DUMP_CHUNKSIZE == 0) {
				std::cout << " ";
			}
			printf("%02x ", data_ptr[offset + in_offset]);
		}

		// printable
		std::cout << " ";
		for (unsigned int in_offset = 0; in_offset < DATA_PER_LINE && in_offset < remaining; in_offset++) {
			if (isprint(data_ptr[offset + in_offset])) {
				std::cout << data_ptr[offset + in_offset];
			} else {
				std::cout << ".";
			}
		}

		std::cout << std::endl;
	}
	std::cout << std::endl;
}
