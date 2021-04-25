#ifndef IPK_SNIFFER_SNIFFER_H
#define IPK_SNIFFER_SNIFFER_H

#include "config.h"
#include <pcap/pcap.h>

class Sniffer
{
private:
	Config *config;

	/**
	 * Data link header type
	 * determined by pcap_datalink
	 * used in packet callback when determining which header the packet is encapsulated in
	 */
	int header_type;

	/**
	 * List interfaces which can be opened by pcap_create to stdout
	 */
	static void print_interfaces();

	/**
	 * Print time given by timeval in RFC3339 format with millisecond precision to stdout
	 * @param timeval timestamp to be converted
	 */
	static void print_time(struct timeval timeval);

	/**
	 * Packet examination callback
	 * Called from pcap_loop
	 * Receives a reference to an instance of this class
	 * @param user arbitrary pointer to the instance of this class -> needs to be recast
	 * @param header packet header
	 * @param payload packet data
	 */
	static void packet_callback(u_char *user, const struct pcap_pkthdr *header, const u_char *payload);

	/**
	 * Constructs, compiles and applies the appropriate pcap filter program to the given pcap handle
	 * @param pcap pcap handle
	 * @return reference to the compiled program which can later be freed
	 */
	struct bpf_program set_filter(pcap_t *pcap);

public:
	/**
	 * Initializes sniffer with arguments from argc and argv
	 * @param argc argc
	 * @param argv argv
	 */
	Sniffer(int argc, char *argv[]);

	/**
	 * Destructor also frees the allocated config instance
	 */
	virtual ~Sniffer();

	/**
	 * Run the sniffer
	 * @throws std::runtime_error for when an error occurs
	 */
	void run();
};


#endif //IPK_SNIFFER_SNIFFER_H
