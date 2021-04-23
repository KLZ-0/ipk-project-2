#include <iostream>
#include <pcap/pcap.h>
#include "config.h"
#include "sniffer.h"

int main(int argc, char *argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_init(0, errbuf)) {
		std::cerr << "PCAP initialization error: " << errbuf << std::endl;
		return EXIT_FAILURE;
	}

	Sniffer sniffer = Sniffer(argc, argv);

	try {
		sniffer.run();
	} catch (std::runtime_error &e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
