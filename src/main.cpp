#include <iostream>
#include "config.h"
#include "sniffer.h"

int main(int argc, char *argv[]) {
	Sniffer sniffer = Sniffer(argc, argv);

	try {
		sniffer.run();
	} catch (std::runtime_error &e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
