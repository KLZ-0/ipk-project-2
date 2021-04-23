#include <iostream>
#include "sniffer.h"

Sniffer::Sniffer(int argc, char **argv) {
	config = new Config(argc, argv);
	if (config->only_interfaces()) {
		print_interfaces();
		delete config;
		std::exit(EXIT_SUCCESS);
	}
}

void Sniffer::run() {
	config->print();
}

Sniffer::~Sniffer() {
	delete config;
}

void Sniffer::print_interfaces() {
	std::cout << "interfaces" << std::endl;
}
