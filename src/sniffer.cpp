#include <iostream>
#include "sniffer.h"

Sniffer::Sniffer(int argc, char **argv) {
	config = new Config(argc, argv);
}

void Sniffer::run() {
	if (config->only_interfaces()) {
		print_interfaces();
		return;
	}

	config->print();
}

Sniffer::~Sniffer() {
	delete config;
}

void Sniffer::print_interfaces() {
	std::cout << "interfaces" << std::endl;
}
