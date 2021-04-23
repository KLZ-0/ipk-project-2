#include <iostream>
#include "config.h"
#include "sniffer.h"

int main(int argc, char *argv[]) {
	auto *sniffer = new Sniffer(argc, argv);
	sniffer->run();
	delete sniffer;
	return 0;
}
