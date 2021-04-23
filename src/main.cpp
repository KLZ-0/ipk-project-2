#include <iostream>
#include "config.h"
#include "sniffer.h"

int main(int argc, char *argv[]) {
	Sniffer sniffer = Sniffer(argc, argv);
	sniffer.run();
	return 0;
}
