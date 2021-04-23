#include <cstdlib>
#include <cstring>
#include <iostream>
#include "config.h"

Config::Config(int argc, char *argv[]) {
	parse(argc, argv);

	if (!(tcp || udp || arp || icmp)) {
		tcp = udp = arp = icmp = true;
	}
}

void Config::parse(int argc, char *argv[]) {
	char *arg;
	char *nextarg;

	for (int argi = 1; argi < argc; argi++) {
		arg = argv[argi];
		nextarg = (argi + 1 < argc) ? argv[argi + 1] : nullptr;

		if (std::strlen(arg) < 2) {
			std::cerr << "'-' is not an option" << std::endl;
			std::exit(EXIT_FAILURE);
		}

		if (arg[0] == '-' && arg[1] == '-') {
			arg = arg + 2;
			if (std::strcmp(arg, "interface") == 0) {
				if (nextarg == nullptr || nextarg[0] == '-') {
					only_interfaces = true;
					return;
				}
				interface = nextarg;
				argi++;
			}
			else if (std::strcmp(arg, "tcp") == 0) {
				tcp = true;
			}
			else if (std::strcmp(arg, "udp") == 0) {
				udp = true;
			}
			else if (std::strcmp(arg, "arp") == 0) {
				arp = true;
			}
			else if (std::strcmp(arg, "icmp") == 0) {
				icmp = true;
			} else {
				std::cerr << "unknown option! see --help for all options" << std::endl;
				std::exit(EXIT_FAILURE);
			}
		} else if (arg[0] == '-' && arg[2] == '\0') {
			switch (arg[1]) {
				case 'i':
					if (nextarg == nullptr || nextarg[0] == '-') {
						only_interfaces = true;
						return;
					}
					interface = nextarg;
					argi++;
					break;

				case 't':
					tcp = true;
					break;

				case 'u':
					udp = true;
					break;

				case 'p':
					try {
						port = std::stoi(nextarg);
					} catch (std::invalid_argument &e) {
						std::cerr << "Conversion error" << std::endl;
						std::exit(EXIT_FAILURE);
					}
					argi++;
					break;

				case 'n':
					try {
						num = std::stoi(nextarg);
					} catch (std::invalid_argument &e) {
						std::cerr << "Conversion error" << std::endl;
						std::exit(EXIT_FAILURE);
					}
					argi++;
					break;

				default:
					std::cerr << "unknown option! see --help for all options" << std::endl;
					std::exit(EXIT_FAILURE);
			}
		} else {
			std::cerr << "unknown option! see --help for all options" << std::endl;
			std::exit(EXIT_FAILURE);
		}
	}
}

void Config::print() {
	std::cerr << "Interface: " << interface << std::endl;
	std::cerr << "port: " << port << std::endl;
	std::cerr << "num: " << num << std::endl;
	std::cerr << "tcp: " << tcp << std::endl;
	std::cerr << "udp: " << udp << std::endl;
	std::cerr << "arp: " << arp << std::endl;
	std::cerr << "icmp: " << icmp << std::endl;
}
