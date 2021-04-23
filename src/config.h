#ifndef IPK_SNIFFER_CONFIG_H
#define IPK_SNIFFER_CONFIG_H

#include <string>

class Config
{
private:
	std::string interface = "all";
	int port = -1; // default ports all
	bool tcp = false;
	bool udp = false;
	bool arp = false;
	bool icmp = false;
	int num = 1; // default 1 packet

	bool only_print_interfaces = false;

	void parse(int argc, char *argv[]);

public:
	Config(int argc, char *argv[]);
	void print();

	bool only_interfaces();
};


#endif //IPK_SNIFFER_CONFIG_H
