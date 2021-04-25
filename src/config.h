#ifndef IPK_SNIFFER_CONFIG_H
#define IPK_SNIFFER_CONFIG_H

#include <string>

class Config
{
private:
	void parse(int argc, char *argv[]);
	static void print_help();

public:
	Config(int argc, char *argv[]);
	void print();

	std::string interface = "any";
	int port = -1; // default ports all
	bool tcp = false;
	bool udp = false;
	bool arp = false;
	bool icmp = false;
	int num = 1; // default 1 packet

	bool only_interfaces = false;
};


#endif //IPK_SNIFFER_CONFIG_H
