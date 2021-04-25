#ifndef IPK_SNIFFER_CONFIG_H
#define IPK_SNIFFER_CONFIG_H

#include <string>

/**
 * @class Config
 * Used for argument parsing & parsed data persistance
 */
class Config
{
private:
	/**
	 * Parses argc and argv - invoked from the constructor
	 * @param argc argc
	 * @param argv argv
	 */
	void parse(int argc, char *argv[]);

	/**
	 * Prints help if the -h or --help arguments are present
	 */
	static void print_help();

public:
	/**
	 * Parses and constructs an object from argc and argv
	 * @param argc argc
	 * @param argv argv
	 */
	Config(int argc, char *argv[]);

	/**
	 * Print internal state - used for debugging
	 */
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
