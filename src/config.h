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

	std::string interface = "any"; ///< listening interface
	int port = -1; ///< listening port (-1 == any)
	bool tcp = false; ///< only TCP
	bool udp = false; ///< only UDP
	bool arp = false; ///< only ARP
	bool icmp = false; ///< only ICMP
	int num = 1; ///< number of captured packets

	bool only_interfaces = false; ///< only show interfaces and exit
};


#endif //IPK_SNIFFER_CONFIG_H
