#ifndef IPK_SNIFFER_SNIFFER_H
#define IPK_SNIFFER_SNIFFER_H


#include "config.h"

class Sniffer
{
private:
	Config *config;

	static void print_interfaces();

public:
	Sniffer(int argc, char *argv[]);
	virtual ~Sniffer();

	void run();
};


#endif //IPK_SNIFFER_SNIFFER_H
