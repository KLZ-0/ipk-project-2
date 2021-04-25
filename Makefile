all: ipk-sniffer
.PHONY: all clean

ipk-sniffer: src/main.cpp src/config.cpp src/config.h src/sniffer.cpp src/sniffer.h
	g++ -Isrc -lpcap $^ -o $@

clean:
	rm -f ipk-sniffer
