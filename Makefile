all: ipk-sniffer
.PHONY: all clean

ipk-sniffer: src/main.cpp src/config.cpp src/sniffer.cpp
	g++ -Isrc -lpcap $^ -o $@

clean:
	rm -f ipk-sniffer
