all: ipk-sniffer
.PHONY: all clean pack

ipk-sniffer: src/main.cpp src/config.cpp src/config.h src/sniffer.cpp src/sniffer.h
	g++ -Isrc -lpcap $^ -o $@

pack:
	tar --exclude=CMakeLists.txt -cvf xkalaz00.tar src Makefile README manual.pdf

clean:
	rm -f ipk-sniffer
