add_executable(ipk-sniffer main.cpp config.cpp config.h sniffer.cpp sniffer.h)

target_link_libraries(ipk-sniffer pcap)
