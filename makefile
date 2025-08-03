LDLIBS += -lpcap

all: send-arp-pk

send-arp-pk: send-arp-pk.cpp get-my-mac.cpp NetworkHeader/arp.cpp NetworkHeader/ethernet.cpp NetworkHeader/ipv4.cpp NetworkHeader/tcp.cpp NetworkHeader/addr_cast.cpp
	g++ -Wall -std=c++11 $^ -o $@ $(LDLIBS)

clean:
	rm -f send-arp-pk *.o

.PHONY: all clean