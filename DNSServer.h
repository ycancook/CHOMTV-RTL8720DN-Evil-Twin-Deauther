#pragma once

#include <Arduino.h>
#include <lwip/udp.h>
#include <lwip/ip4_addr.h>
#include "WiFi.h"

#define DNS_HEADER_SIZE 12
#define DNS_SERVER_PORT 53
#define DNS_MAX_RESPONSE_SIZE 512
#define DNS_MAX_DOMAIN_LENGTH 255

#define DNS_FLAG_RESPONSE 0x8580
#define DNS_FLAG_REFUSED  0x8185
#define DNS_ANSWER_TTL    60
#define DNS_NAME_POINTER  0x0C

struct DNSHeader {
	uint16_t ID;
	union {
		struct {
			uint16_t RD     : 1;
			uint16_t TC     : 1;
			uint16_t AA     : 1;
			uint16_t OPCode : 4;
			uint16_t QR     : 1;
			uint16_t RCode  : 4;
			uint16_t Z      : 3;
			uint16_t RA     : 1;
		};
		uint16_t Flags;
	};
	uint16_t QDCount;
	uint16_t ANCount;
	uint16_t NSCount;
	uint16_t ARCount;
};

struct DNSQuestion {
	const uint8_t* QName;
	uint16_t QNameLength;
	uint16_t QType;
	uint16_t QClass;
};

class DNSServer {
public:
	DNSServer();
	void start();
	void start(IPAddress resolvedIP);
	void stop();
	void begin();
	bool isSingleQuestion(const DNSHeader& header);
	void setResolvedIP(uint8_t ip0, uint8_t ip1, uint8_t ip2, uint8_t ip3);
	void enableDebug(bool enable);

private:
	uint32_t _resolvedIP;
	uint8_t _response_buffer[DNS_MAX_RESPONSE_SIZE];
	struct udp_pcb* _dns_server_pcb;
	bool _debug;

	static void handlePacketStatic(void* arg, struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port);
	void handlePacket(struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port);
	void handleValidRequest(struct udp_pcb* pcb, struct pbuf* request, const ip_addr_t* addr, u16_t port, DNSHeader& header);
	void handleInvalidRequest(struct udp_pcb* pcb, struct pbuf* request, const ip_addr_t* addr, u16_t port);
};