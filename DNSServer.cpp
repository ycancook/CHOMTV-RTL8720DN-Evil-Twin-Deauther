#include "DNSServer.h"

DNSServer::DNSServer() {
	_resolvedIP = htonl((192 << 24) | (168 << 16) | (1 << 8) | 1); 
	_dns_server_pcb = nullptr;
	_debug = false;
}

void DNSServer::enableDebug(bool enable) {
	_debug = enable;
}

void DNSServer::setResolvedIP(uint8_t ip0, uint8_t ip1, uint8_t ip2, uint8_t ip3) {
	_resolvedIP = htonl((ip0 << 24) | (ip1 << 16) | (ip2 << 8) | ip3);
}

bool DNSServer::isSingleQuestion(const DNSHeader& header) {
	return ntohs(header.QDCount) == 1 && header.ANCount == 0 && header.NSCount == 0 && header.ARCount == 0;
}

void DNSServer::begin() {
	for (struct udp_pcb* pcb = udp_pcbs; pcb != nullptr; pcb = pcb->next) {
		if (pcb->local_port == DNS_SERVER_PORT) {
			if (_debug) Serial.println("Removing existing DNS PCB on port 53...");
			udp_remove(pcb);
		}
	}

	_dns_server_pcb = udp_new();
	if (!_dns_server_pcb) {
		if (_debug) Serial.println("Failed to create new DNS server PCB!");
		return;
	}

	if (udp_bind(_dns_server_pcb, IP4_ADDR_ANY, DNS_SERVER_PORT) != ERR_OK) {
		if (_debug) Serial.println("Failed to bind DNS server to port 53!");
		udp_remove(_dns_server_pcb);
		_dns_server_pcb = nullptr;
		return;
	}
	udp_recv(_dns_server_pcb, &DNSServer::handlePacketStatic, this);

	if (_debug) Serial.println("DNS server started on port 53.");
}

void DNSServer::start() {
	IPAddress ip = WiFi.localIP();
	setResolvedIP(ip[0], ip[1], ip[2], ip[3]);
	begin();
}

void DNSServer::start(IPAddress resolvedIP) {
	setResolvedIP(resolvedIP[0], resolvedIP[1], resolvedIP[2], resolvedIP[3]);
	begin();
}

void DNSServer::stop() {
	if (_dns_server_pcb) {
		udp_remove(_dns_server_pcb);
		_dns_server_pcb = nullptr;
		if (_debug) Serial.println("DNS server stopped.");
	}
}

void DNSServer::handlePacketStatic(void* arg, struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port) {
	DNSServer* server = static_cast<DNSServer*>(arg);
	server->handlePacket(pcb, p, addr, port);
}

void DNSServer::handlePacket(struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port) {
	if (!p || p->len < DNS_HEADER_SIZE) {
		if (p) pbuf_free(p);
		return;
	}

	DNSHeader header;
	memcpy(&header, p->payload, DNS_HEADER_SIZE);

	if ((ntohs(header.Flags) & 0x8000) != 0 || (ntohs(header.Flags) & 0x7800) != 0) {
		handleInvalidRequest(pcb, p, addr, port);
		pbuf_free(p);
		return;
	}

	if (isSingleQuestion(header)) {
		handleValidRequest(pcb, p, addr, port, header);
	} else {
		handleInvalidRequest(pcb, p, addr, port);
	}

	pbuf_free(p);
}

void DNSServer::handleValidRequest(struct udp_pcb* pcb, struct pbuf* request, const ip_addr_t* addr, u16_t port, DNSHeader& header) {
	uint16_t nameLen = 0;
	uint16_t offset = DNS_HEADER_SIZE;
	uint8_t* payload = (uint8_t*)request->payload;

	while (offset < request->len && payload[offset] != 0 && nameLen < DNS_MAX_DOMAIN_LENGTH) {
		offset++;
		nameLen++;
	}
	if (offset >= request->len - 4) return;
	offset++;
	nameLen++;

	DNSQuestion question;
	question.QName = payload + DNS_HEADER_SIZE;
	question.QNameLength = nameLen;
	question.QType = ntohs(*(uint16_t*)(payload + offset));
	question.QClass = ntohs(*(uint16_t*)(payload + offset + 2));

	if (question.QType != 1 || question.QClass != 1) {
		handleInvalidRequest(pcb, request, addr, port);
		return;
	}

	DNSHeader* rsp_hdr = (DNSHeader*)_response_buffer;
	rsp_hdr->ID = header.ID;
	rsp_hdr->Flags = htons(DNS_FLAG_RESPONSE);
	rsp_hdr->QDCount = htons(1);
	rsp_hdr->ANCount = htons(1);
	rsp_hdr->NSCount = 0;
	rsp_hdr->ARCount = 0;

	uint8_t* ptr = _response_buffer + sizeof(DNSHeader);
	memcpy(ptr, question.QName, question.QNameLength);
	ptr += question.QNameLength;

	*(uint16_t*)ptr = htons(1);      
	*(uint16_t*)(ptr + 2) = htons(1); 
	*(ptr + 4) = 0xC0;                
	*(ptr + 5) = DNS_NAME_POINTER;
	*(uint16_t*)(ptr + 6) = htons(1); 
	*(uint16_t*)(ptr + 8) = htons(1); 
	*(uint32_t*)(ptr + 10) = htonl(DNS_ANSWER_TTL); 
	*(uint16_t*)(ptr + 14) = htons(4); 
	*(uint32_t*)(ptr + 16) = _resolvedIP; 

	struct pbuf* response = pbuf_alloc(PBUF_TRANSPORT, sizeof(DNSHeader) + question.QNameLength + 20, PBUF_REF);
	if (!response) return;
	response->payload = _response_buffer;
	response->len = sizeof(DNSHeader) + question.QNameLength + 20;
	response->tot_len = response->len;

	if (udp_sendto(pcb, response, addr, port) != ERR_OK) {
		if (_debug) {
			Serial.print("Failed to send DNS reply to ");
			Serial.println(ipaddr_ntoa(addr));
		}
	} else if (_debug) {
		Serial.print("DNS Reply sent to ");
		Serial.println(ipaddr_ntoa(addr));
	}

	pbuf_free(response);
}

void DNSServer::handleInvalidRequest(struct udp_pcb* pcb, struct pbuf* request, const ip_addr_t* addr, u16_t port) {
	struct pbuf* response = pbuf_alloc(PBUF_TRANSPORT, request->len, PBUF_REF);
	if (!response) return;
	response->payload = _response_buffer;
	response->len = request->len;
	response->tot_len = request->len;

	memcpy(_response_buffer, request->payload, request->len);
	DNSHeader* hdr = (DNSHeader*)_response_buffer;
	hdr->Flags = htons(DNS_FLAG_REFUSED);

	if (udp_sendto(pcb, response, addr, port) != ERR_OK) {
		if (_debug) {
			Serial.print("Failed to send REFUSED response to ");
			Serial.println(ipaddr_ntoa(addr));
		}
	} else if (_debug) {
		Serial.println("Invalid DNS query received — responded with REFUSED.");
	}

	pbuf_free(response);
}