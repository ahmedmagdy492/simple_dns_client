#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <time.h>

// TODO: remember to add these dynamically
#define DNS_SERVER "8.8.8.8"
#define PORT 53
#define DNS_STATIC_SIZE 17
#define REC_SIZE 1024

#pragma pack(1)

typedef struct dns_hdr {
	uint16_t transaction_id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answer_rrs;
	uint16_t authority_rrs;
	uint16_t addtional_rrs;
	uint8_t label_len;
} dns_hdr;

typedef struct domain_label {
	uint8_t len;
	char* label;

} domain_label;

int generate_trans_id() {
	srand(time(0));
	return rand();
}

int count_labels(char* domain) {
	int len = strlen(domain);
        int dots_found = 1;

        for(int i = 0; i < len; i++) {
                if(domain[i] == '.') {
                        dots_found++;
                }
        }
	return dots_found;
}

char** extract_labels(char* domain, int labels_count) {
    char** labels = (char**)malloc(sizeof(char*) * labels_count);
    int counter = 0;

    for (int i = 0; i < labels_count; i++) {
        labels[i] = (char*)malloc(sizeof(char) * 253);
    }

    int labels_index = 0;
    int last_stop = 0;
    int chars_count = 0;

    for (int i = 0; i < strlen(domain); i++) {
        if (domain[i] == '.') {
            for (int j = 0; j < chars_count; j++) {
                labels[labels_index][j] = domain[last_stop+j];
            }
            last_stop = i+1;
            labels[labels_index][chars_count] = '\0';
            labels_index++;
            chars_count = 0;
        }
        else {
            chars_count++;
        }
    }

    for (int j = 0; j < chars_count; j++) {
        labels[labels_index][j] = domain[last_stop + j];
    }
    labels[labels_index][chars_count] = '\0';
    labels_index++;

    return labels;
}

int copy(int write_start, char* dest, char* src) {
    for (int i = 0; i < strlen(src); i++) {
        dest[write_start] = src[i];
        write_start++;
    }

    return write_start;
}

char* create_labels_str(char** labels, int count, int labels_count) {
    char* buffer = (char*)malloc(sizeof(char)*count);
    int buff_counter = 0;

    for (int i = 0; i < labels_count; i++) {
        buffer[buff_counter] = strlen(labels[i]);
        buff_counter++;
        buff_counter = copy(buff_counter, buffer, labels[i]);
    }

    buffer[buff_counter] = 0;

    return buffer;
}

// TODO: do not forget to deallocaet heap memory after sending the packet
void* create_packet(char* domain, int* packet_len) {
	int domain_len = strlen(domain) + 1;
	int total_len = DNS_STATIC_SIZE + domain_len+1;
	*packet_len = total_len;

	dns_hdr dns;
	dns.transaction_id = generate_trans_id();
	dns.flags = 1;
	((uint8_t*)&(dns.questions))[0] = 0;
	((uint8_t*)&(dns.questions))[1] = 1;
	dns.answer_rrs = 0;
	dns.authority_rrs = 0;
	dns.addtional_rrs = 0;

	void* dns_buffer = malloc(sizeof(char)*total_len);

	memcpy(dns_buffer, &dns, total_len);

	char* offseted_buffer = ((char*)(dns_buffer+sizeof(dns_hdr)));

	int label_count = count_labels(domain);
        char** result = extract_labels(domain, label_count);

	char* labels_str = create_labels_str(result, strlen(domain)+2, label_count);

	strncpy(offseted_buffer-1, labels_str, strlen(labels_str));

	char* offseted_buffer2 = (offseted_buffer+strlen(labels_str));
	(offseted_buffer+strlen(labels_str)-1)[0] = 0;
	offseted_buffer2[0] = 0;
	offseted_buffer2[1] = 1;
	offseted_buffer2[2] = 0;
	offseted_buffer2[3] = 1;

	return dns_buffer;
}

void* send_dns_packet(char* domain, int* packet_len_out) {
	int sock = socket(AF_INET, SOCK_DGRAM, 17);

	if(sock < 0) {
		perror("while creating socket");
		exit(-1);
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	inet_aton(DNS_SERVER, &addr.sin_addr);


	int con = connect(sock, (struct sockaddr*)&addr, sizeof(addr));

	if(con < 0) {
		perror("while trying to connect to DNS Server");
		exit(-1);
	}

	int packet_len = 0;
	void* packet = create_packet(domain, &packet_len);
	
	int result = sendto(sock, packet, packet_len, 0, 0, 0);

	if(result < 0) {
		perror("while sending the packet");
		exit(-1);
	}

	printf("Sent DNS Standard Query Packet\n");

	printf("Waiting for an answer...\n");

	char temp_buff[REC_SIZE];
	memset(temp_buff, 0, REC_SIZE);

	int msg_len = recvfrom(sock, temp_buff, REC_SIZE, MSG_WAITALL, 0, 0);
	*packet_len_out = msg_len;

	void* rec_buffer = malloc(sizeof(char)*msg_len);
	memcpy(rec_buffer, temp_buff, msg_len);

	close(sock);

	free(packet);

	return rec_buffer;
}

void extract_ip_address(void* dns_res_packet, int packet_len, char* output) {
	unsigned char* ip = ((unsigned char*)dns_res_packet)+packet_len-4;

	printf("%d.", ip[0]);
	printf("%d.", ip[1]);
	printf("%d.", ip[2]);
	printf("%d\n", ip[3]);
}

int main(int argc, char* argv[]) {
	if(argc != 2) {
		printf("Usage: %s <domain-name>\n", argv[0]);
		return -1;
	}
	
	int packet_len = 0;
	void* dns_res_packet = send_dns_packet(argv[1], &packet_len);
	
	char ip[16];
	memset(ip, 0, 16);

	extract_ip_address(dns_res_packet, packet_len, ip);

	free(dns_res_packet);
}
