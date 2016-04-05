/*
** client.c -- a stream socket client
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

// the start of my implementation
#include <time.h>
#define OP 0
#define MAXDATASIZE 10*(1<<20) + 1 // max number of bytes we can get at once 
// the end of my implementation

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
	int sockfd, numbytes;	
	char *buf = (char *) malloc(MAXDATASIZE);
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	// the start of my implementation
	int hostSelector=0;
	int portSelector=0;
	int protocolSelector=0;
	unsigned long phase1;

	if (argc != 7) {
		fprintf(stderr,"usage: client hostname -h\nclient port -p\nclient protocol -m\n\n");
		exit(1);
	}
	else {
		for (int i = 0; i < 3; i++) {
			if (!strcmp(argv[2*i+1], "-h")) {
				if (hostSelector) {
					fprintf(stderr,"usage: duplicated -h option\n");
					exit(1);
				}
				hostSelector = 2*i+2;
			}
			else if (!strcmp(argv[2*i+1], "-p")) {
				if (portSelector) {
					fprintf(stderr,"usage: duplicated -p option\n");
					exit(1);
				}
				portSelector = 2*i+2;
			}
			else if (!strcmp(argv[2*i+1], "-m")) {
				if (protocolSelector) {
					fprintf(stderr,"usage: duplicated -m option\n");
					exit(1);
				}
				protocolSelector = 2*i+2;
			}
			else {
				fprintf(stderr,"usage: client hostname -h\nclient port -p\nclient protocol -m\n\n");
				exit(1);
			}
		}
	}
	// the end of my implemetation
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(argv[hostSelector], argv[portSelector], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	// printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure

	// the start of my implementation
	srand(time(NULL));
	uint8_t *hand_req = (uint8_t *) malloc(8);
	uint8_t protocol = (uint8_t) atoi(argv[protocolSelector]);
	uint32_t trans_id = rand() % (1<<31);
	uint16_t checksum = ~((OP<<8) + protocol + 
		(uint16_t) trans_id + (uint16_t) (trans_id>>16)) ;

	hand_req[0] = OP;
	hand_req[1] = protocol;
	for (int i = 0; i < 2; i++)
		hand_req[3-i] = (uint8_t) (checksum >> (8*i));
	for (int i = 0; i < 4; i++)
		hand_req[7-i] = (uint8_t) (trans_id >> (8*i));
	// printf("client: send '");	
	// for (int i = 0; i < 8; i++)
		// printf("%02x", hand_req[i]);
	//printf("'\n");	

	if (send(sockfd, hand_req, 8, 0) == -1)
		perror("send phase1");

	int len_hand = 0;
	while (len_hand < 8) {
		if ((numbytes = recv(sockfd, buf+len_hand, MAXDATASIZE-1, 0)) == -1) {
				perror("recv");
				exit(1);
		}
		len_hand += numbytes;
		if (numbytes == 0) {
			perror("No response");
			exit(1);
		}
	}
	
	uint8_t *hand_recv = (uint8_t *) malloc(8);
	// printf("client: received '");
	for (int i = 0; i < numbytes; i++) {
		// printf("%02x", ((uint8_t) buf[i]));
		hand_recv[i] = buf[i];
	}
	// printf("'\n");

	uint8_t op_recv = buf[0];
	uint8_t protocol_recv = buf[1];
	uint16_t checksum_recv = (buf[2]<<8) + buf[3];
	uint32_t trans_id_recv = 0;

	for (int i = 0; i < 4; i++) {
		trans_id_recv += (uint32_t) ((uint8_t) buf[4+i])<<(8*(3-i));
	}
	if (protocol != 0 && protocol != buf[1]) {
		perror("protocol handshake");
		close(sockfd);
		exit(1);
	}
	if (trans_id != trans_id_recv) {
		perror("trans_id handshake");
		close(sockfd);
		exit(1);
	}
	if (op_recv != 1) {
		perror("op handshake");
		close(sockfd);
		exit(1);
	}
	uint16_t test_check = 0;
	for (int i = 0; i < 8; i++) {
		test_check += (uint16_t) ((uint8_t) buf[i])<<(8*((i+1)%2));
	}
	if (test_check != 0xffff) {
		perror("checksum handshake");
		close(sockfd);
		exit(1);
	}
	if (protocol != 1 && protocol != 2) {
		perror("protocol handshake");
		close(sockfd);
		exit(1);
	}
	while (1) {
		char *message = (char *) malloc(MAXDATASIZE);
		// printf("client: protocol '%d' trans_id '%x'\n", protocol, trans_id);
		if (protocol == 1) {
			char *temp_msg = (char *) malloc(MAXDATASIZE);
			int len_read;
			if ((len_read = fread(temp_msg, sizeof(char), MAXDATASIZE, stdin)) == 0) {
				perror("EOF");
				exit(1);
			}
			int len = 0;
			for (int i = 0; i < len_read; i++) {
				message[len++] = temp_msg[i];
				if (temp_msg[i] == '\\') message[len++] = temp_msg[i];
			}
			// printf("client: send %d '", len);
			// printf("'\n");

			int len_send = 0;
			char *chunk = (char *) malloc(1024);
			uint32_t len_received = 0;
			
			while (len_send < len) {
				int chunk_size = 1022;
				if (len_send + chunk_size > len) chunk_size = len - len_send;
				int rev;
				for (rev = 0; rev < chunk_size; rev++)
					if (message[len_send + chunk_size - 1 - rev] != '\\') break;
				chunk_size -= rev %= 2;
				for (int i = 0; i < chunk_size; i++)
					chunk[i] = message[len_send + i];
				chunk[chunk_size] = '\\';
				chunk[chunk_size+1] = '0';
				len_send += chunk_size;
				if (send(sockfd, chunk, chunk_size + 2, 0) == -1)
					perror("send phase2");
				while (1) {
					if ((numbytes = recv(sockfd, buf+len_received, MAXDATASIZE-1, 0)) == -1) {
							perror("recv");
							exit(1);
					}
					// printf("client: received (partial) %d\n", numbytes);
					if (numbytes == 0) {
						perror("No response");
						exit(1);
					}
					len_received += numbytes;
					if (buf[len_received-1] == '0' && buf[len_received-2] == '\\') {
						len_received -= 2;
						break;
					}
				}
			} 
			
			char *msg_recv = (char *) malloc(MAXDATASIZE);
			int len_recv = 0;
			for (int i = 0; i < len_received; i++) {
				msg_recv[len_recv++] = (unsigned char) buf[i];
				if ((unsigned char) buf[i] == '\\') i++;
			}
			// printf("client: received %d\n", len_recv);
			FILE *f;
			f = fopen("test.out", "wb");
			fwrite(msg_recv, sizeof(char), len_recv, f);
			fclose(f);
			for (int i = 0; i < len_recv; i++) printf("%c", msg_recv[i]);
		}
		else if (protocol == 2) {
			uint32_t len;
			if ((len = fread(message+4, sizeof(char), MAXDATASIZE, stdin)) == 0) {
				perror("EOF");
				exit(1);
			}
			for (int i = 0; i < 4; i++) {
				message[i] = (uint8_t) (len >> (8*(4-i-1)));
			}
			// printf("client: send %d '", len + 4);
			// printf("'\n");	
			if (send(sockfd, message, len + 4, 0) == -1)
				perror("send phase2");
			uint32_t full = 0, len_received = 0;
			while (1) {
				if ((numbytes = recv(sockfd, buf+len_received, MAXDATASIZE-1, 0)) == -1) {
						perror("recv");
						exit(1);
				}
				// printf("client: received (partial) %d\n", numbytes);
				if (!full)
					for (int i = 0; i < 4; i++)
						full += (uint8_t) buf[i]<<(8*(3-i));
				len_received += numbytes;
				if (len_received >= full + 4) break;
			}
			// printf("client: received %d '", full);
			// printf("'\n");	
			FILE *f;
			f = fopen("test.out", "wb");
			fwrite(buf+4, sizeof(char), full, f);
			fclose(f);
			for (int i = 0; i < full; i++) printf("%c", buf[i+4]);
		}
	}
	close(sockfd);

	return 0;
}

