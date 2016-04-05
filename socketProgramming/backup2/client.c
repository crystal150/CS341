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

// #define PORT "3490" // the port client will be connecting to 


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
	printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure
	/*
	if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
			perror("recv");
			exit(1);
	}

	buf[numbytes] = '\0';

	printf("client: received '%s'\n",buf);
	*/

	// the start of my implementation
	// pahse1[0] is op(0~8) protocol(8~16) checksum(16~32)
	// phase1[1] is trans_id(0~32)
	srand(time(NULL));
	unsigned char op;
	unsigned char protocol = (unsigned char) atoi(argv[protocolSelector]);
	unsigned short checksum = ~((OP<<8) + protocol);
	unsigned int trans_id = rand() % (1<<31);

	phase1 = (unsigned long) OP<<56;
	phase1 += (unsigned long) protocol<<48;
	phase1 += (unsigned long) checksum<<32;
	phase1 += (unsigned long) trans_id;
	// printf("checksum is %x\n", checksum);
	//phase1 = htonl(phase1);

	printf("client: send '%lx'\n", phase1);	
	if (send(sockfd, &phase1, 8, 0) == -1)
		perror("send phase1");

	/* phase1 divided packet test
	printf("client: send '%lx'\n", *((int *) &phase1));	
	printf("client: send '%lx'\n", *((int *) &phase1+1));	
	if (send(sockfd, &phase1, 4, 0) == -1)
		perror("send phase1");
	sleep(1);
	if (send(sockfd, (int *)&phase1+1, 4, 0) == -1)
		perror("send phase1");
	*/

	int len_hand = 0;
	while (len_hand < 8) {
		if ((numbytes = recv(sockfd, buf+len_hand, MAXDATASIZE-1, 0)) == -1) {
				perror("recv");
				exit(1);
		}
		len_hand += numbytes;
	}

	unsigned long handshake = 0;
	for (int i = 0; i < numbytes; i++) {
		handshake += (unsigned long) ((unsigned char) buf[i]) << (8*i);		
	}
	printf("client: received %d '%lx'\n", numbytes, handshake);
	if (protocol != 0 && protocol != (unsigned char) (handshake >>48)) {
		perror("protocol handshake");
		close(sockfd);
		exit(1);
	}
	if (trans_id != (unsigned int) handshake) {
		perror("trans_id handshake");
		close(sockfd);
		exit(1);
	}
	op = (unsigned char) (handshake >> 56);
	protocol = (unsigned char) (handshake >> 48);
	checksum = (unsigned short) (handshake >> 32);
	if (op != 1) {
		perror("op handshake");
		close(sockfd);
		exit(1);
	}
	if ((op << 8) + protocol + checksum != 0xffff) {
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
		// printf("client: protocol %d\n", protocol);
		printf("client: protocol '%d' trans_id '%x'\n", protocol, trans_id);
		FILE *fp;
		do {
			char *filename = (char *) malloc(1024);
			printf("-> ");
			if (scanf("%s", filename) == EOF) continue;
			fp = fopen(filename, "rb");
		} while (fp == NULL);
		if (protocol == 1) {
			// int i = 0;
			// while (2) {	
			// 	if ( (message[i++] = fgetc(STDIN_FILENO)) == EOF ) {
			// 		printf("			EOF!			\n");
			// 		break;
			// 	}
			// 	printf("%x ", message[i]);
			// }
			// while ( (message[i++] = fgetc(stdin)) != EOF );
			int len;
			if ((len = fread(message, sizeof(char), MAXDATASIZE, fp)) == -1) {
				perror("EOF");
				exit(1);
			}
			// if (message[0] == '\n') continue;
			// int len = strlen(message) + 1;
			// int len = i + 1;
			// for (int i = 0; i < strlen(message) + 1 ; i++)
				// printf("client: %c\n", message[i]);
			// if (message[strlen(message)+3] == '\0')
				// printf("client: NULL\n");
			len += 2;
			message[len-2] = '\\';
			message[len-1] = '0';
			printf("client: send %d '", len);
			/*
			for (int i = 0; i < len; i++)
				if (message[i] == '\n')
					printf("\\n");
				else printf("%c", message[i]);
			*/
			printf("'\n");
			if (send(sockfd, message, len, 0) == -1)
				perror("send phase2");

			unsigned int len_received = 0;
			int rep = 1;
			while (rep) {
				// printf("Just Before recv\n");
				if ((numbytes = recv(sockfd, buf+len_received, MAXDATASIZE-1, 0)) == -1) {
						perror("recv");
						exit(1);
				}
				printf("client: received (partial) %d\n", numbytes);
				len_received += numbytes;
				if (buf[len_received-1] == '0' && buf[len_received-2] == '\\') {
					rep = 0;
					break;
				}
				/*
				for (int i = len_received; i < numbytes + len_received; i++)
					if ((unsigned char) buf[i] == '0')
						if ((unsigned char) buf[i-1] == '\\') {
							len_received -= numbytes - i - 1;
							rep = 0;
							break;
						}
				*/
			}
			printf("client: received %d\n", len_received-2);
			FILE *f;
			f = fopen("test.out", "wb");
			fwrite(buf, sizeof(char), len_received-2, f);
			fclose(f);
		}
		else if (protocol == 2) {
			/*
			if (fgets(message+4, MAXDATASIZE, stdin) == NULL) {
				perror("EOF");
				exit(1);
			}
			*/
			// int len = strlen(message+4);
			unsigned int len;
			if ((len = fread(message+4, sizeof(char), MAXDATASIZE, fp)) == -1) {
				perror("EOF");
				exit(1);
			}
			for (int i = 0; i < 4; i++) {
				message[i] = (unsigned char) (len >> (8*(4-i-1)));
				// printf("%x\n", (unsigned char) (len >> (8*(4-i-1))));
			}
			printf("client: send %d '", len + 4);
			/*
			for (int i = 4; i < len + 4; i++)
				if (message[i] == '\n')
					printf("\\n");
				else printf("%c", message[i]);
			*/
			printf("'\n");	
			if (send(sockfd, message, len + 4, 0) == -1)
				perror("send phase2");
			unsigned int full = 0, len_received = 0;
			while (1) {
				if ((numbytes = recv(sockfd, buf+len_received, MAXDATASIZE-1, 0)) == -1) {
						perror("recv");
						exit(1);
				}
				printf("client: received (partial) %d\n", numbytes);
				if (!full)
					for (int i = 0; i < 4; i++)
						full += (unsigned char) buf[i]<<(8*(3-i));
				len_received += numbytes;
				// printf("client: %d %d\n", full, len_received);
				if (len_received >= full + 4) break;
			}
			// buf[len_received] = '\0';
			printf("client: received %d '", full);
			/*
			for (int i = 4; i < full + 4; i++)
				if (buf[i] == '\n')
					printf("\\n");
				else printf("%c", buf[i]);
			*/
			printf("'\n");	
			// printf("client: received %d '%d %s'", numbytes, full, buf+4);
			FILE *f;
			f = fopen("test.out", "wb");
			fwrite(buf+4, sizeof(char), full, f);
			fclose(f);
		}
	}
	/*
	if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
			perror("recv");
			exit(1);
	}

	buf[numbytes] = '\0';

	printf("client: received '%s'\n",buf);
	// the end of my implemetation
	*/
	close(sockfd);

	return 0;
}

