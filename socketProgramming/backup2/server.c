/*
** server.c -- a stream socket server
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

// the start of my implementation
#include <time.h>

// #define PORT "3490"  // the port users will be connecting to

#define BACKLOG 10	 // how many pending connections queue will hold

#define OP 1
#define MAXDATASIZE 10*(1<<20) + 1
// the end of my implementation


void sigchld_handler(int s)
{
	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
}


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
	int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;

	// the start of my implementation
	unsigned long handshake;
	int numbytes;
	char *buf = (char *) malloc(MAXDATASIZE);

	if (argc != 3) {
		fprintf(stderr, "usage: server port -p\n");
		exit(1);
	}
	else {
		if (strcmp(argv[1], "-p")) {
			fprintf(stderr, "usage: server port -p\n");
			exit(1);
		}
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, argv[2], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}
	// the end of my implementation

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo); // all done with this structure

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	printf("server: waiting for connections...\n");

	while(1) {  // main accept() loop
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family,
			get_in_addr((struct sockaddr *)&their_addr),
			s, sizeof s);
		printf("server: got connection from %s\n", s);

		if (!fork()) { // this is the child process
			close(sockfd); // child doesn't need the listener
			/*
			if (send(new_fd, "Hello, world!", 13, 0) == -1)
				perror("send");
			close(new_fd);
			exit(0);
			*/
			// the start of my implementation
			int len_hand = 0;
			while (len_hand < 8) {
				if ((numbytes = recv(new_fd, buf+len_hand, MAXDATASIZE-1, 0)) == -1) {
					perror("recv");
					exit(1);
				}
				// for (int i = 0; i < numbytes; i++)
					// printf("%x\n", (unsigned char) buf[i + len_hand]);
				len_hand += numbytes;
			}
			// buf[numbytes] = '\0';
			unsigned char op;
			unsigned char protocol;
			unsigned short checksum;
			unsigned int trans_id;

			unsigned long phase1 = 0;
			for (int i = 0; i < len_hand; i++) {
				phase1 += (unsigned long) ((unsigned char) buf[i]) << (8*i);
				// printf("server: received '%x'\n", (unsigned char) buf[i]);
			}
			op = (unsigned char) (phase1 >> 56);
			protocol = (unsigned char) (phase1 >> 48);
			checksum = (unsigned short) (phase1 >> 32);
			trans_id = (unsigned int) phase1;
			
			printf("server: received %d '%lx'\n", len_hand, phase1);
			// printf("server: received %x, %x, %x, %x'\n", op, protocol, checksum, trans_id);
			if (op != 0) {
				perror("op phase1");
				close(new_fd);
				exit(0);
			}
			// printf("server: received '%x'\n", (op << 8) + protocol + checksum);
			if ((op << 8) + protocol + checksum != 0xffff) {
				perror("checksum phase1");
				close(new_fd);
				exit(0);
			}
			if (protocol == 0) {
				srand(time(NULL));
				protocol = (rand() % 2) + 1;
			}
			else if (protocol != 1 && protocol != 2) {
				perror("protocol phase1");
				close(new_fd);
				exit(0);
			}
			checksum = ~((OP<<8) + protocol);
			handshake = (unsigned long) OP<<56;
			handshake += (unsigned long) protocol<<48;
			handshake += (unsigned long) checksum<<32;
			handshake += (unsigned long) trans_id;

			printf("server: send '%lx'\n", handshake);
			if (send(new_fd, &handshake, 8, 0) == -1)
				perror("send");
			while (1) {
				char *message = (char *) malloc(MAXDATASIZE);
				int len = 0, full = 0, pointer = 0;
				int init = 4;
				int rep = 1;
				char temp;
				printf("server: protocol '%d' trans_id '%x'\n", protocol, trans_id);
				while (rep) {
					if ((numbytes = recv(new_fd, buf, MAXDATASIZE-1, 0)) == -1) {
						perror("recv");
						exit(1);
					}
					if (numbytes == 0) {
						perror("EOF");
						exit(1);
					}
					if (protocol == 1) {
						printf("server: received (partial) %d\n", numbytes);
						/*
						for (int i = 0; i < numbytes; i++)
							if (buf[i] == '\n')
								printf("\\n");
							else printf("%c", buf[i]);
						printf("'\n");
						*/
						// printf("server: received %d '%s'", numbytes, buf);
						// printf("%x %x\n", '\\', '0');
						
						for (int i = 0; i < numbytes; i++) {
							unsigned char tmp = buf[i];
							// printf("%x\n\n", tmp);
							/*
							if (tmp == '0' && temp == '\\') {
								message[len++] = tmp;
								printf("The end len: %x %x %d\n", tmp, temp, len);
								rep = 0;
								break;
							}
							*/
							if (temp != tmp) {
								message[len++] = tmp;
								temp = tmp;
							}
						}
						if (buf[numbytes-1] == '0' && buf[numbytes-2] == '\\') {
							rep = 0;
							break;
						}
					}
					else if (protocol == 2) {
						// buf[numbytes] = '\0';
						printf("server: received (partial) %d\n", numbytes);
						/*
						for (int i = 4; i < numbytes; i++)
							if (buf[i] == '\n')
								printf("\\n");
							else printf("%c", buf[i]);
						printf("'\n");
						*/
						if (full) init = 0;
						
						if (!full)
							for (int i = 0; i < 4; i++)
								full += (unsigned char) buf[i]<<(8*(3-i));
			
						for (int i = init; i < numbytes; i++) {
							unsigned char tmp = buf[i];
							if (temp != tmp) {
								message[len++ + 4] = tmp;
								temp = tmp;
							}
							// printf("server: pointer %d full %d\n", pointer, full);
							if (++pointer == full) {
								rep = 0;
								break;
							}
						}
					}
				}
				if (protocol == 1) {
					printf("server: send %d\n", len-2);
					/*
					for (int i = 0; i < len; i++)
						if (message[i] == '\n')
							printf("\\n");
						else printf("%c", message[i]);
					printf("'\n");
					*/
					// printf("server: send '%s'", message);
					if (send(new_fd, message, len, 0) == -1)
						perror("send");
				}
				else if (protocol == 2) {
					for (int i = 0; i < 4; i++)
						message[i] = (unsigned char) (len >> (8*(4-i-1)));
					printf("server: send %d\n", len);
					/*
					for (int i = 4; i < len + 4; i++)
						if (message[i] == '\n')
							printf("\\n");
						else printf("%c", message[i]);
					printf("'\n");
					*/
					// printf("server: send '%d %s'", len, message+4);
					if (send(new_fd, message, len + 4, 0) == -1)
						perror("send");
				}
			}
			close(new_fd);
			exit(0);
			// the end of my implementation

		}
		close(new_fd);  // parent doesn't need this
	}

	return 0;
}

