#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <signal.h>

int dport = 32768 + 666;

void sig_alarm(int sig) {
}

void main (int argc, char** argv) {
    int sendfd;
    int recvfd;

    int ttl = 1, setttl;
    int i, n, rlen;
    char opt;
    char buf[1024];
    struct sockaddr_in sa_bind, sa_send, sa_recv;
    char *sendstr;
    time_t t;
    struct icmp* icmp, hicmp;
    struct udphdr* udp;
    struct ip *ip, *hip;
    unsigned short sport;
    char *ch;
    struct sigaction sa;

    memset(&sa_bind, 0, sizeof(sa_bind));
    memset(&sa_send, 0, sizeof(sa_send));

    sport = (0xffff & getpid()) | 0x8000;

    while( (opt = getopt(argc, argv, "t:")) != -1 ) {
        switch( opt ) {
            case 't':
                ttl = atoi(optarg);
                break;
        }
    }

    sendfd = socket(PF_INET, SOCK_DGRAM, 0);
    if((recvfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("");
        exit(1);
    }

    sa_bind.sin_family = AF_INET;
    sa_bind.sin_port   = htons(sport);
    sa_send.sin_family = AF_INET;

    inet_aton("183.79.135.206", &sa_send.sin_addr);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = &sig_alarm;
    sigaction(SIGALRM, &sa, NULL);

    for ( i = 1; i <= ttl; ++i ) {
        sa_bind.sin_port = htons(sport);

        bind(sendfd, (struct sockaddr* )&sa_bind, sizeof(sa_bind));

        setttl = i;
        setsockopt(sendfd, IPPROTO_IP, IP_TTL, &i, sizeof(setttl));

        time(&t);
        sendstr = ctime(&t);

        sa_send.sin_port = htons(dport + i);

	alarm(5);
        sendto(sendfd, sendstr, strlen(sendstr), 0, (struct sockaddr*)&sa_send, sizeof(sa_send));


        // receive
        rlen = sizeof(sa_recv);
	while(1) {
		n = recvfrom(recvfd, buf, 1024, 0, (struct sockaddr*)&sa_recv, &rlen);

		if ( n == -1 ) {
		    if ( errno == EINTR ) {
			printf("not found\n");
			break;
		    } else {
			perror("");
			exit(1);
		    }
		}


		ip = (struct ip*)buf;
		icmp = (struct icmp*)(buf + (ip->ip_hl << 2));

		if(icmp->icmp_type == ICMP_TIMXCEED &&
		   icmp->icmp_code == ICMP_TIMXCEED_INTRANS) {

		    hip = (struct ip*)(buf + (ip->ip_hl << 2) + 8);
		    udp = (struct udphdr*)(buf + (ip->ip_hl << 2) + 8 + (hip->ip_hl << 2));

		    if(
		       hip->ip_p == IPPROTO_UDP &&
		       udp->source == htons(sport) &&
		       udp->dest   == htons(dport + i) ) {

			ch = inet_ntoa(sa_recv.sin_addr);
			printf("%s\n", ch);
			break;

		    }
		} else if (icmp->icmp_type == ICMP_UNREACH ) {
		    hip = (struct ip*)(buf + (ip->ip_hl << 2) + 8);
		    udp = (struct udphdr*)(buf + (ip->ip_hl << 2) + 8 + (hip->ip_hl << 2));

		    if(
		       hip->ip_p == IPPROTO_UDP &&
		       udp->source == htons(sport) &&
		       udp->dest   == htons(dport + i) ) {

                if ( icmp->icmp_code == ICMP_UNREACH_PORT ) {
                    ch = inet_ntoa(sa_recv.sin_addr);
                    printf("end %s\n", ch);
                } else {
                    printf("end\n");
                    break;
                }
            }

	}
	}


    }

}
