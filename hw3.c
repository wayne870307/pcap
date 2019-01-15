#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    tcp_seq th_seq;     /* sequence number */
    tcp_seq th_ack;     /* acknowledgement number */
    u_char th_offx2;    /* data offset, rsvd */
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;     /* window */
    u_short th_sum;     /* checksum */
    u_short th_urp;     /* urgent pointer */
};

int main(int argc, char *argv[]) {
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *handler = pcap_open_offline(argv[1], errbuff);

    struct bpf_program filter;
    char *filter_exp = argv[2];
    pcap_compile(handler, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handler, &filter);

    struct pcap_pkthdr *header = NULL;
    const u_char *packet = NULL;   

    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    
    u_int size_ip;
    u_int size_tcp;

    int i = 0;
    while (pcap_next_ex(handler, &header, &packet) >= 0) {
        i++;

        ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	
		if(filter_exp != NULL)
		{
			printf("Filter             : %s\n", filter_exp);
		}
        printf("Source address     : %s\n", inet_ntoa(ip->ip_src));
        printf("Destination address: %s\n", inet_ntoa(ip->ip_dst));
        printf("Source port        : %d\n", ntohs(tcp->th_sport));
        printf("Destination port   : %d\n", ntohs(tcp->th_dport));
        printf("Length             : %d\n", header->len);
        
        char buf[80];
        struct tm *ts;
        ts = localtime(&(header->ts.tv_sec));
        strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", ts);
        printf("Time        : %s\n\n", buf);
    }
	printf("Total Packet: %d\n", i);
    return 0;
}
