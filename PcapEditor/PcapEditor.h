//
// Created by root on 18-11-3.
//

#ifndef PCAPEDITOR_PCAPEDITOR_H
#define PCAPEDITOR_PCAPEDITOR_H


#include <pcap.h>
#include <cstdlib>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 65535
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14


/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};



/* content type */
const u_char CHANGE_CIPHER_SPEC = 0x14;
const u_char ALERT = 0x15;
const u_char HANDSHAKE = 0x16;
const u_char APPLICATION_DATA = 0x17;
const u_char HEARTBEAT = 0x18;

/* handshake type */
const u_char HELLO_REQUEST = 0x00;
const u_char CLIENT_HELLO = 0x01;
const u_char SERVER_HELLO = 0x02;
const u_char HELLO_VERIFY_REQUEST = 0x03;
const u_char NEW_SESSION_TICKET = 0x04;
const u_char END_OF_EARLY_DATA = 0x05;
const u_char HELLO_RETYR_REQUEST = 0x06;
const u_char ENCRYPTED_EXTENSIONS = 0x08;
const u_char CERTIFICATE = 0x0b;
const u_char SERVER_KEY_EXCHANGE = 0x0c;
const u_char CERTIFICATE_REQUEST = 0x0d;
const u_char SERVER_HELLO_DONE = 0x0e;
const u_char CERTIFICATE_VERIFY = 0x0f;
const u_char CLIENT_KEY_EXCHANGE = 0x10;
const u_char FINISHED = 0x14;
const u_char CERTIFICATE_URL = 0x15;
const u_char CERTIFICATE_STATUS = 0x16;
const u_char SUPPLEMENTAL_DATA = 0x17;
const u_char KEY_UPDATE = 0x18;
const u_char COMPRESSED_CERTIFICATE = 0x19;
const u_char MESSAGE_HASH = 0xff;


/* Client Hello */
struct Random{
    u_int gmt_unix_time;
    u_int random_bytes[7];
};

int label_num=0;
int label = -1;
char * src_pcap = NULL;
char * dst_pcap = NULL;

int packet_num=-1;

int flow_num=-1;
struct Flow{
    u_int ip_src;
    ushort tcp_sport;
    u_int ip_dst;
    ushort tcp_dport;
};
struct Flow flow_id_list[200000];
int cur_flow_num = 0;



void label_pcap();
void got_packet_label(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void create_pcap_packet_num(char *src_pcap, char *dst_pcap, int packet_num);
void got_packet_packet_num(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void create_pcap_flow_num(char *src_pcap, char *dst_pcap);
void got_packet_flow_num(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int in_flow_id_list(struct Flow flow_id_list[], int cur_flow_num, struct Flow flow);

#endif //PCAPEDITOR_PCAPEDITOR_H
