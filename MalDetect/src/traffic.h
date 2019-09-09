//
// Created by isaac on 18-9-11.
//

#ifndef ONLINE_MALICIOUS_TRAFFIC_DETECTION_TRAFFIC_H
#define ONLINE_MALICIOUS_TRAFFIC_DETECTION_TRAFFIC_H

#include <netinet/in.h>

/* the definition of traffic elements */

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

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





/* Client Hello */
struct Random{
    u_int gmt_unix_time;
    u_int random_bytes[7];
};



/* the definition of feature format in RAM */
#define FEATURE_VECTOR_LEN 855
struct Features{
    // flow metadata: from the start of flow to the end of TLS handshake
    int inbound_bytes;
    int inbound_packets;
    int outbound_bytes;
    int outbound_packets;
    double duration;
    int spl[11];
    int spt[11];
    double pre_ts;

    // TLS Data: information in handshake
    float tls_flow_ratio;
    // client hello
    int tls_version[5];
    int off_cipher_suites[340];
    int off_compression_methods[4];
    int off_extensions[46];

    // server hello
    int sel_cipher_suites[340];
    int sel_compression_methods[4];
    int sel_extensions[46];

    // certificate
    int cert_number;
    int bad_cert_number;
    float cert_version_ratios[4];
    float cert_extension_ratios[18];
    float cert_validity_mean;
    float cert_key_algorithm_ratios[3];
    float cert_signature_algorithm_ratios[13];
    float cert_key_length_mean;

    int label;

};

struct Flow{
    u_int ip_src;
    ushort tcp_sport;
    u_int ip_dst;
    ushort tcp_dport;
};

/* the definition of features storage in RAM*/
#define MAX_FLOWS_IN_RAM 1000

/* the Max number of packets of a specific flow */
#define THRESHOLD_PACKETS_OF_FLOW 20
#define THRESHOLD_STAY_TIME 5


class Traffic{
private:
    struct Features *Records;
    struct Flow *Flow_id_list;
    u_char **pre_tls_record;
    int *pre_tls_record_len;



public:
    Traffic();
    void init();
    int update(const u_char *payload, double packet_ts);
    void free_RAM(int pos);
    int find_flow(struct Flow flow, double ts);
    int compare_flow_id(struct Flow fa, struct Flow fb);
    int get_empty_flow_pos();
    int process_payload(u_char *payload, int pos, int len, double cur_packet_ts);
    int process_tls_records(u_char *cur_tls_record, int pos, int len_remained, double cur_packet_ts);
    void print_features(int pos);
    int get_label(int pos);
    void get_flow_id_str(int pos, char * flow_id_str);
    void get_fea_vec(int pos, double vec[], int len);
    void print_payload(const u_char *payload, int len);
    void print_hex_ascii_line(const u_char *payload, int len, int offset);
};

#define not_update -1 /* not updating packet */
#define seg_err -2 /* packet segment is not well formatted */
#define not_eff -3   /* not effective packet */
#define no_ram -4   /* there is no spare room */
#define flow_err -5 /* for flow errors */

#endif //ONLINE_MALICIOUS_TRAFFIC_DETECTION_TRAFFIC_H