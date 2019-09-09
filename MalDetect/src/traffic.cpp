//
// Created by isaac on 18-9-11.
//

#include "traffic.h"
#include "values.h"

#include <cstdio>
#include <stdlib.h>
#include <stdlib.h>
#include <ctype.h>
#include <cstring>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <sys/time.h>


int
get_pos_uchar_list(u_char list[], int size, u_char u){
    for(int i=0; i< size; i++){
        if(u == list[i]){
            return i;
        }
    }
    return size;
}

int
get_pos_ushort_list(u_short list[], int size, u_short u){
    for(int i=0; i< size; i++){
        if(u == list[i]){
            return i;
        }
    }
    return size;
}

int
get_pos_int_list(int list[], int size, int u){
    for(int i=0; i<size; i++){
        if(u == list[i]){
            return i;
        }
    }
    return size;
}

Traffic::Traffic() {

}

void Traffic::init() {
    Records = (struct Features *)malloc(sizeof(struct Features)*MAX_FLOWS_IN_RAM);
    Flow_id_list = (struct Flow *)malloc(sizeof(struct Flow)*MAX_FLOWS_IN_RAM);
    pre_tls_record = (u_char **)malloc(sizeof(char *)*MAX_FLOWS_IN_RAM);
    pre_tls_record_len = (int *)malloc(sizeof(int)*MAX_FLOWS_IN_RAM);

    memset(Flow_id_list, '\0', sizeof(struct Flow)*MAX_FLOWS_IN_RAM);
    memset(Records, '\0', sizeof(struct Features)*MAX_FLOWS_IN_RAM);
    memset(pre_tls_record, '\0', sizeof(char *)*MAX_FLOWS_IN_RAM);
    memset(pre_tls_record_len, '\0', sizeof(int)*MAX_FLOWS_IN_RAM);


//    int a[MAX_FLOWS_IN_RAM];
//    for(int j=0; j<MAX_FLOWS_IN_RAM; j++){
//        a[j] = pre_tls_record_len[j];
//    }

    /* reverse the network byte order into host byte order */
    int i = 0;
    for(i=0; i< sizeof(tls_version_list)/2; i++){
        tls_version_rev_list[i] = ntohs(tls_version_list[i]);
    }
    for(i=0; i< sizeof(cipher_suite_list)/2; i++){
        cipher_suite_rev_list[i] = ntohs(cipher_suite_list[i]);
    }
    for(i=0; i < sizeof(compression_method_list); i++){
        compression_method_rev_list[i] = compression_method_list[i];
    }
    for(i=0; i < sizeof(extension_list)/2; i++){
        extension_rev_list[i] = ntohs(extension_list[i]);
    }
}

int Traffic::update(const u_char *packet, double packet_ts) {

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    u_char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int tcp_payload_size;


    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);

    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return seg_err;
    }


    /* determine protocol */
    switch(ip->ip_p) {
        case IPPROTO_TCP:
//            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
//            printf("   Protocol: UDP\n");
            return not_eff;
        case IPPROTO_ICMP:
//            printf("   Protocol: ICMP\n");
            return not_eff;
        case IPPROTO_IP:
//            printf("   Protocol: IP\n");
            return not_eff;
        default:
//            printf("   Protocol: unknown\n");
            return not_eff;
    }

    /* print source and destination IP addresses */
//    printf("       From: %s\n", inet_ntoa(ip->ip_src));
//    printf("         To: %s\n", inet_ntoa(ip->ip_dst));


    /*
     *  OK, this packet is TCP.
     */

    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return seg_err;
    }

//    printf("   Src port: %d\n", ntohs(tcp->th_sport));
//    printf("   Dst port: %d\n", ntohs(tcp->th_dport));


    /* if the flow is transferred into or from port 433, then get the flow_id */
    if(ntohs(tcp->th_sport)==0x01bb || ntohs(tcp->th_dport)==0x01bb){
        /* the flow id is formatted as 0x code
         * ip_src + th_sport + ip_dst + th_dport
         * 12 bytes
         */
        struct Flow flow = {ip->ip_src.s_addr, tcp->th_sport, ip->ip_dst.s_addr, tcp->th_dport};
        /* this flow is new or already exists */
        int flow_id_pos = find_flow(flow, packet_ts);
        /* define the flow direction, 1 is c-s, 2 is s-c */
        int flow_direction;
        if(flow_id_pos==-1){
            /* this flow is not currently processed, check if the packet is the first packet of this flow */
            /* check if it is a SYN packet */
            if(tcp->th_flags & 0x02 != 0x02){
                return not_eff;
            }
            /* if it is a SYN packet, it is a completely new flow */
            /* this is a new flow, get a flow id position for it */
            int index = get_empty_flow_pos();
            if(index==-1){
//                for(int i=0; i< MAX_FLOWS_IN_RAM; i++){
//                    printf("   Src port: %d\n", ntohs(Flow_id_list[i].tcp_sport));
//                    printf("   Dst port: %d\n", ntohs(Flow_id_list[i].tcp_dport));
//                }
                fprintf(stderr, "Too many flows: there is no extra space in RAM for new flows.");
//                exit(EXIT_FAILURE);
                return no_ram;
            }
            Flow_id_list[index] = flow;
            /* always set the direction of new packet 1 */
            flow_direction = 1;
            flow_id_pos = index;
            /* for a new flow, set the primary timestamp to its duration */
            Records[flow_id_pos].duration = packet_ts;
//            printf("packet time: %f", Records[flow_id_pos].duration);
        }else{
            flow_direction = compare_flow_id(Flow_id_list[flow_id_pos], flow);
            /*
             * check if it is FIN packet,
             * if it is, remove this flow out of RAM
             */
            if(tcp->th_flags & 0x01 == 0x01){
                /* do not output features, for this flow is discarded */
                free_RAM(flow_id_pos);
                return flow_err;
            }
            /* check if the number of the flow is over the threshold */
            if(Records[flow_id_pos].outbound_packets+Records[flow_id_pos].inbound_packets>THRESHOLD_PACKETS_OF_FLOW){
                /* do not output features, for this flow is discarded */
                free_RAM(flow_id_pos);
                return flow_err;
            }
        }
//        printf("\nflow pos: %d\n", flow_id_pos);
        /* add the information into features records */
        /* set the flow_metadata */
        int ip_payload_size = ntohs(ip->ip_len) - size_ip;
        if(flow_direction==1){
            Records[flow_id_pos].outbound_bytes += ip_payload_size;
            Records[flow_id_pos].outbound_packets += 1;
        }else{
            Records[flow_id_pos].inbound_bytes += ip_payload_size;
            Records[flow_id_pos].inbound_packets += 1;
        }
        int nl = ip_payload_size/150;
        if(nl<10){
            Records[flow_id_pos].spl[nl] += 1;
        }else{
            Records[flow_id_pos].spl[10] += 1;
        }
        /* if the flow is new, its pre_ts is 0, then we do not count its timestamp into spt */
        if(Records[flow_id_pos].pre_ts!=0){
            double interval = packet_ts - Records[flow_id_pos].pre_ts;
            int nt = interval/0.05;
            if(nt<10){
                Records[flow_id_pos].spt[nt] += 1;
            }else{
                Records[flow_id_pos].spt[10] += 1;
            }
        }
        /* update the pre_ts */
        Records[flow_id_pos].pre_ts = packet_ts;


        /* define/compute tcp payload (segment) offset */
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        tcp_payload_size = ntohs(ip->ip_len) - size_ip - size_tcp;


        return process_payload(payload, flow_id_pos, tcp_payload_size, packet_ts);

    }else{
        /* the flow does not belong to TLS flow */
        return not_eff;
    }

}

int Traffic::find_flow(struct Flow flow, double ts) {
    for(int i=0; i<MAX_FLOWS_IN_RAM; i++){
        if(Flow_id_list[i].ip_src==0){
            continue;
        }
        if(ts - Records[i].pre_ts > THRESHOLD_STAY_TIME){
            free_RAM(i);
            continue;
        }
        if(compare_flow_id(Flow_id_list[i], flow)){
            return i;
        }
    }
    return -1;
}

int Traffic::compare_flow_id(struct Flow fa, struct Flow fb) {
    if(fa.ip_src==fb.ip_src && fa.tcp_sport==fb.tcp_sport && fa.ip_dst==fb.ip_dst && fa.tcp_dport==fb.tcp_dport){
        return 1;
    }else if(fa.ip_src==fb.ip_dst && fa.tcp_sport==fb.tcp_dport && fa.ip_dst==fb.ip_src && fa.tcp_dport==fb.tcp_sport){
        return 2;
    }else{
        return 0;
    }
}

int Traffic::get_empty_flow_pos() {
    for(int i=0; i<MAX_FLOWS_IN_RAM; i++){
        if(Flow_id_list[i].ip_src==0){
            return i;
        }
    }
    return -1;
}

int Traffic::process_payload(u_char *payload, int pos, int len, double cur_packet_ts) {
    /*
     * we process the packets before the end of TLS handshake,
     * so only packets containing handshake information are considered as effective TLS packets.
     * other packets, such as pure ack packets or tcp(carrying no handshake information), are not effective.
     * by the way, there aren't any TLS application data or other types of packets in this process.
     */

    /* if it is a pure ack, meaning the tcp payload length is 0 */
    if(len == 0){
        return not_eff;
    }else{
        /* it is an effective TLS packet */
        /* number of effective tls packet is accumulated here,
         * the ratio will be calculated at the end of handshake
         */
        Records[pos].tls_flow_ratio += 1;
    }

    int len_remained=0;
    u_char *cur_tls_record;
    int flag = 0;
    if(pre_tls_record_len[pos]!=0){
        /* get a new joint payload */
        flag = 1;

        len_remained = len + pre_tls_record_len[pos];
        cur_tls_record = (u_char *)malloc(len_remained);
        memcpy(cur_tls_record, pre_tls_record[pos], pre_tls_record_len[pos]);
        memcpy(cur_tls_record+pre_tls_record_len[pos], payload, len);

        free(pre_tls_record[pos]);
        /* reset the pre_tls_record and pre_tls_record_len */
        pre_tls_record_len[pos] = 0;
        pre_tls_record[pos] = NULL;

//        print_payload(cur_tls_record, len_remained);

    }else{
        len_remained = len;
        cur_tls_record = payload;
    }


    int code = process_tls_records(cur_tls_record, pos, len_remained, cur_packet_ts);

    if(flag){
        free(cur_tls_record);
    }

    return code;
}

int Traffic::process_tls_records(u_char *cur_tls_record, int pos, int len_remained, double cur_packet_ts) {
    /* the other choice to proceed the TLS message with multiple records of the same structure */
    /* recursive method */
//    if(len_remained==0){
//        return;
//    }

    /* one choice */
    while(len_remained>0) {

        /* get the content_type */
        u_char *content_type_p = cur_tls_record;
        u_char content_type = *content_type_p;
//        printf("content_type: %02x \n", content_type);

        /* not used in Features */
        u_short *content_version_p = (u_short *)(cur_tls_record + 1);

        u_short *content_length_p = (u_short *)(cur_tls_record + 3);
        int content_length = ntohs(*content_length_p);

        /* if the handshake length is bigger than payload length
         * the tls record is separated into several parts
         * store this part and wait the next packet of the same direction
         */
        if (content_length + 5 > len_remained) {
            /*store it*/
            pre_tls_record[pos] = (u_char *)malloc(len_remained);
            memcpy(pre_tls_record[pos], cur_tls_record, len_remained);
            pre_tls_record_len[pos] = len_remained;
            break;
        }


        /* choose the HANDSHAKE type */
        if (content_type == HANDSHAKE) {


            u_char *handshake_type_p = cur_tls_record + 5;
            u_char handshake_type = *handshake_type_p;
            //        printf("handshake_type: %02x \n", handshake_type);

            if (handshake_type == CLIENT_HELLO) {

                int id;

                /* not used in Features */
                u_int *client_hello_length_extended_p = (u_int *)(cur_tls_record + 5);
                u_int client_hello_length_extended = *client_hello_length_extended_p;
                int client_hello_length = ntohl(client_hello_length_extended & 0xffffff00);
                //            printf("client hello length: %06x \n", client_hello_length);
                if(client_hello_length+5+2>len_remained){
                    free_RAM(pos);
                    return seg_err;
                }

                /* used as tls_version in Features */
                u_short *client_hello_version_p = (u_short *)(cur_tls_record + 9);
                id = get_pos_ushort_list(tls_version_rev_list, sizeof(tls_version_rev_list) / 2,
                                         *client_hello_version_p);
                Records[pos].tls_version[id] = 1;

                /* not used in Features */
                struct Random *random = (struct Random *)(cur_tls_record + 11);
                //            printf("random time: %08x \n", ntohl(random->gmt_unix_time));
                // Random.bytes is the flag of a flow
                int trainordetect = 1;  //train is 1, detect is 0.
                for(int i=0; i<6; i++){
                    if(random->random_bytes[i]!=0){
                        trainordetect = 0;
                        break;
                    }
                }
                if(trainordetect){
                    Records[pos].label = random->random_bytes[6];
                }else{
                    Records[pos].label = -1;
                }


                /* not used in Features */
                /* but helpful to further analysis, so we obtain it */
                u_short *session_id_length_extended_p = (u_short *)(cur_tls_record + 42);
                u_short session_id_length_extended = *session_id_length_extended_p;
                int session_id_length = ntohs(session_id_length_extended & 0xff00);
                //            printf("session_id_length: %02x \n", session_id_length);
                if(session_id_length+42+2>len_remained){
                    free_RAM(pos);
                    return seg_err;
                }
                // ignore session_id


                /* not used in Features */
                /* but helpful to further analysis, so we obtain it */
                u_short *cipher_suites_length_p = (u_short *)(cur_tls_record + 44 + session_id_length);
                int cipher_suites_length = ntohs(*cipher_suites_length_p);
                //            printf("cipher_suites_length: %04x \n", cipher_suites_length);
                if(cipher_suites_length+44+session_id_length+2>len_remained){
                    free_RAM(pos);
                    return seg_err;
                }

                /* used in Features */
                u_short *cipher_suites_short_p = (u_short *)(cur_tls_record + 44 + session_id_length + 2);
                u_short *cipher_suite_p = cipher_suites_short_p;
                //            print_payload(cipher_suite_p, 30);
                for (int i = 0; i < cipher_suites_length / 2; i++) {
                    id = get_pos_ushort_list(cipher_suite_rev_list, sizeof(cipher_suite_rev_list) / 2, *cipher_suite_p);
                    Records[pos].off_cipher_suites[id] = 1;
                    cipher_suite_p += 1;
                }

                /* not used in Features */
                /* but helpful to further analysis, so we obtain it */
                u_short *compression_methods_length_extended_p = (u_short *)
                        (cur_tls_record + 44 + session_id_length + 2 + cipher_suites_length - 1);
                u_short compression_methods_length_extended = *compression_methods_length_extended_p;
                int compression_methods_length = ntohs(compression_methods_length_extended & 0xff00);
                //            printf("compression_methods_length: %02x \n", compression_methods_length);
                if(compression_methods_length+44+session_id_length+2+cipher_suites_length-1+2>len_remained){
                    free_RAM(pos);
                    return seg_err;
                }

                u_char *compression_methods_char_p =
                        cur_tls_record + 44 + session_id_length + 2 + cipher_suites_length + 1;
                for (int i = 0; i < compression_methods_length; i++) {
                    id = get_pos_uchar_list(compression_method_rev_list, sizeof(compression_method_rev_list),
                                            *compression_methods_char_p);
                    Records[pos].off_compression_methods[id] = 1;
                    compression_methods_char_p += 1;
                }

                u_char *extensions_p = cur_tls_record + 44 + session_id_length + 2 + cipher_suites_length + 1 + compression_methods_length;


                /* not used in Features */
                /* but helpful to further analysis, so we obtain it */
                u_short *extensions_length_p = (u_short *)extensions_p;
                int extensions_length = ntohs(*extensions_length_p);
                if(extensions_length+44 + session_id_length + 2 + cipher_suites_length + 1 + compression_methods_length+2>len_remained){
                    free_RAM(pos);
                    return seg_err;
                }

                /* used in Features */
                int ex_len = extensions_length;
                u_char *extension_type_p = extensions_p + 2;
                while (ex_len > 0) {
                    /* get and store cur extension type */
                    u_short *extension_type = (u_short *)extension_type_p;
                    id = get_pos_ushort_list(extension_rev_list, sizeof(extension_rev_list) / 2, *extension_type);
                    Records[pos].off_extensions[id] = 1;

                    u_short *extension_length_p = (u_short *)(extension_type_p + 2);
                    int extension_length = ntohs(*extension_length_p);
                    if(extension_length+2+2>ex_len){
                        free_RAM(pos);
                        return seg_err;
                    }

                    ex_len -= (extension_length + 4);
                    extension_type_p += (extension_length + 4);
                }

            } else if (handshake_type == SERVER_HELLO) {
                int id;

                /* not used in Features */
                u_int *server_hello_length_extended_p = (u_int *)(cur_tls_record + 5);
                u_int server_hello_length_extended = *server_hello_length_extended_p;
                int server_hello_length = ntohl(server_hello_length_extended & 0xffffff00);
                //            printf("server hello length: %06x \n", server_hello_length);
                if(server_hello_length+5+2>len_remained){
                    free_RAM(pos);
                    return seg_err;
                }

                /* not used in Features */
                u_short *server_hello_version_p = (u_short *)(cur_tls_record + 9);


                /* not used in Features */
                struct Random *random = (struct Random *)(cur_tls_record + 11);
                //            printf("random time: %08x \n", ntohl(random->gmt_unix_time));
                // ignore Random.random_bytes

                /* not used in Features */
                /* but helpful to further analysis, so we obtain it */
                u_short *session_id_length_extended_p = (u_short *)(cur_tls_record + 42);
                u_short session_id_length_extended = *session_id_length_extended_p;
                int session_id_length = ntohs(session_id_length_extended & 0xff00);
                //            printf("session_id_length: %02x \n", session_id_length);
                if(session_id_length+42+2>len_remained){
                    free_RAM(pos);
                    return seg_err;
                }
                // ignore session_id


                /* used in Features */
                /* selected cipher suite */
                u_short *sel_cipher_suite_p = (u_short *)(cur_tls_record + 44 + session_id_length);
                id = get_pos_ushort_list(cipher_suite_rev_list, sizeof(cipher_suite_rev_list) / 2, *sel_cipher_suite_p);
                Records[pos].sel_cipher_suites[id] = 1;
                //            printf("\nsel_cipher_suite: 0x%04x", *sel_cipher_suite_p);

                /* used in Features */
                /* selected compression method */
                u_char *sel_compression_method_p = cur_tls_record + 44 + session_id_length + 2;
                id = get_pos_uchar_list(compression_method_rev_list, sizeof(compression_method_rev_list),
                                        *sel_compression_method_p);
                Records[pos].sel_compression_methods[id] = 1;
                //            printf("\nsel_compression_method_p: 0x%02x", *sel_compression_method_p);

                /* next field pointer */
                u_char *extensions_p = cur_tls_record + 44 + session_id_length + 3;


                /* not used in Features */
                /* but helpful to further analysis, so we obtain it */
                u_short *extensions_length_p = (u_short *)extensions_p;
                int extensions_length = ntohs(*extensions_length_p);
                if(extensions_length+44+session_id_length+3+2>len_remained){
                    free_RAM(pos);
                    return seg_err;
                }

                /* used in Features */
                int ex_len = extensions_length;
                u_char *extension_type_p = extensions_p + 2;
                while (ex_len > 0) {
                    /* get and store cur extension type */
                    u_short *extension_type = (u_short *)extension_type_p;
                    id = get_pos_ushort_list(extension_rev_list, sizeof(extension_rev_list) / 2, *extension_type);
                    Records[pos].sel_extensions[id] = 1;

                    u_short *extension_length_p = (u_short *)(extension_type_p + 2);
                    int extension_length = ntohs(*extension_length_p);
                    if(extension_length+2+2>ex_len){
                        free_RAM(pos);
                        return seg_err;
                    }

                    ex_len -= (extension_length + 4);
                    extension_type_p += (extension_length + 4);
                }

            } else if (handshake_type == CERTIFICATE) {

                int id;

                /* not used in Features */
                u_int *certificate_protocol_length_extended_p = (u_int *)(cur_tls_record + 5);
                u_int certificate_protocol_length_extended = *certificate_protocol_length_extended_p;
                int certificate_protocol_length = ntohl(certificate_protocol_length_extended & 0xffffff00);
//                printf("certificate protocol length: %06x \n", certificate_protocol_length);
                if(certificate_protocol_length+5+2>len_remained){
                    free_RAM(pos);
                    return seg_err;
                }

                /* not used in Features */
                u_int *certificates_length_extended_p = (u_int *)(cur_tls_record + 8);
                u_int certificates_length_extended = *certificates_length_extended_p;
                int certificates_length = ntohl(certificates_length_extended & 0xffffff00);
//                printf("certificates length: %06x \n", certificates_length);
                if(certificates_length+8+2>len_remained){
                    free_RAM(pos);
                    return seg_err;
                }

                int certificates_len = certificates_length;
                u_char *cur_certificate_p = cur_tls_record + 12;
                while(certificates_len>0){
                    /* this is one certificate, keep it in Features */
                    Records[pos].cert_number += 1;

                    /* get current certificate length */
                    u_int *cur_certificate_length_extended_p = (u_int *)(cur_certificate_p - 1);

                    u_int cur_certificate_length_extended;
                    cur_certificate_length_extended = *cur_certificate_length_extended_p;

                    int cur_certificate_length = ntohl(cur_certificate_length_extended & 0xffffff00);
                    if(cur_certificate_length+3>certificates_len){
                        free_RAM(pos);
                        return seg_err;
                    }

                    const unsigned char * certificate_p = cur_certificate_p + 3;
                    X509 *cert = d2i_X509(NULL, &certificate_p, (long)cur_certificate_length);
                    if(!cert){
                        fprintf(stderr, "unable to parse certificate in memory\n");
                        /* consider it is not a certificate */
                        Records[pos].cert_number -= 1;

                        Records[pos].bad_cert_number += 1;

                        cur_certificate_p += cur_certificate_length + 3;
                        certificates_len -= cur_certificate_length + 3;

                        continue;
                    }

                    /* get certificate details */

                    /* get certificate version */
                    int version = (int)X509_get_version(cert);
                    id = get_pos_int_list(cert_version, sizeof(cert_version)/ sizeof(int), version);
                    Records[pos].cert_version_ratios[id] += 1;

                    /* get certificte extension */
                    STACK_OF(X509_EXTENSION) *exts = cert->cert_info->extensions;
                    int num_of_exts;
                    if(exts){
                        num_of_exts = sk_X509_EXTENSION_num(exts);
                    }else{
                        num_of_exts = 0;
                    }

                    for(int i=0; i<num_of_exts; i++){
                        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
                        if(ex == NULL){
                            fprintf(stderr, "unable to extract extension from stack");
                            continue;
                        }
                        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
                        if(obj == NULL){
                            fprintf(stderr, "unable to extract ASN1 object from extension");
                            continue;
                        }
//                        BIO *ext_bio = BIO_new(BIO_s_mem());
//                        if(ext_bio == NULL){
//                            fprintf(stderr, "unable to allocate memory for extension value BIO");
//                            continue;
//                        }
//                        if(!X509V3_EXT_print(ext_bio, ex, 0, 0)){
//                            M_ASN1_OCTET_STRING_print(ext_bio, ex->value);
//                        }
//
//                        BUF_MEM *bptr;
//                        BIO_get_mem_ptr(ext_bio, &bptr);
//                        BIO_set_close(ext_bio, BIO_NOCLOSE);
//
//                        //remove newlines
//                        int lastchar = bptr->length;
//                        if(lastchar>1 && (bptr->data[lastchar-1]=='\n' || bptr->data[lastchar-1]=='\r')){
//                            bptr->data[lastchar-1] = (char) 0;
//                        }
//                        if(lastchar>0 && (bptr->data[lastchar]='\n' || bptr->data[lastchar]=='\r')){
//                            bptr->data[lastchar] = (char) 0;
//                        }
//
//                        BIO_free(ext_bio);


                        int nid = OBJ_obj2nid(obj);

                        id = get_pos_int_list(cert_extension_nid, sizeof(cert_extension_nid)/ sizeof(int), nid);
                        Records[pos].cert_extension_ratios[id] += 1;
                    }

                    /* get certificate validity */

                    ASN1_TIME *not_before = X509_get_notBefore(cert);
                    ASN1_TIME *not_after = X509_get_notAfter(cert);
                    int pdays, psecs;
                    ASN1_TIME_diff(&pdays, &psecs, not_before, not_after);
                    /* only calculate the days*/
                    Records[pos].cert_validity_mean += pdays;

                    /* get key algorithms */
                    int key_algorithm_nid =  OBJ_obj2nid(X509_get_X509_PUBKEY(cert)->algor->algorithm);
                    id = get_pos_int_list(cert_key_algorithm_nid, sizeof(cert_key_algorithm_nid)/ sizeof(int), key_algorithm_nid);
                    Records[pos].cert_key_algorithm_ratios[id] += 1;

                    /* get key length */
                    int key_length = cert->cert_info->key->public_key->length;
                    Records[pos].cert_key_length_mean += key_length;


                    /* get signature algorithm */
                    int pkey_nid = OBJ_obj2nid(cert->cert_info->signature->algorithm);
                    id = get_pos_int_list(cert_signature_algorithm_nid, sizeof(cert_signature_algorithm_nid)/ sizeof(int), pkey_nid);
                    Records[pos].cert_signature_algorithm_ratios[id] += 1;


                    X509_free(cert);


                    cur_certificate_p += cur_certificate_length + 3;
                    certificates_len -= cur_certificate_length + 3;
                }

            }



        } else if (content_type == CHANGE_CIPHER_SPEC){

            //used for measure the response time
            double first_packet_ts = Records[pos].duration;

            /* the duration is calculated */
            Records[pos].duration = cur_packet_ts - Records[pos].duration;
            /* the ssl_flow_ratio is calculated */
            Records[pos].tls_flow_ratio = Records[pos].tls_flow_ratio / (Records[pos].inbound_packets + Records[pos].outbound_packets);
            if(Records[pos].cert_number != 0) {
                int number = Records[pos].cert_number;
                float a[4];
                float b[4];
                for(int i=0; i<4; i++){
                    b[i] = Records[pos].cert_version_ratios[i] / Records[pos].cert_number;
                }

                /* the certificate verssion ratio */
                for (int i = 0; i < sizeof(Records[pos].cert_version_ratios) / sizeof(float); i++) {
                    a[i] = Records[pos].cert_version_ratios[i] / Records[pos].cert_number;
//                    Records[pos].cert_version_ratios[i] = a[i];
                    Records[pos].cert_version_ratios[i] =
                            Records[pos].cert_version_ratios[i] / Records[pos].cert_number;

                }
                /* the certificate extension ratio */
                for (int i = 0; i < sizeof(Records[pos].cert_extension_ratios) / sizeof(float); i++) {
                    Records[pos].cert_extension_ratios[i] =
                            Records[pos].cert_extension_ratios[i] / Records[pos].cert_number;
                }
                /* the certificate validity mean */
                Records[pos].cert_validity_mean = Records[pos].cert_validity_mean / Records[pos].cert_number;
                /* the certificate key algorithm ratio */
                for (int i = 0; i < sizeof(Records[pos].cert_key_algorithm_ratios) / sizeof(float); i++) {
                    Records[pos].cert_key_algorithm_ratios[i] =
                            Records[pos].cert_key_algorithm_ratios[i] / Records[pos].cert_number;
                }
                /* the certificate signature algorithm ratio*/
                for (int i = 0; i < sizeof(Records[pos].cert_signature_algorithm_ratios) / sizeof(float); i++) {
                    Records[pos].cert_signature_algorithm_ratios[i] =
                            Records[pos].cert_signature_algorithm_ratios[i] / Records[pos].cert_number;
                }
                /* the certificate key length mean */
                Records[pos].cert_key_length_mean = Records[pos].cert_key_length_mean / Records[pos].cert_number;
            }


            for(int i=0; i< sizeof(Records[pos].tls_version)/ sizeof(int); i++){
                if (Records[pos].tls_version[i] == 1) {

                    return pos;
                }
            }
            free_RAM(pos);
            return flow_err;
        }
        else if (content_type == APPLICATION_DATA){
            /* do not output features, for this flow is discarded */
            free_RAM(pos);
            return flow_err;
        }
        /* update the len_remained and t */
        len_remained -= content_length + 5;
        cur_tls_record += content_length + 5;

    }
    return not_update;
    //            print_payload(cur_tls_record, len_remained);

    /* the other choice to proceed the TLS message with multiple records of the same structure */
    /* recursive method */
//        process_tls_records(cur_tls_record + handshake_length + 5, pos, len_remained);

}

void Traffic::free_RAM(int pos) {
    struct Features *cur_features = &Records[pos];
    memset(cur_features, 0, sizeof(struct Features));
    struct Flow *cur_flow = &Flow_id_list[pos];
    memset(cur_flow, 0, sizeof(struct Flow));
    pre_tls_record[pos] = NULL;
    pre_tls_record_len[pos] = 0;
}

void Traffic::get_flow_id_str(int pos, char * flow_id_str) {


    in_addr sip, dip;
    sip.s_addr = Flow_id_list[pos].ip_src;
    dip.s_addr = Flow_id_list[pos].ip_dst;

    char * sips = (char *)malloc(20);
    strcpy(sips, inet_ntoa(sip));

    sprintf(flow_id_str, "%s, %d, %s, %d", sips, ntohs(Flow_id_list[pos].tcp_sport), inet_ntoa(dip), ntohs(Flow_id_list[pos].tcp_dport));

}

int Traffic::get_label(int pos){
    return Records[pos].label;
}

void Traffic::get_fea_vec(int pos, double vec[], int len) {
    vec[0] = Records[pos].inbound_bytes;
    vec[1] = Records[pos].inbound_packets;
    vec[2] = Records[pos].outbound_bytes;
    vec[3] = Records[pos].outbound_packets;
    vec[4] = Records[pos].duration;
    int i=0;
    for(i=0; i<11; i++){
        vec[5+i] = Records[pos].spl[i];
    }
    for(i=0; i<11; i++){
        vec[16+i] = Records[pos].spt[i];
    }
    vec[27] = Records[pos].tls_flow_ratio;
    for(i=0; i<5; i++){
        vec[28+i] = Records[pos].tls_version[i];
    }
    for(i=0; i<340; i++){
        vec[33+i] = Records[pos].off_cipher_suites[i];
    }
    for(i=0; i<4; i++){
        vec[373+i] = Records[pos].off_compression_methods[i];
    }
    for(i=0; i<46; i++){
        vec[377+i] = Records[pos].off_extensions[i];
    }
    for(i=0; i<340; i++){
        vec[423+i] = Records[pos].sel_cipher_suites[i];
    }
    for(i=0; i<4; i++){
        vec[763+i] = Records[pos].sel_compression_methods[i];
    }
    for(i=0; i<46; i++){
        vec[767+i] = Records[pos].sel_extensions[i];
    }
    vec[813] = Records[pos].cert_number;
    vec[814] = Records[pos].bad_cert_number;
    for(i=0; i<4; i++){
        vec[815+i] = Records[pos].cert_version_ratios[i];
    }
    for(i=0; i<18; i++){
        vec[819+i] = Records[pos].cert_extension_ratios[i];
    }
    vec[837] = Records[pos].cert_validity_mean;
    for(i=0; i<3; i++){
        vec[838+i] = Records[pos].cert_key_algorithm_ratios[i];
    }
    for(i=0; i<13; i++){
        vec[841+i] = Records[pos].cert_signature_algorithm_ratios[i];
    }
    vec[854] = Records[pos].cert_key_length_mean;
}


void Traffic::print_features(int pos){
    printf("Flow Metadata:\n");
    printf("> inbound_bytes: %d \n", Records[pos].inbound_bytes);
    printf("> inbound_packets: %d \n", Records[pos].inbound_packets);
    printf("> outbound_bytes: %d \n", Records[pos].outbound_bytes);
    printf("> outbound_packets: %d \n", Records[pos].outbound_packets);
    printf("> duration: %f \n", Records[pos].duration);
    printf("> spl: ");
    for(int i=0; i<11; i++){
        printf("%d ", Records[pos].spl[i]);
    }
    printf("\n> spt: ");
    for(int i=0; i<11; i++){
        printf("%d ", Records[pos].spt[i]);
    }
//    printf("\n> pre_ts: %f ", Records[pos].pre_ts);

    printf("\nTLS information: ");
    printf("\n> tls_flow_ratio: %f", Records[pos].tls_flow_ratio);
    printf("\nClient Hello: ");
    printf("\n> tls_version: ");
    for(int i=0; i < sizeof(Records[pos].tls_version)/ sizeof(int); i++){
        printf("%d ", Records[pos].tls_version[i]);
    }
    printf("\n> off_cipher_suites: ");
    for(int i=0; i < sizeof(Records[pos].off_cipher_suites)/sizeof(int); i++){
        printf("%d ", Records[pos].off_cipher_suites[i]);
    }
    printf("\n> off_compression_methods: ");
    for(int i=0; i < sizeof(Records[pos].off_compression_methods)/sizeof(int); i++){
        printf("%d ", Records[pos].off_compression_methods[i]);
    }
    printf("\n> off_extensions: ");
    for(int i=0; i < sizeof(Records[pos].off_extensions)/sizeof(int); i++){
        printf("%d ", Records[pos].off_extensions[i]);
    }
    printf("\nServer Hello: ");
    printf("\n> sel_cipher_suites: ");
    for(int i=0; i < sizeof(Records[pos].sel_cipher_suites)/sizeof(int); i++){
        printf("%d ", Records[pos].sel_cipher_suites[i]);
    }
    printf("\n> sel_compression_methods: ");
    for(int i=0; i < sizeof(Records[pos].sel_compression_methods)/sizeof(int); i++){
        printf("%d ", Records[pos].sel_compression_methods[i]);
    }
    printf("\n> sel_extensions: ");
    for(int i=0; i < sizeof(Records[pos].sel_extensions)/sizeof(int); i++){
        printf("%d ", Records[pos].sel_extensions[i]);
    }
    printf("\nCertificate: ");
    printf("\n> cert_number: %d", Records[pos].cert_number);
    printf("\n> bad_cert_number: %d", Records[pos].bad_cert_number);
    printf("\n> cert_version_ratios: ");
    for(int i=0; i < sizeof(Records[pos].cert_version_ratios)/ sizeof(float); i++){
        printf("%f ", Records[pos].cert_version_ratios[i]);
    }
    printf("\n> cert_extension_ratios: ");
    for(int i=0; i < sizeof(Records[pos].cert_extension_ratios)/sizeof(float); i++){
        printf("%f ", Records[pos].cert_extension_ratios[i]);
    }
    printf("\n> cert_validity_mean: %f", Records[pos].cert_validity_mean);
    printf("\n> cert_key_algorithm_ratios: ");
    for(int i=0; i < sizeof(Records[pos].cert_key_algorithm_ratios)/sizeof(float); i++){
        printf("%f ", Records[pos].cert_key_algorithm_ratios[i]);
    }
    printf("\n> cert_signature_algorithm_ratios: ");
    for(int i=0; i < sizeof(Records[pos].cert_signature_algorithm_ratios)/sizeof(float); i++){
        printf("%f ", Records[pos].cert_signature_algorithm_ratios[i]);
    }
    printf("\n> cert_key_length_mean: %f", Records[pos].cert_key_length_mean);
}

void Traffic::print_payload(const u_char *payload, int len) {
    int len_rem = len;
    int line_width = 16;			/* number of bytes per line */
    int line_len;
    int offset = 0;					/* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

    return;
}

void Traffic::print_hex_ascii_line(const u_char *payload, int len, int offset) {
    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}