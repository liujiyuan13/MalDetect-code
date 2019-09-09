//
// Created by isaac on 18-9-27.
//

#include <cstring>
#include "PcapEditor.h"

pcap_dumper_t * t;

void help() {
    printf("- -h | --help : display this message.\n"
           "- -l : assign the current label, this label must be in your configuration file.\n"
           "- -s : specify the path of source traffic.\n"
           "- -d : specify destination path for the processed traffic.\n"
           "- -cp : specify the packet number.\n"
           "- -cf : specify the flow number.\n");
}


int main(int argc, char *argv[]) {

    FILE * conf = fopen("../conf/label.conf", "r");
    if(conf==NULL){
        printf("open config file failed!\n");
        exit(0);
    }

    fscanf(conf, "%d\n", &label_num);
    char *labels[label_num];
    for(int i=0; i<label_num; i++){
        char * temp = (char *)malloc(100);
        fscanf(conf, "%s\n", temp);
        labels[i] = temp;
    }
    fclose(conf);


    if (argc == 1) {
        printf("No input argument specified: aborting.\n");
        help();
        exit(EXIT_SUCCESS);
    }

    int inputCounter = 1;
    while (inputCounter < argc) {
        if (!strcmp(argv[inputCounter], "-h") || !strcmp(argv[inputCounter], "--help")) {
            help();
            return EXIT_SUCCESS;
        } else if (!strcmp(argv[inputCounter], "-l")){
            inputCounter++;
            for(int i=0; i<6; i++){
                if(!strcmp(labels[i], argv[inputCounter])){
                    label = i;
                    break;
                }
            }
            if(label==-1){
                printf("invalid label! Please input one label in your config file!");
                return EXIT_FAILURE;
            }
        } else if (!strcmp(argv[inputCounter], "-s")){
            inputCounter++;
            src_pcap = argv[inputCounter];
        } else if (!strcmp(argv[inputCounter], "-d")){
            inputCounter++;
            dst_pcap = argv[inputCounter];
        } else if (!strcmp(argv[inputCounter], "-cp")){
            inputCounter++;
            packet_num = atoi(argv[inputCounter]);
        } else if (!strcmp(argv[inputCounter], "-cf")){
            inputCounter++;
            flow_num = atoi(argv[inputCounter]);
        }
        inputCounter++;
    }

    if(label!=-1 && src_pcap!=NULL && dst_pcap!=NULL){
        label_pcap();
        printf("Label the traffic, done!\n");
    }

    if(packet_num!=-1 && src_pcap!=NULL && dst_pcap!=NULL){
        create_pcap_packet_num(src_pcap, dst_pcap, packet_num);
        printf("Partition the traffic acoording to packet number, done!\n");
    }

    if(flow_num!=-1 && src_pcap!=NULL && dst_pcap!=NULL){
        create_pcap_flow_num(src_pcap, dst_pcap);
        printf("flow required: %d\n", flow_num);
        printf("flow extracted: %d\n", cur_flow_num);
        printf("Partition the traffic acoording to flow number, done!\n");
    }

}

void label_pcap(){

    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;				/* packet capture handle */
    char filter_exp[] = "port 443";		/* filter expression [3] */
    struct bpf_program fp;			/* compiled filter program (expression) */
    int num_packets = -1;			/* number of packets to capture */

    handle = pcap_open_offline_with_tstamp_precision(src_pcap, PCAP_TSTAMP_PRECISION_MICRO, errbuf);

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // open dump file
    t = pcap_dump_open(handle, dst_pcap);

    /* now we can set our callback function */
    pcap_loop(handle, num_packets, got_packet_label, NULL);

    //close dump file
    pcap_dump_close(t);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);
}


void got_packet_label(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    // revise the packet
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    u_char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int tcp_payload_size;


    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return ;
    }


    if (ip->ip_p != IPPROTO_TCP){
        return ;
    }

    /*
     *  OK, this packet is TCP.
     */

    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return ;
    }

    /* if the flow is transferred into or from port 433, then get the flow_id */
    if(ntohs(tcp->th_sport)==0x01bb || ntohs(tcp->th_dport)==0x01bb){

        /* define/compute tcp payload (segment) offset */
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        tcp_payload_size = ntohs(ip->ip_len) - size_ip - size_tcp;

        if(tcp_payload_size==0){
            return ;
        }

        /* get the content_type */
        u_char *content_type_p = payload;
        u_char content_type = *content_type_p;

        if (content_type == HANDSHAKE){
            u_char *handshake_type_p = payload + 5;
            u_char handshake_type = *handshake_type_p;

            if (handshake_type == CLIENT_HELLO){

                struct Random *random = (struct Random *)(payload + 11);
//                memset(random->random_bytes, 0, 6*4+3);
//                memset(random->random_bytes, codes[label], 1);
                for(int i=0; i<6; i++){
                    random->random_bytes[i] = 0;
                }
                random->random_bytes[6] = label;
            }

        }

    }else{
        return ;
    }



    // output into dump file
    pcap_dump((u_char*)t, header, packet);


}


void create_pcap_packet_num(char *src_pcap, char *dst_pcap, int packet_num){
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;				/* packet capture handle */


    handle = pcap_open_offline_with_tstamp_precision(src_pcap, PCAP_TSTAMP_PRECISION_MICRO, errbuf);

    // open dump file
    t = pcap_dump_open(handle, dst_pcap);

    /* now we can set our callback function */
    pcap_loop(handle, packet_num, got_packet_packet_num, NULL);

    //close dump file
    pcap_dump_close(t);

    /* cleanup */
    pcap_close(handle);
}

void got_packet_packet_num(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    // output into dump file
    pcap_dump((u_char*)t, header, packet);

}

void create_pcap_flow_num(char *src_pcap, char *dst_pcap){
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;				/* packet capture handle */


    handle = pcap_open_offline_with_tstamp_precision(src_pcap, PCAP_TSTAMP_PRECISION_MICRO, errbuf);

    // open dump file
    t = pcap_dump_open(handle, dst_pcap);

    /* now we can set our callback function */
    pcap_loop(handle, -1, got_packet_flow_num, NULL);

    //close dump file
    pcap_dump_close(t);

    /* cleanup */
    pcap_close(handle);
}

void got_packet_flow_num(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    // revise the packet
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    u_char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int tcp_payload_size;


    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return ;
    }


    if (ip->ip_p != IPPROTO_TCP){
        return ;
    }

    /*
     *  OK, this packet is TCP.
     */

    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return ;
    }

    /* define/compute tcp payload (segment) offset */
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    tcp_payload_size = ntohs(ip->ip_len) - size_ip - size_tcp;

    if(tcp_payload_size==0){
        return ;
    }

    struct Flow flow;
    flow.ip_src = ip->ip_src.s_addr;
    flow.ip_dst = ip->ip_dst.s_addr;
    flow.tcp_sport = tcp->th_sport;
    flow.tcp_dport = tcp->th_dport;


    if(in_flow_id_list(flow_id_list, cur_flow_num, flow)){
        // output into dump file
        pcap_dump((u_char*)t, header, packet);
    }else{
        if(cur_flow_num<flow_num){
            pcap_dump((u_char*)t, header, packet);
            flow_id_list[cur_flow_num] = flow;
            cur_flow_num++;
        }
    }

}

int in_flow_id_list(struct Flow flow_id_list[], int cur_flow_num, struct Flow flow){
    for(int i=0; i<cur_flow_num; i++){
        if(flow_id_list[i].ip_src==flow.ip_src && flow_id_list[i].tcp_sport==flow.tcp_sport && flow_id_list[i].ip_dst==flow.ip_dst && flow_id_list[i].tcp_dport==flow.tcp_dport){
            return 1;
        }else if(flow_id_list[i].ip_src==flow.ip_dst && flow_id_list[i].tcp_sport==flow.tcp_dport && flow_id_list[i].ip_dst==flow.ip_src && flow_id_list[i].tcp_dport==flow.tcp_sport){
            return 1;
        }
    }
    return 0;
}
