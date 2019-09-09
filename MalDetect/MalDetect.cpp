//
// Created by isaac on 18-9-27.
//

#include "MalDetect.h"


int main(int argc, char *argv[]) {

    char *dev=NULL;
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;				/* packet capture handle */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */
    int num_packets = -1;			/* number of packets to capture */
    char filter_exp[] = "port 443";		/* filter expression [3] */
    struct bpf_program fp;			/* compiled filter program (expression) */

    if(dev==NULL){
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    }

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);
    printf("Filter expression: %s\n", filter_exp);

    handle = pcap_open_live(dev, SNAP_LEN, 1, 10, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }
    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    traffic.init();

    /* now we can set our callback function */
    pcap_loop(handle, num_packets, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    double cur_packet_ts = header->ts.tv_sec + header->ts.tv_usec*1e-6;

    int pos = traffic.update(packet, cur_packet_ts);

    if(pos<0) {
        return;
    }

    double vec[FEATURE_VECTOR_LEN];
    traffic.get_fea_vec(pos, vec, FEATURE_VECTOR_LEN);
    int label = traffic.get_label(pos);

    Sample sample;
    sample.y = label;
    sample.w = 1.0;
    resize(sample.x, FEATURE_VECTOR_LEN);
    for(int i=0; i<FEATURE_VECTOR_LEN; i++){
        sample.x[i] = vec[i];
    }

    if(label==-1){
        int predict = model.eval(sample).prediction;
        char flow_id_str[100];
        traffic.get_flow_id_str(pos, flow_id_str);
        printf("<%s, tls>: %s\n", flow_id_str, hp.labels[predict]);
    }else{
        model.update(sample);
    }

    traffic.free_RAM(pos);
}

