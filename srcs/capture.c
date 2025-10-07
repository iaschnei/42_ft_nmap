#include "capture.h"
#include <netinet/ether.h>

//This part captures every incoming packets and stores them (using packet_store_add) if they are relevant 
//The reason for that is that workers will then be able to check stored packet to find responses to their requests

static void packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes)
{

    // This argument isn't needed here but pcap_loop requires it's second argument (packet_handler) to have it
    (void)user;

    if (hdr->caplen < sizeof(struct ether_header) + sizeof(struct ip)) return;

    //Check that the packet is in IPv4 (= ETHERTYPE_IP), otherwise, ignore it
    const struct ether_header *eth = (const struct ether_header *)bytes;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;

    const struct ip *iph = (const struct ip *)(bytes + sizeof(struct ether_header));
    size_t iphdr_len = iph->ip_hl * 4;

    //Store the packet in memory based on protocol (tcp, udp or icmp)
    if (iph->ip_p == IPPROTO_TCP) {

        if (hdr->caplen < sizeof(struct ether_header) + iphdr_len + sizeof(struct tcphdr))
            return;

        const struct tcphdr *tcp = (const struct tcphdr *)((const uint8_t *)iph + iphdr_len);

        uint8_t flags = 0;
        if (tcp->syn)  flags |= TH_SYN;
        if (tcp->ack)  flags |= TH_ACK;
        if (tcp->rst)  flags |= TH_RST;
        if (tcp->fin)  flags |= TH_FIN;
        if (tcp->psh)  flags |= TH_PUSH;
        if (tcp->urg)  flags |= TH_URG;

        //debug
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->ip_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &iph->ip_dst, dst_ip, sizeof(dst_ip));
        printf("[capture] TCP packet: src=%s dst=%s sport=%d dport=%d flags=0x%02x seq=%u ack=%u\n",
            src_ip, dst_ip,
            ntohs(tcp->th_sport), ntohs(tcp->th_dport),
            flags,
            ntohl(tcp->seq), ntohl(tcp->ack_seq));
       //debug end

        packet_store_add_tcp_ex(&g_store,
            iph->ip_src, iph->ip_dst,
            ntohs(tcp->th_sport), ntohs(tcp->th_dport),
            flags,
            ntohl(tcp->seq),
            ntohl(tcp->ack_seq)
        );
    } else if (iph->ip_p == IPPROTO_UDP) {

        const struct udphdr *udp = (const struct udphdr *)((const uint8_t *)iph + iphdr_len);
        packet_store_add(&g_store, iph->ip_src, iph->ip_dst,
                         ntohs(udp->uh_sport), ntohs(udp->uh_dport), IPPROTO_UDP);

    } else if (iph->ip_p == IPPROTO_ICMP) {

        packet_store_add(&g_store, iph->ip_src, iph->ip_dst, 0, 0, IPPROTO_ICMP);

    }

}

// Launches a thread to capture every incoming packet
static void *capture_thread(void *arg)
{
    t_capture *cap = (t_capture *)arg;
    cap->running = true;

    pcap_loop(cap->handle, 0, packet_handler, (u_char *)cap);

    cap->running = false;
    //debug
    printf("[Capture] Thread exiting\n");
    return NULL;
}

// Setup the capture for later use in capture_thread()
int capture_start(t_capture *cap, const char *iface, const t_config *config)
{
    (void)config;
    if (!cap || !iface) return -1;

    packet_store_init(&g_store);

    cap->handle = pcap_open_live(iface, BUFSIZ, 1, 1000, cap->errbuf);
    if (!cap->handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", cap->errbuf);
        return -1;
    }

    char filter_exp[64];
    snprintf(filter_exp, sizeof(filter_exp), "ip");

    struct bpf_program fp;
    if (pcap_compile(cap->handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(cap->handle));
        pcap_close(cap->handle);
        return -1;
    }
    if (pcap_setfilter(cap->handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(cap->handle));
        pcap_freecode(&fp);
        pcap_close(cap->handle);
        return -1;
    }
    pcap_freecode(&fp);

    if (pthread_create(&cap->thread, NULL, capture_thread, cap) != 0) {
        perror("pthread_create(capture_thread)");
        pcap_close(cap->handle);
        return -1;
    }
    return 0;
}

void capture_stop(t_capture *cap)
{
    if (!cap) return;
    if (cap->handle) {
        //debug
        printf("[Capture] Breaking loop\n");
        pcap_breakloop(cap->handle);
        pthread_join(cap->thread, NULL);
        //debug
        printf("[Capture] Closing handle\n");
        pcap_close(cap->handle);
    }
    packet_store_destroy(&g_store);
}
