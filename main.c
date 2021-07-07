#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <net/if.h>
#include <net/bpf.h>
#include <net/ethernet.h>  //Provides declarations for ethernet header
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <fcntl.h>
#include <ifaddrs.h>

char* interface, html_ip[16] = { 0 }, html_start[5] = "<html", html_end[7] = "</html>", html_file_index = 0, session_file_name[200] = { 0 };
int session_fd = -1, html_fd = -1, bpf_fd = -1, bpf_buf_len = 1;
bool is_running = true, session_file_created = false;
char session_directory[150] = { 0 };
int tcpNum = 0, udpNum = 0, icmpNum = 0;
int interfacesCount = 0;
bool info_mode = false;

void setPromiscMode(bool value, char* interface) {
    struct ifreq ifr;
    memset((void *)&ifr, 0, sizeof(struct ifreq));
    int sockfd;
    if((sockfd = socket(PF_INET, SOCK_RAW, 0)) < 0) {
        perror("Open Socket");
        return;
    }
    
    sprintf(ifr.ifr_name, "%s", interface);
    
    if(ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        close(sockfd);
        return;
    }
    
    if(value) ifr.ifr_flags |= IFF_PROMISC;
    else ifr.ifr_flags &= ~(IFF_PROMISC);
    
    if(ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        close(sockfd);
        return;
    }
}

void printTime(struct timeval32 tv, char* time) {
    char tmbuf[64], buf[64];
    struct tm* nowTime;
    time_t nowtm = tv.tv_sec;
    nowTime = localtime(&nowtm);
    strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowTime);
    snprintf(buf, sizeof buf, "%s.%06d", tmbuf, tv.tv_usec);
    if(time != NULL) {
        memcpy(time, buf, strlen(buf));
    }
    printf("%s\n", buf);
}

void printMAC(struct ether_header* hdr) {
    char d_addr[50] = { 0 }, s_addr[50] = { 0 };
    struct ether_addr dest_addr;
    memcpy(dest_addr.octet, hdr->ether_dhost, ETHER_ADDR_LEN);
    char* d = ether_ntoa(&dest_addr);
    memcpy(d_addr, d, strlen(d));
    struct ether_addr src_addr;
    memcpy(src_addr.octet, hdr->ether_shost, ETHER_ADDR_LEN);
    char* s = ether_ntoa(&src_addr);
    memcpy(s_addr, s, strlen(s));
    printf("%s > %s\n", d_addr, s_addr);
}

bool cmp(char* s1, char* s2, int len) {
    for(int i = 0; i < len; i++)
    if(s1[i] != s2[i])
        return false;
    return true;
}

bool isHTMLResponse(char* buf) {
    if(cmp(buf, "HTTP", 4)) {
        if(cmp(buf, "HTTP/1.1 200 OK", 15)) {
            for(int i = 17, line = 0; buf[i] != '\0' && line < 10; i++) { // reading first 10 lines
                if(buf[i] == '\n') {
                    for(int k = i + 1; k < i + 24; k++)
                    printf("%c", buf[k]);
                    printf("\n");
                    if(cmp(buf + i + 1, "Content-Type: text/html", 23))
                        return true;
                    printf("NextLine %d\n", i);
                    line++;
                }
            }
            return false;
        } else return false;
    } else return true;
}

void parseHTMLData(char* buf, u_int data_len, char* ip) {
    int html_index = 0;
    bool is_html_ip = !strcmp(html_ip, ip);
    if(!cmp(buf, "GET", 3) && !cmp(buf, "POST", 4))
        for(int i = 0; i < data_len; i++) {
            if(buf[i] == html_start[html_index] && html_fd == -1) {
                if(++html_index == 5) {
                    memcpy(html_ip, ip, strlen(ip));
                    char file_name[200] = { 0 };
                    sprintf(file_name, "%s/html%d.htm", session_directory, html_file_index++);
                    html_fd = open(file_name, O_CREAT | O_WRONLY);
                    if(html_fd == -1)
                        exit(-1);
                    write(html_fd, html_start, 5);
                    printf("Write html start\n");
                    html_index = 0;
                }
            } else if(buf[i] == html_end[html_index] && html_fd != -1 && is_html_ip) {
                write(html_fd, buf + i, 1);
                if(++html_index == 7) {
                    close(html_fd);
                    printf("Write html end\n");
                    html_fd = -1;
                    html_index = 0;
                }
            } else if((buf[i] != html_end[html_index] || buf[i] != html_start[html_index]) && html_index != 0) {
                write(html_fd, buf + i, 1);
                html_index = 0;
            } else {
                write(html_fd, buf + i, 1);
            }
        }
}

void printIP(struct ip* ip_hdr, struct tcphdr* tcp_hdr) {
    char ip_s[50] = { 0 }, ip_d[50] = { 0 };
    char* ip = inet_ntoa(ip_hdr->ip_src);
    memcpy(ip_s, ip, strlen(ip));
    ip = inet_ntoa(ip_hdr->ip_dst);
    memcpy(ip_d, ip, strlen(ip));
    printf("%s:%.4d > %s:%.4d\n", ip_s, ntohs(tcp_hdr->th_sport), ip_d, ntohs(tcp_hdr->th_dport));
}

void createSessionDir(char* time) {
    sprintf(session_directory, "./SnifferSessions/%s", time);
    struct stat st = { 0 };
    if (stat("./SnifferSessions", &st) == -1) {
        mkdir("./SnifferSessions", 0777);
    }
    mkdir(session_directory, 0777);
    sprintf(session_file_name, "%s/%s", session_directory, time);
    session_fd = open(session_file_name, O_CREAT | O_WRONLY);
    printf("File created\n");
    session_file_created = true;
}

void printNetworkInterfaces(char** interfaces) { // result will be writed to char* interfaces
    struct ifaddrs* ifaddr;
    int count = 0;
    for(getifaddrs(&ifaddr); ifaddr != NULL; ifaddr = ifaddr->ifa_next) {
        if(count == 0 || strcmp(interfaces[count - 1], ifaddr->ifa_name)) {
            printf("%d. %s\n", count + 1, ifaddr->ifa_name);
            u_long len = strlen(ifaddr->ifa_name);
            interfaces[count] = (char*) malloc((len + 1) * sizeof(char));
            memcpy(interfaces[count], ifaddr->ifa_name, len);
            interfaces[count++][len] = '\0';
        }
    }
    interfacesCount = count;
    freeifaddrs(ifaddr);
}

void* sniff(void* arg) {
    long read_bytes = 0;
    char time[100] = { 0 };
    
    struct bpf_hdr bpf_buf[bpf_buf_len];
    struct bpf_hdr* bpf_packet;
    struct ip* ip_hdr;
    struct tcphdr* tcp_hdr;
    struct udphdr* udp_hdr;
    struct ether_header* ether_hdr;
    u_int bpf_datalen;
    u_short ether_protocol, ip_protocol, ip_len, tcp_len;
    
    while(is_running)
    {
        memset(bpf_buf, 0, bpf_buf_len);
        
        if((read_bytes = read(bpf_fd, bpf_buf, bpf_buf_len)) > 0)
        {
            
            // read all packets that are included in bpf_buf. BPF_WORDALIGN is used
            // to proceed to the next BPF packet that is available in the buffer.
            
            char* ptr = (char*)bpf_buf;
            while(ptr < ((char*)bpf_buf + read_bytes))
            {
                printf("<-------------Ethernet Frame------------->\n");
                bpf_packet = (struct bpf_hdr*) ptr;
                void* data = ((char*) bpf_packet + bpf_packet->bh_hdrlen);
                ether_hdr = (struct ether_header*)data;
                printTime(bpf_packet->bh_tstamp, session_fd == -1 ? time : NULL);
                printMAC(ether_hdr);
                bpf_datalen = bpf_packet->bh_datalen;
                ether_protocol = ntohs(ether_hdr->ether_type);
                switch (ether_protocol) {
                    case ETHERTYPE_IP:
                        printf("IPv4\n");
                        ip_hdr = (struct ip*)((char*) data + sizeof(struct ether_header));
                        ip_protocol = ip_hdr->ip_p;
                        ip_len = ntohs(ip_hdr->ip_len); // length of ip header with data
                        printf("IP len %d\n", ip_len);
                        switch (ip_protocol) {
                            case IPPROTO_TCP:
                                tcpNum++;
                                tcp_hdr = (struct tcphdr*) ((char*) ip_hdr + ip_hdr->ip_hl * sizeof(u_int));
                                tcp_len = tcp_hdr->th_off * sizeof(u_int);
                                printf("TCP Connection\n");
                                printIP(ip_hdr, tcp_hdr);
                                printf("TTL %d\n", ip_hdr->ip_ttl);
                                u_int data_len = bpf_datalen - sizeof(struct ether_header) - sizeof(struct ip) - tcp_len;
                                printf("Data len %d\n", data_len);
                                char* buf = (char*) ((char*) tcp_hdr + tcp_hdr->th_off * sizeof(u_int));
                                buf[data_len] = '\0';
                                if(info_mode) {
                                    printf("%s\n", buf);
                                }
                                char data_info[20] = { 0 };
                                sprintf(data_info, "%d\n", data_len);
                                if(!session_file_created || session_fd == -1) {
                                    createSessionDir(time);
                                }
                                write(session_fd, data_info, strlen(data_info));
                                write(session_fd, buf, data_len);
                                parseHTMLData(buf, data_len, inet_ntoa(ip_hdr->ip_src));
                                if(data_len > 0)
                                    printf("\n");
                                break;
                            case IPPROTO_UDP:
                                udpNum++;
                                udp_hdr = (struct udphdr*) ((char*) ip_hdr + ip_hdr->ip_hl * sizeof(u_int));
                                printf("UDP Connection\n");
                                break;
                            case IPPROTO_ICMP:
                                icmpNum++;
                                printf("ICMP Connection\n");
                                break;
                        }
                        break;
                    case ETHERTYPE_ARP:
                        printf("ARP\n");
                        break;
                    case ETHERTYPE_IPV6:
                        printf("IPv6\n");
                        break;
                }
                ptr += BPF_WORDALIGN(bpf_packet->bh_hdrlen + bpf_packet->bh_caplen);
            }
        }
    }
    return NULL;
}

void openBPFfile() {
    char file_name[11] = { 0 };
    
    for(int i = 0; i < 99; i++) {
        sprintf(file_name, "/dev/bpf%i", i);
        bpf_fd = open(file_name, O_RDWR);
        
        if(bpf_fd != -1)
            break;
    }
    
    struct ifreq bound_if;
    
    strcpy(bound_if.ifr_name, interface);
    if(ioctl(bpf_fd, BIOCSETIF, &bound_if) > 0)
        exit(-1);
    
    // activate immediate mode (therefore, bpf_buf_len is initially set to "1")
    if(ioctl(bpf_fd, BIOCIMMEDIATE, &bpf_buf_len) == -1)
        exit(-1);
    
    // request buffer length
    if(ioctl(bpf_fd, BIOCGBLEN, &bpf_buf_len) == -1)
        exit(-1);
}

void inputNum(int* num, int b1, int b2) {
    bool isWrong = true;
    do {
        scanf("%d", num);
        if(*num >= b1 && *num <= b2)
            isWrong = false;
    } while(isWrong);
}

int main(int argc, char* argv[]) {
    if(argc > 1) {
        if(!strcmp(argv[1], "-i"))
            info_mode = true;
    }
    pthread_t sniff_thread;
    char* interfaces[100];
    printNetworkInterfaces(interfaces);
    int interfaceNum;
    inputNum(&interfaceNum, 1, interfacesCount);
    for(int i = 0; i < interfacesCount; i++) {
        if(i + 1 == interfaceNum)
            interface = interfaces[i];
    }
    system("clear");
    setPromiscMode(true, interface);
    openBPFfile();
    pthread_create(&sniff_thread, NULL, sniff, NULL);
    rewind(stdin);
    getchar();
    is_running = false;
    pthread_join(sniff_thread, NULL);
    
    if(session_fd != -1)
        close(session_fd);
    for(int i = 0; i < interfacesCount; i++) {
        free(interfaces[i]);
    }
    setPromiscMode(false, interface);
    struct bpf_stat stat;
    if(ioctl(bpf_fd, BIOCGSTATS, &stat) > 0)
        exit(-1);
    printf("%d packets received\n", stat.bs_recv);
    printf("%d packets were accepted by the filter but dropped by the kernel\n", stat.bs_drop);
    printf("%d TCP packets received by filter\n", tcpNum);
    printf("%d UDP packets received by filter\n", udpNum);
    printf("%d ICMP packets received by filter\n", icmpNum);
    return 0;
}
