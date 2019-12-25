#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<time.h>
#include<pcap.h>
#include<sys/types.h>
#include<sys/socket.h>
#ifndef __linux
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#else /* if BSD */
#define __FAVOR_BSD
#include<linux/if_ether.h>
#include<netpacket/packet.h>
#include<linux/if_link.h>
#include<netinet/ether.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>
#endif /* if linux */
#define	ETHERTYPE_IP		0x0800	

struct sockaddr_in source,dest;

struct pair_ip{
	/* data */
	char source[1024];
	char dest[1024];
	int cnt;
};

struct pair_ip ip_arr[10240];
int pair_cnt = 0;

int compare_ip(char a[1024],char b[1024]){
	for(int i=0;i<pair_cnt;i++){
		if( strcmp(a,ip_arr[i].source)==0 && strcmp(b,ip_arr[i].dest)==0){
			return i;
		}
	}
	return -1;
}

void sorting_arr(int check){
	for(int i=0;i<pair_cnt;i++){
		for(int j=0;j<pair_cnt;j++){
			if( ip_arr[i].cnt<ip_arr[j].cnt && check == 1 ){
				struct pair_ip tmp = ip_arr[i];
				ip_arr[i] = ip_arr[j];
				ip_arr[j] = tmp;
			}
			else if (ip_arr[i].cnt>ip_arr[j].cnt && check == 0){
				struct pair_ip tmp = ip_arr[i];
				ip_arr[i] = ip_arr[j];
				ip_arr[j] = tmp;
			}
			
		}
	}
}

void print_arr(){
	for(int i=0;i<pair_cnt;i++){
		printf("%-16s\t%-16s\t%-3d\n",ip_arr[i].source,ip_arr[i].dest,ip_arr[i].cnt);
	}
}

void print_ip_header(const u_char * Buffer, int Size,char s_ip[1024],char d_ip[1024]){ 
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	printf("|-Source IP        : %s\n", inet_ntoa(source.sin_addr) );
	printf("|-Destination IP   : %s\n", inet_ntoa(dest.sin_addr) );
	strcpy(s_ip,inet_ntoa(source.sin_addr));
	strcpy(d_ip,inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(const u_char * Buffer, int Size){
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	printf("|-Source Port      : %u\n",ntohs(tcph->source));
	printf("|-Destination Port : %u\n",ntohs(tcph->dest));
}

void print_udp_packet(const u_char *Buffer , int Size){
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	printf("|-Source Port      : %d\n" , ntohs(udph->source));
	printf("|-Destination Port : %d\n" , ntohs(udph->dest));
}


int main(int argc,char *argv[]){
	char file_name[1024]={0},ebuf[1024]={0},output_file[1024]="\0";
	char ord[1024]="\0";
	int read_cnt = -1;
	for(int i=1;i<argc;i+=2){
		if(!strcmp("-h",argv[i])){
			printf("-r filename 	--------read pcapfile to program\n");
			printf("-ord asc/decs 	--------asc:sort pair ip with counting from low to high,decs:sort pair ip with counting from high to low\n");
			printf("-h 		--------help\n");
			printf("-c number	--------read k packet in pcap file\n");
			printf("-w filename	--------write output to file\n");
			return 0;
		}
		if(!strcmp("-r",argv[i])){
			strcpy(file_name,argv[i+1]);
		}
		if(!strcmp("-ord",argv[i])){
			strcpy(ord,argv[i+1]); //asc || decs
		}
		if(!strcmp("-c",argv[i])){
			read_cnt = atoi(argv[i+1]);
		}
		if(!strcmp("-w",argv[i])){
			strcpy(output_file,argv[i+1]);
		}
	}
	pcap_t *pd = pcap_open_offline(file_name,ebuf);
	if(strlen(ebuf)){
		printf("err:%s\n",ebuf);
		return 0;
	}
	int pack_cnt = 0;
	int pack_byte = 0;
	while(1){
		if(read_cnt>=0){
			if(pack_cnt == read_cnt){
				break;
			}
		}
		struct pcap_pkthdr *header;
		const u_char *content;
		int ret = pcap_next_ex(pd, &header, &content);
		if(ret == 1){
			char source_ip[1024],dest_ip[1024];
			pack_byte += header->caplen;
			pack_cnt++;
			const struct ether_header *ethernet = (struct ether_header *)content;
			if (ntohs (ethernet->ether_type) == ETHERTYPE_IP){
				const struct iphdr *iph = (struct iphdr*)(content + sizeof(struct ethhdr));
				if(iph->protocol == 6){
					printf("tcp packet\n");
					print_ip_header(content,header->len,source_ip,dest_ip);
					print_tcp_packet(content,header->len);
				}
				else if(iph->protocol == 17){
					printf("udp packet\n");
					print_ip_header(content,header->len,source_ip,dest_ip);
					print_udp_packet(content,header->len);
				}
				else{
					print_ip_header(content,header->len,source_ip,dest_ip);
				}
				int flag = compare_ip(source_ip,dest_ip);
				if(flag == -1){
					strcpy(ip_arr[pair_cnt].source,source_ip);
					strcpy(ip_arr[pair_cnt].dest,dest_ip);
					ip_arr[pair_cnt].cnt = 1;
					pair_cnt++;
				}
				else{
					ip_arr[flag].cnt++;
				}
				printf("Dest MAC: %s\n", ether_ntoa(&ethernet->ether_dhost));
				printf("Source MAC: %s\n", ether_ntoa(&ethernet->ether_shost));
				struct tm *ltime;
				char timestr[30];
				time_t local_tv_sec;
				local_tv_sec = header->ts.tv_sec;
				ltime = localtime(&local_tv_sec);
				strftime(timestr, sizeof timestr, "%x-%H:%M:%S", ltime);

				printf("Time: %s.%.6d\n", timestr, (int)header->ts.tv_usec);
				printf("Capture length: %d bytes\n", header->caplen);
				printf("\n\n");	
			}
		}
		else if (ret == 0){
			printf("timeout");
		}	
		else if(ret == -1){
			fprintf(stderr,"err:%s\n",pcap_geterr(pd));
		}
		else if(ret == -2){
			printf("done!\n");
			break;
		}
	}
	if(strlen(output_file)){
		FILE *fp = freopen(output_file, "w", stdout); 
	}
	printf("total size:%d\n",pack_byte);
	printf("total:%d\n",pack_cnt);
	printf("Source\t\t\tDestination\t\tCount\n");
	if(strcmp(ord,"asc")==0){
		sorting_arr(1);
		print_arr();
	}
	else if(strcmp(ord,"decs")==0){
		sorting_arr(0);
		print_arr();
	}
	else {
		print_arr();
	}
	return 0;
}