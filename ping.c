#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

/* IP Header */
struct ipheader
{
	unsigned char iph_ihl : 4 , //IP header length
		      iph_ver : 4 ; //IP version
	unsigned char iph_tos ; //Type of service
	unsigned short int iph_len ; //IP Packet length (data+ header )
	unsigned short int iph_ident ; //Identification
	unsigned short int iph_flag : 3 , //Fragmentation flags
		           iph_offset:13; //Flags offset
	unsigned char iph_ttl ; //Time to Live
	unsigned char iph_protocol; //Protocol type
	unsigned short iph_chksum; //IP datagram checksum
	struct in_addr iph_sourceip ; //Source IP address
	struct in_addr iph_destip ; //Destination IP address
} ;

/* ICMP Header */
struct icmpheader {
	unsigned char icmp_type ; // ICMP me s sage type
	unsigned char icmp_code ; // Erro r code
	unsigned short int icmp_chksum; //Checksum for ICMP Header and data
	unsigned short int icmp_id; //Used for ide ntifying request
	unsigned short int icmp_seq ; //Sequence number
} ;

unsigned short in_cksum (unsigned short *buf, int length ) ;
void send_raw_ip_packet (struct ipheader* ip);


int main (int argc, char *argv[])
{
	char buffer[1500] ;
	memset (buffer , 0 , 1500 ) ;
	struct icmpheader *icmp = (struct icmpheader * )(buffer + sizeof (struct ipheader ));
	icmp->icmp_type = 8 ; //ICMP Type : 8 is request , 0 is reply .
	// Calculate the checksum for integrity
	icmp->icmp_chksum = 0 ;
	icmp->icmp_chksum = in_cksum((unsigned short * ) icmp,sizeof (struct icmpheader ));
	
	//Fill in the IP header .
	struct ipheader *ip = (struct ipheader *) buffer ;
	ip->iph_ver = 4 ;
	ip->iph_ihl = 5 ;
	ip->iph_ttl = 20 ;
	ip->iph_sourceip.s_addr = inet_addr(argv[1]);
	ip->iph_destip.s_addr = inet_addr(argv[2]);
	ip->iph_protocol = IPPROTO_ICMP;
	ip->iph_len = htons(sizeof(struct ipheader) +sizeof (struct icmpheader)) ;
	
	//Send Packet
	//send_raw_ip_packet (ip) ;
	int i;
	for(i=0;i<3;i++)
	{
		//icmp->icmp_seq=i;
		send_raw_ip_packet (ip) ;
	}
	return 0;
}

void send_raw_ip_packet (struct ipheader* ip )
{
	struct sockaddr_in dest_info ;
	int enable = 1 ;
	int sock = socket (AF_INET , SOCK_RAW, IPPROTO_ICMP) ;
	setsockopt (sock , IPPROTO_IP , IP_HDRINCL , &enable , sizeof(enable));
	dest_info.sin_family = AF_INET ;
	dest_info.sin_addr = ip->iph_destip ;
	sendto(sock , ip , ntohs(ip-> iph_len) , 0 ,(struct sockaddr *) &dest_info , sizeof (dest_info ) ) ;
	close (sock) ;
}

unsigned short in_cksum (unsigned short *buf, int length)
{
	unsigned short *w = buf;
	int nleft = length ;
	int sum= 0;
	unsigned short temp=0;
	while (nleft > 1 )
	{
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1 ) 
	{
		*(u_char *)( &temp ) = *(u_char *) w ;
		sum+= temp ;
	}
	sum= (sum>>16) + (sum & 0xffff ) ;
	sum+= (sum>>16);
	return (unsigned short ) (~sum) ;
}













