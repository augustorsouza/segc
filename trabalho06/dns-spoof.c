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

/* Constantes: */
#define MAX_SIZE 256
#define PARAMETERS_NUMBER 7
#define ONLY_DNS_FILTER "udp port 53" // filtro para obter apenas requisições DNS
#define DNS_HEADER_SIZE_IN_BYTES 12

/***************************************************************************/
/* INICIO de trecho de código extraido de http://www.tcpdump.org/pcap.htm  */

/* Ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TERMINO de trecho de código extraido de http://www.tcpdump.org/pcap.htm */
/***************************************************************************/

/***************************************************************************/
/* INICIO de trecho de código extraido do código fonte do tcpdump          */

/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
struct udphdr {
	u_int16_t	uh_sport;		/* source port */
	u_int16_t	uh_dport;		/* destination port */
	u_int16_t	uh_ulen;		/* udp length */
	u_int16_t	uh_sum;			/* udp checksum */
};

/* TERMINO  de trecho de código extraido do código fonte do tcpdump        */
/***************************************************************************/

/* Variáveis globais: */
char interface[MAX_SIZE] = "";
char requisition[MAX_SIZE] = "";
char ip[MAX_SIZE] = "";
pcap_t *descriptor = NULL;

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

void process_dns_packet_callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	const struct sniff_ethernet *ethernet; // cabecalho ethernet
	const struct sniff_ip *ip_hdr; // cabecalho ip
    u_int size_ip;
	const struct udphdr *udp; // cabecalho udp
	u_char *dns_msg_start;
	char dns_qname[MAX_SIZE];
    
	ethernet = (struct sniff_ethernet*)(packet);
    ip_hdr = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip_hdr)*4;
	if (size_ip < 20) {
		printf("Cabeçalho ip de tamanho invalido: %u bytes\n", size_ip);
		return;
	}
    
    udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
    
    dns_msg_start = (u_char*)(packet + SIZE_ETHERNET + size_ip + sizeof(struct udphdr) + DNS_HEADER_SIZE_IN_BYTES);
    get_dns_domain_in_query(dns_msg_start, dns_qname);
    
    if (!strcmp(requisition, dns_qname)) {
        printf("**************************************************************************************************\n");    
        printf("O host %s fez uma requisição a %s\n", inet_ntoa(ip_hdr->ip_src), dns_qname);
        printf("Resta responder o requisitante (MAC %s; IP %s; porta udp 0x%x;) dizendo que o host requisitado está no ip %s\n", (char*)ether_ntoa(ethernet->ether_shost), inet_ntoa(ip_hdr->ip_src), udp->uh_sport, ip);
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

