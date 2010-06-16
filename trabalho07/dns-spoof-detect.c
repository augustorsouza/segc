/**
Autores: 
    Augusto Rodrigues de Souza - ra031357 - augustorsouza@gmail.com
    Leonardo Maia Barbosa - ra107213 - leomaia_eco@yahoo.com.br

Arquivo: 
    dns-spoof-detect.c

parametros:
    --interface   = A interface que será ouvida, ex.: eth0   
           
plataforma:
    linux
*/

/* Bibliotecas: */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
//#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

/* Constantes: */
#define MAX_SIZE 256
#define PARAMETERS_NUMBER 3
#define ONLY_DNS_FILTER "src port 53" 			// filtro para obter apenas requisições DNS desejadas; source port 53
#define DNS_HEADER_SIZE_IN_BYTES 12
#define UDP_HEADER_SIZE_IN_BYTES 8
#define SIZE_ETHERNET 14
#define MAX_NUM_PACKET 1000				// numero maximo de pacotes a serem armazenados no buffer

/* Variáveis globais: */
char interface[MAX_SIZE] = "";
char requisition[MAX_SIZE] = "";
char ip[MAX_SIZE] = "";
pcap_t *descriptor = NULL;


int global_counter = 0;					// contador global do numero de pacotes DNS contidos no buffer
int buffer_dns_id[MAX_NUM_PACKET];			// buffer que registra id dos pacotes 	(hex 0x0000)
char buf_ip_address_converted[16];			// variavel para registrar o valor ip convertido u_char -> char (16bits XXX.XXX.XXX.XXX\0)
char buf_ip_address_duplicated[MAX_SIZE];		// variavel para registrar ocorrencias duplicadas e imprimi-las posteriormente
char buffer_dns_ip[MAX_NUM_PACKET][16];			// buffer que registra ip (answer) dos pacotes 			(16bits XXX.XXX.XXX.XXX\0)
int flag_big_endian = 1;

// Verifica se o sistema eh little endian ou big endian
union endian_tester {
    uint32_t my_int;
    uint8_t  my_bytes[4];
} et;


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

/* Zerar variavel global */
void reset_buf_ip_address_converted()
{
	int k = 0;
	for ( ; k < 7; k++)
		buf_ip_address_converted[k] = 0;
	buf_ip_address_converted[k] = '\0';
}

/* Zerar buffers globais */
void reset_global_buffers()
{
	int k = 0;
	int m = 0;
	for ( ; k < MAX_NUM_PACKET-1; k++)
	{
		buffer_dns_id[k] = 0;
		for ( ; m < 16-1; m++)
			buffer_dns_ip[k][m] = 0;
	}
	buffer_dns_id[k] = 0;
	buffer_dns_ip[k][m] = '\0';
}

/* Zerar variavel global */
void reset_buf_ip_address_duplicated()
{
	int k = 0;
	for ( ; k < MAX_SIZE-1; k++)
		buf_ip_address_duplicated[k] = 0;
	buf_ip_address_duplicated[k] = '\0';
}

/* Find duplicated dns_answer packets comparing id's */
int find_duplicated_dns_answer_packets(int num_dns)
{
	int m = 0;
	int flag_found = 0;

	for ( ; m < global_counter; m++)
	{
		if (buffer_dns_id[m] == num_dns)
		{
			flag_found = 1;
			strcat(buf_ip_address_duplicated, buffer_dns_ip[m]);
			strcat(buf_ip_address_duplicated, ", ");
		}
		
		//DEBUG PURPOSES
		//printf("BUFFER_ID[%i]: 0x%x \n" , m , buffer_dns_id[m]);		
		//printf("BUFFER_IP[%i]: %s \n" , m , buffer_dns_ip[m]);
	}

	// contatena ip corrente na string
	if (flag_found)
	{	
		strcat(buf_ip_address_duplicated, buf_ip_address_converted);
		strcat(buf_ip_address_duplicated, ", ");
	}
	//printf("buf_ip_address_converted: %s " , buf_ip_address_converted);
	return flag_found;
}

/* Função para extrair o campo "answer" do pacote dns */
int get_dns_answer_in_dns_answer(u_char *qr) 
{
    int i = 0;
    int flag1 = 0;
    int flag2 = 0;
    int flag_no_dns_packet = 0;
    int resposta = 0;
    char buf_temp[8];

    do
	{
		if ((qr[i] == 0x00))
			flag1 = 1;
		else
			flag1 = 0;	

		if ((qr[i+1] == 0x04))
			flag2 = 1;
		else
			flag2 = 0;

		resposta = flag1 * flag2;

		i = i + 1;

		if (i == MAX_SIZE)
		{
			resposta = 1;	
			flag_no_dns_packet = 1;
		}
		
		//{printf("flag1: %i flag2: %i \n", flag1, flag2);}
	}while (resposta == 0);

	i = i + 1;
	
	// dns packet identify
	if (flag_no_dns_packet == 0)
	{	
		reset_buf_ip_address_converted();
	
		sprintf (buf_temp, "%d", qr[i]);
		strcat (buf_ip_address_converted, buf_temp);
		strcat (buf_ip_address_converted, "." );

		sprintf (buf_temp, "%d", qr[i+1]);
		strcat (buf_ip_address_converted, buf_temp);
		strcat (buf_ip_address_converted, "." );

		sprintf (buf_temp, "%d", qr[i+2]);
		strcat (buf_ip_address_converted, buf_temp);
		strcat (buf_ip_address_converted, "." );

		sprintf (buf_temp, "%d", qr[i+3]);
		strcat (buf_ip_address_converted, buf_temp);

		//printf ("buf_ip_address_converted: %s", buf_ip_address_converted);
	
		return 1;
	}
	else
		return 0;
}


/* Callback para processar o pacote recebido */
void process_dns_packet_callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
     int i = 0;
	const struct ether_header *ethernet; // cabecalho ethernet
	const struct ip *ip_hdr;             // cabecalho ip
	const struct dnsheader *dns_hdr;         // cabecalho dns
    u_int size_ip;
	u_char *transport_hdr; // cabecalho da camada de transporte (tcp ou udp)
	u_char *dns_msg_start;
	char dns_qname[MAX_SIZE];
	char dns_ansname[18];
	u_int16_t source_port;

	u_int16_t dns_id = 0x0000; 		// registra o id do dns de resposta; endian purpose
	u_int16_t dns_id_hs = 0x0000; 		// registra a parte mais significativa do id do dns de resposta; endian purpose
	u_int16_t dns_id_ms = 0x0000; 		// registra a parte menos significativa do id do dns de resposta; endian purpose
    
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
        return; // do nothing
    }
     
   get_dns_domain_in_query(dns_msg_start, dns_qname); 
 
   // verificacao endian
   if (flag_big_endian == 0)
	{
	dns_id_hs = (0xFF00 & dns_hdr->id); 
	dns_id_ms = (0x00FF & dns_hdr->id);

	//printf("dns_hdr->id: %x ", dns_hdr->id);
	//printf("id_hs: %x ", (id_hs));
	//printf("id_ms: %x ", (id_ms));
	dns_id_ms = (dns_id_ms * 0x0100);
	dns_id_hs = (dns_id_hs / 0x0100);

	// printf("id_ms: %x ", (id_ms));
	// printf("id_hs: %x ", (id_hs));
	
	dns_id = (dns_id | dns_id_ms); 
	dns_id = (dns_id | dns_id_hs);
	//printf("dns_id: %x ", dns_id);

	}
   else
	dns_id = dns_hdr->id;

   if (get_dns_answer_in_dns_answer(dns_msg_start))
	{
		// verifica pacotes duplicados		
		if (find_duplicated_dns_answer_packets(dns_id))		
		{
			printf("Requisicao DNS sobre o dominio: %s \n", dns_qname);
			printf("Respostas: %s" , buf_ip_address_duplicated);
			printf("\n\n\n");
			reset_buf_ip_address_duplicated();
		}

		// adiciona este pacote no buffer global
		buffer_dns_id[global_counter] = (dns_id);
		strcpy(buffer_dns_ip[global_counter], (buf_ip_address_converted));

		// buffer global limtado a MAX_NUM_PACKET
		if (global_counter < MAX_NUM_PACKET)
			global_counter++;
		else
			reset_global_buffers();		

		// DEBUGGING PURPOSES
		//printf("\n\n\n");
		//printf("ipsource: %s dns_qname: %s\n", inet_ntoa(ip_hdr->ip_src), dns_qname);
		//printf("ipdest:%s ", inet_ntoa(ip_hdr->ip_dst));
		//printf("ip_hdr->ip_id:%i\n", ip_hdr->ip_id);
		//printf("dns_id:0x%x\n", dns_id);
		//printf("dns_hdr->flags_and_codes:%x\n", dns_hdr->flags_and_codes);
		//printf("dns_hdr->qdcount:%i\n", dns_hdr->qdcount);
		//printf("dns_hdr->ancount:%i\n", dns_hdr->ancount);
		//printf("dns_hdr->nscount:%i\n", dns_hdr->nscount);
		//printf("dns_hdr->arcount:%i\n", dns_hdr->arcount);
		//printf("dns_ansname: %s \n\n\n", buf_ip_address_converted);
	}
  
}

/* Função main */
int main(int argc, char *argv[]) {
    int i; // contador auxiliar

	// Verifica se o sistema eh big ou little endian
	et.my_int = 0x0a0b0c0d;
	if(et.my_bytes[0] == 0x0a )
	{
		//printf( "big-endian system\n" );
		flag_big_endian = 1;
	}
	else
	{
		//printf( "little-endian system\n" );
		flag_big_endian = 0;
	}

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
    }

    /* Se algum dos parametros não foi settado corretamente, exibe mensagem de erro */
    if ((!strcmp(interface, "")))
        show_usage_and_exit();

    /* Inicio do sniffing da interface por requisições DNS */
    start_sniffing_interface_for_dns_traffic();
    
    pcap_loop(descriptor, -1, process_dns_packet_callback, NULL);
    
    return(0);
}

