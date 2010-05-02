/**
Autores: 
    Augusto Rodrigues de Souza - ra031357 - augustorsouza@gmail.com
    Leonardo Maia Barbosa - ra107213 - leomaia_eco@yahoo.com.br

Arquivo: 
    extractor.c

parametros:
    --victim_ip  = IP do host monitorado   
    --victim-ethernet = MAC do host monitorado
    -proto Protocolos de aplicação que serão monitorados
    <arquivo pcap> Arquivo pcap do trafego a ser monitorado
           
plataforma:
    linux
*/

/* Bibliotecas: */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>

/* Constantes: */
#define MAX_SIZE 256
#define PARAMETERS_NUMBER 8

#define ONLY_TCP_FILTER "tcp && host " // filtro para contar pacotes tcp
#define ONLY_UDP_FILTER "udp && host " // filtro para contar pacotes udp
#define TCP_SESSIONS_FILTER "(tcp[tcpflags] & tcp-syn) != 0 && (tcp[tcpflags] & tcp-ack) == 0 && host " // filtro para contar sessões tcp
#define APPLICATION_PROTOCOL_SESSIONS_FILTER "(tcp[tcpflags] & tcp-syn) != 0 && (tcp[tcpflags] & tcp-ack) == 0 && port " // filtro para contar sessões tcp de um determinado protocolo de aplicação

#define SUPPORTED_PROTOCOLS_QUANTITY 7
char const * const SUPPORTED_PROTOCOLS_ORDERED_BY_PORT_NUMBER[] = {
    "ftp",      // 21
    "ssh",      // 22
    "telnet",   // 23
    "smtp",     // 25
    "http",     // 80
    "pop3",     // 110
    "ldap"      // 389
};

/* Numeradores */
enum FILTER_TYPE { 
    ONLY_TCP, 
    ONLY_UDP,
    TCP_SESSIONS,
    APPLICATION_PROTOCOL_SESSIONS
};

/* Variáveis globais: */
char victim_ip[MAX_SIZE] = "";
char victim_ethernet[MAX_SIZE] = "";
char proto[MAX_SIZE] = "";
char pcap_filename[MAX_SIZE] = "";
pcap_t *pcap_descriptor = NULL;

/* Função para contar o número de pacotes de acordo com um determinado filtro */
int packet_count(enum FILTER_TYPE filter, char *protocol) {
    struct bpf_program fp;		    // filtro compilado
    struct pcap_pkthdr *pkt_header; // cabeçalho de um determinado pacote, informação que não utilizaremos
    const u_char *pkt_data;         // dados de um determinado pacote, informação que não utilizaremos
    char filter_exp[MAX_SIZE] = "";	// expressão para descrever o filtro
    int count = 0;                  // contador de pacotes

    switch (filter) {
        case ONLY_TCP:
            strcat(filter_exp, ONLY_TCP_FILTER);
            strcat(filter_exp, victim_ip);
        break;
        case ONLY_UDP:
            strcat(filter_exp, ONLY_UDP_FILTER);
            strcat(filter_exp, victim_ip);
        break;
        case TCP_SESSIONS:
            strcat(filter_exp, TCP_SESSIONS_FILTER);
            strcat(filter_exp, victim_ip);
        break;
        case APPLICATION_PROTOCOL_SESSIONS:
            strcat(filter_exp, APPLICATION_PROTOCOL_SESSIONS_FILTER);
            strcat(filter_exp, protocol);
            strcat(filter_exp, "&& host ");
            strcat(filter_exp, victim_ip);
        break;
    }

	if (pcap_compile(pcap_descriptor, &fp, filter_exp, 0, 0) == -1) {
		fprintf(stderr, "Não foi possível interpretar o filtro %s: %s\n", filter_exp, pcap_geterr(pcap_descriptor));
		exit(8);
	}
	
	if (pcap_setfilter(pcap_descriptor, &fp) == -1) {
		fprintf(stderr, "Não foi possível interpretar o filtro %s: %s\n", filter_exp, pcap_geterr(pcap_descriptor));
		exit(8);
	}
	
	/* Após aplicado o filtro basta contar a quantidade de pacotes no descriptor */
	while (pcap_next_ex(pcap_descriptor, &pkt_header, &pkt_data) == 1) 
	    count++;
   
    return count;
}

/* Função para abrir (caso ainda não tenha sido aberto) ou reabrir arquivo pcap */
void open_or_reload_pcap_file() {
    char *ebuf;
    
    /* Se o arquivo já estiver aberto, então o fecharemos */
    if (pcap_descriptor != NULL)
        pcap_close(pcap_descriptor);

    /* Abre o arquivo pcap_filename com checagem de erros */        
    if ((pcap_descriptor = pcap_open_offline(pcap_filename, ebuf)) == NULL) {
        printf("ERRO NA REABERTURA DO ARQUIVO PCAP %s: %s\n", pcap_filename, ebuf);
        exit(8);
    }
}

/* Função para mostrar padrao de execucao */
void show_usage_and_exit(void)
{
	printf("Padrao de utilizacao:\n");
	printf("[obrigatorio] --victim_ip  IP do host monitorado\n");
	printf("[obrigatorio] --victim_ethernet MAC do host monitorado\n");
	printf("[obrigatorio] -proto Protocolos de aplicação que serão monitorados\n");
	printf("[obrigatorio] Passar arquivo PCAP como ultimo parametro\n");
	printf("Exemplo de utilização: ./extractor --victim-ip 10.0.0.1 --victim-ethernet 00:0f:20:2f:63:d9 -proto http,ftp,smtp teste.pcap\n");
	exit(8);
}

/* Função main */
int main(int argc, char *argv[]) {
    int i=0; // contador auxiliar
    
    /* Se o numero de paramestros passados não é o esperado, exibe mensagem de erro */    
    if (argc != PARAMETERS_NUMBER) 
        show_usage_and_exit();
    
    /* Extrai parametros */
    for(i=1; i<argc; i=i+2) {
        if (!strcmp(argv[i], "--victim-ip"))
            strcpy(victim_ip, argv[i+1]);
        else if (!strcmp(argv[i], "--victim-ethernet"))
            strcpy(victim_ethernet, argv[i+1]);
        else if (!strcmp(argv[i], "-proto"))
            strcpy(proto, argv[i+1]);
    }
    
    /* O ultimo parametro passado na linha de comando é o arquivo pcap */
    strcpy(pcap_filename, argv[PARAMETERS_NUMBER-1]);

    /* Se algum dos parametros não foi settado corretamente, exibe mensagem de erro */
    if ((!strcmp(victim_ip, "")) || (!strcmp(victim_ethernet, "")) || (!strcmp(proto, "")) || (!strcmp(pcap_filename, "")))
        show_usage_and_exit();
    
    /* Imprime quantidade de pacotes tcp */
    open_or_reload_pcap_file();
    printf("%d\n", packet_count(ONLY_TCP, NULL));

    /* Imprime quantidade de pacotes udp */    
    open_or_reload_pcap_file();
    printf("%d\n", packet_count(ONLY_UDP, NULL));

    /* Imprime quantidade de pacotes sessões tcp */        
    open_or_reload_pcap_file();
    printf("%d\n", packet_count(TCP_SESSIONS, NULL));

    /* Imprime para cada protocolo de aplicação passado como parametro a quantidade de sessões tcp */    
    for (i=0; i<SUPPORTED_PROTOCOLS_QUANTITY; i++) {
        char *tmp = NULL;
        tmp = strstr(proto, SUPPORTED_PROTOCOLS_ORDERED_BY_PORT_NUMBER[i]);
        if (tmp != NULL) {
            open_or_reload_pcap_file();
            printf("%d\n", packet_count(APPLICATION_PROTOCOL_SESSIONS, (char*)SUPPORTED_PROTOCOLS_ORDERED_BY_PORT_NUMBER[i]));
        }
    }
    
    /* Feche o arquivo e termine a execução */
    pcap_close(pcap_descriptor);
    return(0);
}

