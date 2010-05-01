/**
autores: 
    Augusto Rodrigues de Souza - ra031357 - augustorsouza@gmail.com
    Leonardo Maia Barbosa - ra107213 - leomaia_eco@yahoo.com.br

arquivo: 
    wordharvest.c

funcao: 

parametros:
    -o     [opcional]   determina arquivo de saida
           (ex: -o arquivo_de_saida.txt) (padrao: saida.txt)      
           
    -e     [opcional]   determina tipos de arquivos a serem analisados
           separados por ":" (ex: -e txt:doc:xls) (padrao: txt)
           
    -d     [obrigatorio] determina o diretorio a ser analizado
           (ex: -d /log/)
           
plataforma:
    linux
*/

/* bibliotecas: */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>

/* constantes: */
#define MAX_SIZE 256
#define PARAMETERS_NUMBER 8
#define ONLY_TCP_FILTER "tcp && host "
#define ONLY_UDP_FILTER "udp && host "
#define TCP_SESSIONS_FILTER "(tcp[tcpflags] & tcp-syn) != 0 && (tcp[tcpflags] & tcp-ack) == 0 && host "

#define SUPPORTED_PROTOCOLS_QUANTITY 7
char const * const SUPPORTED_PROTOCOLS_ORDERED_BY_PORT_NUMBER[] = {
    "ftp",
    "ssh",
    "telnet",
    "smtp",
    "http",
    "pop3",
    "ldap"
};

enum FILTER_TYPE { 
    ONLY_TCP, 
    ONLY_UDP,
    TCP_SESSIONS
};

/* variaveis globais: */
char victim_ip[MAX_SIZE] = "";
char victim_ethernet[MAX_SIZE] = "";
char proto[MAX_SIZE] = "";
char pcap_filename[MAX_SIZE] = "";
pcap_t *pcap_descriptor = NULL;

int packet_count(enum FILTER_TYPE filter) {
    struct bpf_program fp;		    /* The compiled filter */
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    char filter_exp[MAX_SIZE] = "";	/* The filter expression */
    int count = 0;

    switch (filter) {
        case ONLY_TCP:
            strcat(filter_exp, ONLY_TCP_FILTER);
        break;
        case ONLY_UDP:
            strcat(filter_exp, ONLY_UDP_FILTER);
        break;
        case TCP_SESSIONS:
            strcat(filter_exp, TCP_SESSIONS_FILTER);
        break;
    }

    strcat(filter_exp, victim_ip);
    
    printf("%s\n", filter_exp);
      
	if (pcap_compile(pcap_descriptor, &fp, filter_exp, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap_descriptor));
		return(2);
	}
	
	if (pcap_setfilter(pcap_descriptor, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap_descriptor));
		return(2);
	}
	
	while (pcap_next_ex(pcap_descriptor, &pkt_header, &pkt_data) == 1) 
	    count++;
   
    return count;
}

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

// funcao para mostrar padrao de execucao
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

int main(int argc, char *argv[])
{
    int i=0;
    
    /* Se o numero de paramestros passados não é o esperado, exibe mensagem de erro */    
    if (argc != PARAMETERS_NUMBER) 
        show_usage_and_exit();
    
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
    
    open_or_reload_pcap_file();
    printf("quantidade de pacotes com protocolo de transporte TCP: %d\n", packet_count(ONLY_TCP));
    
    open_or_reload_pcap_file();
    printf("quantidade de pacotes com protocolo de transporte UDP: %d\n", packet_count(ONLY_UDP));
    
    open_or_reload_pcap_file();
    printf("quantidade de sessões TCP: %d\n", packet_count(TCP_SESSIONS));

    open_or_reload_pcap_file();
    
    for (i=0; i<SUPPORTED_PROTOCOLS_QUANTITY; i++) {
        char *tmp = NULL;
        tmp = strstr(proto, SUPPORTED_PROTOCOLS_ORDERED_BY_PORT_NUMBER[i]);
        if (tmp != NULL)
            printf("%s foi encontrado nos parametros\n",SUPPORTED_PROTOCOLS_ORDERED_BY_PORT_NUMBER[i]);
    }
    
    /* Feche o arquivo e termine a execução */
    pcap_close(pcap_descriptor);
    return(0);
}




