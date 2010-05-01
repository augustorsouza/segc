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

/* variaveis globais: */
char victim_ip[MAX_SIZE] = "";
char victim_ethernet[MAX_SIZE] = "";
char proto[MAX_SIZE] = "";
char pcap_filename[MAX_SIZE] = "";
pcap_t *pcap_descriptor;

enum TRANSPORT_PROTOCOL { 
    TCP, 
    UDP 
};

int packet_count(enum TRANSPORT_PROTOCOL protocol) {
    struct bpf_program fp;		    /* The compiled filter */
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    char filter_exp[MAX_SIZE] = "";	/* The filter expression */
    int count = 0;


    /* Por exemplo: tcp && host 189.126.11.82 */
    if (protocol == TCP)
        strcat(filter_exp, "tcp ");
    else if (protocol == UDP)        
        strcat(filter_exp, "udp ");

    strcat(filter_exp, "&& host ");
    strcat(filter_exp, victim_ip);
        
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
    char *ebuf;
    
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
    
    if ((pcap_descriptor = pcap_open_offline(pcap_filename, ebuf)) == NULL) {
        printf("ERRO NA ABERTURA DO ARQUIVO PCAP %s: %s\n", pcap_filename, ebuf);
        exit(8);
    }


//FIXME:Codigo para converter string de IP em um bpf_u_int32 (guardando aqui caso seja aplicavel...... deletar antes do envio!!!!    
/*    j = 0; */
/*    current_ip_group = 0;*/
/*    for (i=0; i<strlen(victim_ip_string); i++) {*/
/*        ip_group_str[j++] = victim_ip_string[i];*/
/*        ip_group_str[j] = '\0';*/
/*        if  ((victim_ip_string[i+1] == '.') || (i == strlen(victim_ip_string) - 1)){*/
/*            victim_ip += atoi(ip_group_str) << 24 - 8*current_ip_group;*/
/*            current_ip_group++;*/
/*            i++;*/
/*            j = 0;*/
/*        }*/
/*    }*/
    

    printf("quantidade de pacotes com protocolo de transporte TCP: %d\n", packet_count(TCP));
    printf("quantidade de pacotes com protocolo de transporte UDP: %d\n", packet_count(UDP));
    
    /* Feche o arquivo pcap e termine a execução */
    pcap_close(pcap_descriptor);
    return(0);

}




