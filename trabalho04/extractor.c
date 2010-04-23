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
    
    return(0);
}




