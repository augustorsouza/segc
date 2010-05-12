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

/* Constantes: */
#define MAX_SIZE 256
#define PARAMETERS_NUMBER 7

/* Variáveis globais: */
char interface[MAX_SIZE] = "";
char requisition[MAX_SIZE] = "";
char ip[MAX_SIZE] = "";

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

/* Função main */
int main(int argc, char *argv[]) {
    int i; // contador auxiliar
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

    return(0);
}

