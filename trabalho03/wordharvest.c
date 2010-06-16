/**********************************************************

editores: Augusto Rodrigues de Souza - ra031357 - augustorsouza@gmail.com
          Leonardo Maia Barbosa - ra107213 - leomaia_eco@yahoo.com.br

arquivo: wordharvest.c

versao: 0.1

funcao: Procurar palavras em arquivos de texto,
        imprimindo as mesmas em um arquivo de saida padrao,
        em ordem alfabetica e uma palavra por linha.
        Cada caracter diferente de uma letra ou numero,
        sera considerado um separador de palavra.
        
parametros:
    -o     [opcional]   determina arquivo de saida
           (ex: -o arquivo_de_saida.txt) (padrao: saida.txt)      
           
    -e     [opcional]   determina tipos de arquivos a serem analisados
           separados por ":" (ex: -e txt:doc:xls) (padrao: txt)
           
    -d     [obrigatorio] determina o diretorio a ser analizado
           (ex: -d /log/)
           
plataforma:
         linux

**********************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define TAM_MAX_PALAVRA 1024
#define TAM_MAX_NOME_ARQUIVO 1024
#define TAM_MAX_LINHA_DE_COMANDO 2048
#define TAM_MAX_REGEXP 1024

char *nome_arq_saida = "saida.txt";			// nome padrao do arquivo de saida	
char *tipo_arq = "txt:text";					// tipo padrao de arquivos 
int flag_varre_arquivo = 0;				// flag para identificar se parametro -d foi passado 
char *caminho_diretorio = "";				// caminho do diretorio a ser analisado

// funcao para mostrar padrao de execucao
void exec_padrao(void)
{
	printf("Padrao de utilizacao:\n");
	printf("[opcional]    -o<name>  determina arquivo de saida  (ex: -o arquivo_de_saida.txt) (padrao: saida.txt) \n");
	printf("[opcional]    -e<name>  determina tipos de arquivos (ex: -e txt:asc:log) (padrao: txt) \n");
	printf("[obrigatorio] -d<name>  determina o diretorio       (ex: -d /log/) \n");
	exit (8);
}

// atribui valor a variavel global do nome de arquivo de saida
void determina_arq_saida(char * ns)
{   
	nome_arq_saida = ns;    
	//printf("###%s\n",nome_arq_saida);
}

// atribui valor a variavel global do tipo de arquivo a ser analisado
void determina_tipo_arq(char * tp)
{   
	tipo_arq = tp;
	//printf("@@@%s\n",&tipo_arq);
}

// efetua varredura nos arquivos conforme cabecalho
void varre_arquivo(char * caminho_arq)
{    
	FILE *arq_entrada;
	FILE *arq_saida;
	int ch;
	char caracter;
	int ultimo_visitado_era_valido=0; // utilizado para evitar repetição de '\n'
 
	arq_entrada = fopen(caminho_arq,"r");
	arq_saida = fopen("arq_saida_temp.txt", "a" ); 	// arquivo temporario de saida

	if (!arq_entrada)
		printf("ERRO ao abrir arquivo: %s\n", caminho_arq);   
	else
	{
		ch = getc( arq_entrada );
		
		while( ch != EOF )
		{
			caracter = ch;

			// valor decimal de 48 a 57 = numeros de 0 a 9
			// valor decimal de 65 a 90 = letras de A a Z
			// valor decimal de 97 a 122 = letras de a a z

			// PELO QUE EU ENTENDI OS SIMBOLOS E CARACTERES ACENTUADOS DEVERAO SER DESCONSIDERADOS

			if ((ch >= 48 && ch <=57) || (ch >= 65 && ch <=90) || (ch >= 97 && ch <=122))
			{
			    ultimo_visitado_era_valido = 1;
				putc(caracter, arq_saida);
			}
			else
			{
				if (ultimo_visitado_era_valido) {
				    putc('\n', arq_saida);
				    ultimo_visitado_era_valido = 0;
			    }
			}
			ch = getc(arq_entrada);
		}
	}

	fclose(arq_entrada);
	fclose(arq_saida);
}

// lista arquivos dos tipos especificados nos diretorio especificado 
void lista_diretorio(void)
{
	int i, j; // contadores
	char linha_comando[TAM_MAX_LINHA_DE_COMANDO] = "find ";
	char linha_comando_ordena_palavras[TAM_MAX_LINHA_DE_COMANDO] = "sort -u arq_saida_temp.txt > ";
    char regexp[TAM_MAX_REGEXP] = "\'.*\\.(";
    
	strcat (linha_comando, caminho_diretorio);
	strcat (linha_comando, " -regextype posix-egrep -iregex ");
    
    j = strlen(regexp);
    for(i = 0; i < strlen(tipo_arq); i++) {
        if (tipo_arq[i] != ':')
            regexp[i + j] = tipo_arq[i];
        else
            regexp[i + j] = '|';
    }
    regexp[i + j] = '\0'; // garante que ultimo caracter é um '\0' para delimitar a string
    
    strcat(regexp, (char*)(")\'"));
    strcat(linha_comando, regexp);
    strcat(linha_comando, (char*)("|sort > lista_arquivos_temp.txt "));

	// debbuging purposes
	//printf("linha de comando: %s\n", (linha_comando));

	// chama programa externo
	system(linha_comando);   

	FILE *arq_entrada_lista;
	char nome_arquivo[TAM_MAX_NOME_ARQUIVO];

	arq_entrada_lista = fopen("lista_arquivos_temp.txt","r");	
	if (!arq_entrada_lista)
		printf("ERRO ao abrir arquivo temporario com lista de arquivos: lista_arquivos_temp.txt\n");   
	else
	{
        i=0;
		while (!feof(arq_entrada_lista))
		{
		    i++;
			fscanf (arq_entrada_lista, "%s\n", nome_arquivo);    	
			varre_arquivo(nome_arquivo);
			//printf("arquivo: %s\n", (nome_arquivo));
		}	
	}
	
	//printf("Quantidade de arquivos abertos: %d\n", i);
	
	fclose(arq_entrada_lista);
	system("rm -f lista_arquivos_temp.txt");

	strcat(linha_comando_ordena_palavras, nome_arq_saida); 		
	system(linha_comando_ordena_palavras);  
	//printf("linha_comando_ordena_palavras: %s\n", (linha_comando_ordena_palavras));
	system("rm -f arq_saida_temp.txt");
}


int main(int argc, char *argv[])
{
	//printf("Arquivo: %s\n", argv[0]);
	//printf("Numero de pasystem(linha_comando);  rametros: %d\n",(argc-1)/2);

	while ((argc > 1) && (argv[1][0] == '-'))
	{
	
		switch (argv[1][1])
		{
			case 'o':
			determina_arq_saida(&argv[1][3]);
			//printf("Arquivo de saida: %s\n", &argv[1][3]);
			break;

			case 'e':                 
			determina_tipo_arq(&argv[1][3]);
			//printf("Tipos de arquivos: %s\n", tipo_arq);
			break;

			case 'd':
			flag_varre_arquivo = 1;
			caminho_diretorio = &argv[1][3];
			//printf("Diretorio: %s\n", &argv[1][3]);
			break;

			default:
			//printf("Argumento incorreto: %s\n", argv[1]);
			exec_padrao();
		}

		argv = argv + 2;
		argc = argc - 2;
	}

	if (flag_varre_arquivo == 1)
		lista_diretorio();
	else
		printf("ERRO. Argumento obrigatorio (-d) nao definido.");
	 
	return (0);    
}



