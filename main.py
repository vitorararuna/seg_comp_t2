

import sys
from RSA.rsa import importarChave;
novos_caminhos = [
    '/Users/vitorararuna/dev/trabalho-seg-comp/RSA',
]
sys.path.extend(novos_caminhos)
# print(sys.path)

from RSA.rsa import RSAKeys
import time

def main():
    tam_chave_em_bits = 1024
    chavePublica = None
    chavePrivada = None

    a = True
    while a:
        print("1 - Gerar Chaves")
        print("2 - Exportar Ultima Chave Gerada")
        print("3 - Criptografia OAEP")
        a = input("Escolha uma opcao: ")
        if a == '1':
            try:
                print('\n\n')
                print('************ RSA -> Gerador de Chaves ************')
                tam_chave_em_bits =  input("Tamanho de chave desejado (em bits): ")
                tam_chave_em_bits =  int(tam_chave_em_bits)

                print("Gerando chave de " + str(tam_chave_em_bits)+ " bits... Aguarde!")
                start = time.time()

                parDeChaves = RSAKeys(tam_chave_em_bits)

                chavePublica = parDeChaves.criarChavePublica 
                chavePrivada = parDeChaves.criarChavePrivada


                print('Chave Pública Gerada: ', chavePublica.pegarChave())
                print('Chave Privada Gerada: ', chavePrivada.pegarChave())
                print("--- Tempo Total Em Segundos Para Geracao de Chaves:!!! ---", (time.time() - start))
                print('\n\n')
            except:
                print(" ********** Erro inesperado na tentativa de gerar chaves ********** ") 
        elif a == '2':
            try:
                print('\n\n')
                print('************ EXPORTANDO ÚLTIMA CHAVE GERADA ************')

                pubExpotada = chavePublica.exportarChave()
                arqPublica = input("Nome para Chave Publica (arquivo será salvo): ")
                with open(arqPublica, 'w') as f:
                    f.write(pubExpotada)
                privName = input("Nome para Chave Privada (arquivo será salvo): ")
                privExportada = chavePrivada.exportarChave()
                with open(privName, 'w') as f:
                    f.write(privExportada)
                print(' pub exportada: \n', pubExpotada)
                print(' priv exportada: \n', privExportada)
                print('\n\n')

            except (KeyError, ValueError):
                print(KeyError, ValueError)
                print(" ********** Erro inesperado na tentativa de expor chaves ********** ") 
        elif a == '3':
            option = True
            while option:
                print('************ CRIPTOGRAFIA OAEP ************')
        elif a == 'x':
            break
        else:
            print('Opcao inválida.')
    
    
if __name__ == '__main__':
    main()