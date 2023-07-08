

import sys
from RSA.rsa import importarChave;
from RSA.oaep import oaep_encrypt;
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

                # Gets
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
                nomeArqPub = input("Nome para Chave Publica (arquivo será salvo): ")
                with open(nomeArqPub, 'w') as f:
                    f.write(pubExpotada)
                nomeArqPriv = input("Nome para Chave Privada (arquivo será salvo): ")
                privExportada = chavePrivada.exportarChave()
                with open(nomeArqPriv, 'w') as f:
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
                option = input("1) Cifrar\n2) Decifrar\nEscolha uma opcao: ")
                if int(option) == 1:
                    print("111")
                    if int(input) == 1:
                        path = input("Path da chave publica: ")
                        chavePubImportada = importarChave(path)
                        mensagem = input("Mensagem para cifrar: ")
                        EM = oaep_encrypt(M=mensagem, pub_key=chavePubImportada)
                        print("Mensagem cifrada com OAEP: ",EM)
                        export = input("1)Exportar mensagem cifrada\n 2) Voltar ")
                        if int(export) == 1:
                            nomeArq = input("Nome do arquivo para mensagem cifrada:")
                            with open(nomeArq, 'wb') as f:
                                f.write(EM)
                        elif int(option) == 2:
                            print("222")
                        else:
                            break   
        elif a == 'x':
            break
        else:
            print('Opcao inválida.')
    
    
if __name__ == '__main__':
    main()