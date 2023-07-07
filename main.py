

import sys
novos_caminhos = [
    '/Users/vitorararuna/dev/seg_comp_T2/RSA',
]
sys.path.extend(novos_caminhos)
# print(sys.path)

from RSA.rsa import RSAKeys
import time

def main():
    tam_chave_em_bits = 1024
    chavePublica = None
    chavePrivada = None

    print('************ RSA -> Gerador de Chaves ************')
    tam_chave_em_bits =  input("Tamanho de chave desejado (em bits): ")
    tam_chave_em_bits =  int(tam_chave_em_bits)

    print("Gerando chave de " + str(tam_chave_em_bits)+ " bits... Aguarde!")
    start = time.time()

    parDeChaves = RSAKeys(tam_chave_em_bits)

    chavePublica = parDeChaves.criarChavePublica 
    chavePrivada = parDeChaves.criarChavePrivada


    print('Chave Pública Gerada: ', chavePublica.pegarChave)
    print('Chave Privada Gerada: ', chavePrivada.pegarChave())
    print("--- Tempo Total Para Geracao de Chaves: %ss !!! ---" % (time.time() - start))
    
if __name__ == '__main__':
    main()