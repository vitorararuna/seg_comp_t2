
# from src.primitives import xor,i2osp, os2ip, mask, remove_mask, sha256, mask1
import os
import RSA.utils as utils
from RSA.rsa import RSAKeys

# Vale ressaltar que em alguns casos, a funcao octetoParaInteiro gera um inteiro muito grande -> BUG nao tratado

# EME- OAEP ENCONDING & RSAES - OAEP Encryption process: 
# https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf


# ----------------------------------------------------------------------------------------------------------------- # 




# RSAES-OAEP-Encrypt((n, e), M, P)
#      Entradas:
#          1. Chave pública RSA - (e, n) 
#          2. M - Mensagem a ser cifrada uma string de octetos de comprimento no máximo k - 2 - 2*hLen, 
#             onde k é o comprimento em octetos do módulo n e hLen é o comprimento em octetos da saída 
#             da função hash para EME-OAEP.
#          3. P - parâmetros de codificação, uma string de octeto que pode estar vazia
#      Saída:
#           1. C - Mensagem cifrada em string de octetos de comprimento k
#      Erros: 1. mensagem muito longa
#      Suposição: a chave pública (n, e) é válida
#   b"" indica que a string é tratada como uma sequência de 
#   bytes em vez de uma sequência de caracteres Unicode
def oaep_encrypt(chavePub:RSAKeys, M, P = b"") -> bytes:
    print("oaep_encrypt")
    M = M +  ' '

    # Operação de codificação EME-OAEP (oaep_encode) à mensagem M e ao parâmetros de 
    #  codificação P para produzir uma mensagem codificada EM de comprimento k - 1 octetos:
    #  k = o comprimento em octetos do módulo n
    k = chavePub.tamanhoEmBytes()
    print("chavePub.tamanhoEmBytes", k)
    EM = oaep_encode(M, k-1, P)

    # Converte EM em uma mensagem inteira representativa m
    m = utils.octetoParaInteiro(EM)
    print("octetoParaInteiro(EM)", m)

    # Aplica a primitiva de criptografia RSAEP à chave pública (n, e)
    # e o representante da mensagem "m" para produzir um texto cifrado inteiro representativo c:
    c = rsaep(chavePub=chavePub, m=m)
    print("RSAEP à chave pública (n, e)", c)

    # 5. Converta o texto cifrado representativo c em um texto cifrado C de comprimento k octeto
    C = utils.inteiroParaOcteto(c, k)
    print("inteiroParaOcteto", C)
    return C


# OAEP encoding operation:

# Entradas:
#     - M: mensagem a ser codificada, uma string de octetos de comprimento máximo (emLen - 1 - 2hLen)  
#     - P: Parâmetros de Codificação, uma string de octeto
#     -emLen: Comprimento pretendido em octetos da mensagem codificada, pelo menos 2hLen + 1
# Opcoes: 
#     - Funcao hash (hLen denota o comprimento em octetos da saída da função hash)
#     - Funcao mask para gerar a mascara
# Saida:
#     - EM: Mensagem codificada, uma string de octetos de comprimento emLen
# Exceções:
#     - Mensagem muito longa // String de parâmetro muito longa

def oaep_encode(M:str, emLen, label= b"", hash=utils.sha256, mask=utils.mask) -> bytes:
    print("oaep_encode")
    # 1. Se o comprimento de P for maior que a limitação de entrada para a função hash:
     # (2 ^ 61 - 1 octetos para SHA-1) ---> ‘string de parâmetro muito longa’

    # 2. let pHash = Hash(P), an octet string of length hLen.
    M = M.encode('utf-8')
    lHash = hash(label)
    hLen = len(lHash)
    mLen = len(M)    
    # 4. Generate an octet string PS consisting of (emLen − mLen − 2hLen − 1) zero octets. 
    # The length of PS may be 0.

    # Gera uma string de octetos PS  de (emLen − mLen − 2hLen − 1) zero octetos.
    # O comprimento de PS pode ser 0.

    # PADDING (preenchimento):
    zero_octet = b'\x00'
    PS = zero_octet * (emLen - mLen - 2*hLen - 2)
    
    # 5. Concatena lHash, PS, mensagem M e outros preenchimentos para formar um bloco de dados BD:
    # BD = lHash + PS + 01 + M.
    BD = lHash + PS + b'\x01' + M

    # 6. Gera uma seed de string de octetos aleatória de comprimento hLen.
    seed = os.urandom(hLen)

    # 7. Seja bdMask = mask(seed, emLen − hLen)
    bdMask = mask(seed, emLen - hLen)

    # 8. DB xor bdMask.
    maskedBd = utils.xor(BD, bdMask)

    # 9. mask(maskedBd, hLen).
    seedMask = mask(maskedBd, hLen)

    # 10. seed xor seedMask.
    maskedSeed = utils.xor(seed, seedMask)

    # 11. maskedSeed + maskedBd.
    EM = maskedSeed + maskedBd

    # 12. Output EM.
    return EM


def rsaep(chavePub:RSAKeys, m) -> int:
# Processo de cifrar Rsa
#     Chave Publica = (e, n)

    e, n = chavePub.pegarChave()
    c = pow(m, e, n)
    if c > n - 1 or c < 0:
        raise ValueError("M out of range")
    return c






# RSAES - OAEP Decryption process:
# https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf


def oaep_decrypt(chavePriv:RSAKeys, C, P=b"") -> str:
#  RSAES-OAEP-Decrypt(K, C, P)
#         Entradas: 
#             1. K - Chave privada RSA dos destinatários
#             2. C - Texto cifrado a ser descriptografado, uma string de octetos de comprimento k
#             3. P - parâmetros de codificação, uma string de octeto que pode estar vazia

#         Saidas:
#             1. M - (mensagem) uma string de octetos de comprimento no máximo k - 2 - 2hLen, onde hLen é o comprimento em octetos
#             da saída da função hash para EME-OAEP
#         Errors:
#             1. Erro ao decifrar

    # steps:
    k = chavePriv.tamanhoEmBytes()
    # 1. Se o comprimento do texto cifrado C não for k octetos, erro de descriptografia.
    cLen = len(C)
    if cLen != k:
        raise ValueError("Erro na descriptografia, número distinto de octetos")
    # 2. Converte o texto cifrado C em um texto cifrado inteiro representativo c
    c = utils.octetoParaInteiro(C)
    
    # 3. Aplica a primitiva de descriptografia RSADP à chave privada K e ao texto cifrado
    # representante c para produzir uma mensagem inteira
    m = rsadp(chavePriv=chavePriv, c=c)
    
    # 4. Converte a mensagem representativa m em uma mensagem codificada EM de comprimento k − 1 octetos
    EM = utils.inteiroParaOcteto(m, k - 1)
   
    # 5. Aplica a operação de decodificação EME-OAEP à mensagem codificada EM e
    # os parâmetros de codificação P para recuperar uma mensagem
    M = oaep_decode(EM, P)
   
    # 6. Output da mensagem
    return M.decode('utf-8')

def oaep_decode(ME, label = b'', hash=utils.sha256, mask=utils.mask) -> bytes:
#   EME-OAEP-Decode(EM, P)
#         Opcoes: 
#               - Funcao hash (hLen denota o comprimento em octetos da saída da função hash)
#               - Funcao mask para gerar a mascara
#         Entrada: 
#             1. EM - mensagem codificada, uma string de octetos de comprimento de pelo menos 2hLen + 1 (meLen denota o comprimento em
#                     octetos de EM)
#             2. P - Parâmetros de codificação, uma string de octeto
#         Saida:
#             1. M - mensagem recuperada, uma cadeia de octetos de comprimento no máximo meLen - 1 - 2hLen
#         Erros:
#             1. Erro de decodificação

        # steps:
        # 1. Se o comprimento de P for maior que a limitação de entrada, “erro de decodificação”.
        # SHA1: 2^61 - 1
        if len(label) > (pow(2, 61) - 1):
            raise ValueError("Erro de decodificação, parametro mt grande")
        # 2. Se meLen < 2hLen + 1, imprima ‘erro de decodificação’.
        meLen = len(ME) 
        lHash = hash(label)
        hLen = len(lHash)

        #nseisepreciso 
        if meLen < ((2*hLen) + 1):
            raise ValueError("Erro de decodificação, parametro mt grand")
        
        # 3. Seja maskedSeed os primeiros hLen octetos de ME e maskedBd os demais octetos meLen-hLen.
        maskedSeed = ME[0:hLen]
        maskedBd = ME[hLen+1:-1]
        # 4. mask(maskedBd, hLen).
        seedMask =  mask(maskedBd, hLen)
        # 5. maskedSeed xor seedMask.
        seed = utils.xor(maskedSeed,seedMask) 
        # 6. mask(seed , meLen - hLen)
        bdMask = mask(seed, meLen - hLen)
        # 7. maskedBd xor bdMask.
        DB = utils.xor(maskedBd, bdMask)
        # 8. pHash = Hash(P), an octet string of length hLen.
        index = DB.find(b'\x01') + 1
        if lHash not in DB:
            raise ValueError("Hash nao presente BD")

        # 9. Separa DB em uma string de octeto pHash || PS || 01 || M
        # 10. return m
        return DB[index:]

def rsadp(c, chavePriv: RSAKeys) -> int:
# Processo de decifrar RSA
# Chave Privada = (d, n)
    d, n = chavePriv.pegarChave()
    m = pow(c, d, n)
    if m > n - 1 or m < 0:
        raise ValueError("Texto cifrado grande demais!")
    return m
