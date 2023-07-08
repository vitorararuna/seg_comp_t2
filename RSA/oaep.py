
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

    M = M +  ' '

    # Operação de codificação EME-OAEP (oaep_encode) à mensagem M e ao parâmetros de 
    #  codificação P para produzir uma mensagem codificada EM de comprimento k - 1 octetos:
    #  k = o comprimento em octetos do módulo n
    k = chavePub.tamanhoEmBytes()
    EM = oaep_encode(M, k-1, P)

    # Converte EM em uma mensagem inteira representativa m
    m = utils.octetoParaInteiro(EM)

    # Aplica a primitiva de criptografia RSAEP à chave pública (n, e)
    # e o representante da mensagem "m" para produzir um texto cifrado inteiro representativo c:
    c = rsaep(chavePub=chavePub, m=m)

    # 5. Converta o texto cifrado representativo c em um texto cifrado C de comprimento k octeto
    C = utils.inteiroParaOcteto(c, k)
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


# Processo de criptografia Rsa
#     Chave Publica = (e, n)
def rsaep(chavePub:RSAKeys, m) -> int:
   
    e, n = chavePub.pegarChave()
    c = pow(m, e, n)
    if c > n - 1 or c < 0:
        raise ValueError("M out of range")
    return c






# RSAES - OAEP Decryption process:
# https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf

def oaep_decrypt(prv_key:RSAKeys, C, P=b"") -> str:
    """RSAES-OAEP-Decrypt(K, C, P)
        Inputs: 
            1. K - recipients RSA private key
            2. C - ciphertext to be decrypted, an octet string of length k
            3. P - encoding parameters, an octet string that may be empty

        Output:
            1. M -  message, an octet string of length at most k - 2 - 2hLen, where hLen is the length in octets
            of the hash function output for EME-OAEP
        Errors:
            1. Decryption error
    """
    # steps:
    k = prv_key._size_in_bytes()
    # 1. If the length of the ciphertext C is not k octets, output decryption error and stop.
    cLen = len(C)
    if cLen != k:
        raise ValueError("Decryption error, different number of octets")
    # 2. Convert the ciphertext C to an integer ciphertext representative c
    c = os2ip(C)
    # 3. Apply the RSADP decryption primitive  to the private key K and the ciphertext
    # representative c to produce an integer message representative m:
    m = rsadp(prv_key=prv_key, c=c)
    # 4. Convert the message representative m to an encoded message EM of length k − 1 octets
    EM =i2osp(m, k - 1)
    # 5. Apply the EME-OAEP decoding operation to the encoded message EM and
    # the encoding parameters P to recover a message M:
    M = oaep_decode(EM, P)
    # 6. Output the message M
    return M.decode('utf-8')


def oaep_decode(EM, label = b'', hash=sha256, mask=mask1) -> bytes:
        """ EME-OAEP-Decode(EM, P)
        Options: 
            1. Hash - hash function (hLen denotes the length in octets of the hash function output)
            2. mask - mask generation function
        Input: 
            1. EM - encoded message, an octet string of length at least 2hLen + 1 (emLen denotes the length in
            octets of EM)
            2. P - Encoding parameters, an octet string
        Output:
            1. M - recovered message, an octet string of length at most emLen - 1 - 2hLen

        Errors:
            1. Decoding error
        """
        # steps:
        # 1. If the length of P is greater than the input limitation then output ‘‘decoding error’’ and stop.
        # SHA1: 2^61 - 1
        if len(label) > (pow(2, 61) - 1):
            raise ValueError("Decoding error, parameter too large")
        # 2. If emLen < 2hLen + 1, output ‘‘decoding error’’ and stop.
        emLen = len(EM) 
        lHash = hash(label)
        hLen = len(lHash)
        
        # if emLen < ((2*hLen) + 1):
        #     raise ValueError("Decoding error, parameter too large")
        # 3. Let maskedSeed be the first hLen octets of EM and let maskedBd be the remaining emLen-hLen octets.
        maskedSeed = EM[0:hLen]
        maskedBd = EM[hLen+1:-1]
        # 4.  Let seedMask = mask(maskedBd, hLen).
        seedMask =  mask(maskedBd, hLen)
        # 5. Let seed = maskedSeed xor seedMask.
        seed = xor(maskedSeed,seedMask) 
        # 6. Let bdMask = mask(seed , emLen - hLen)
        bdMask = mask(seed, emLen - hLen)
        # 7. Let DB = maskedBd xor bdMask.
        DB = xor(maskedBd, bdMask)
        # 8. Let pHash = Hash(P), an octet string of length hLen.
        index = DB.find(b'\x01') + 1
        if lHash not in DB:
            raise ValueError("Hash not in DB")

        # 9. Separate DB into an octet string pHash’ || PS || 01 || M
        # 10. return m
        return DB[index:]

def rsadp(c, prv_key: RSAKeys) -> int:
    """ 
    Rsa decryption process
    Private Key = (d, n)
    """

    d, n = prv_key.get_key()
    m = pow(c, d, n)
    if m > n - 1 or m < 0:
        raise ValueError("Ciphertext representative out of range")
    return m

