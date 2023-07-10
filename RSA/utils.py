import random, hashlib, math
import base64, random

############################### - MATEMÁTICA MODULAR -  ###############################

# Máximo divisor comum
def mdc(a, b):
    while a != 0:
      a, b = b % a, a
    return b

# Verifica se x é coprimo de y
def coprimo(x, y):
        return mdc(x, y) == 1

# Algoritmo euclidiano estendido
def euclidesEstendido(e, phi):
    if e == 0:
        return (phi, 0, 1)
    else:
        g, y, x = euclidesEstendido(phi % e, e)
        return (g, x - (phi // e) * y, y)
        
# Calcula inverso multipicativo para encontrar e
def euclidesInversoMultiplicativo(e, phi):
    g, x, y = euclidesEstendido(e, phi)
    if g != 1:
        return -1
    else:
        return x % phi




############################### - PRIMALIDADE -  ###############################


def millerRabin(n):
    d, s = n - 1, 0
    while d % 2 == 0:
        s += 1
        d >>= 1 # d é dividido por 2 utilizando o operador de deslocamento bit a direita (d >>= 1).
    for _ in range(40):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        return False
    return True

# valor aleatório de tamanho entre (2 ** (bits - 2), 2 ** (bits - 1)) * 2 - 1 ---2**(bits-1), 2**bits-1)
def rand_odd(bits=1024):
    return random.randrange(2 ** (bits - 2), 2 ** (bits - 1)) * 2 - 1

# Gerando primo aleatório de tamanho "bits":
def gerarPrimo():
        return next(filter(millerRabin, iter(rand_odd, 0)))

############################### - Auxiliares -  ###############################

# Encode string para base64
def toBase64(string):
    string_bytes = string.encode("ascii")
    base64_bytes = base64.b64encode(string_bytes)
    base64_string = base64_bytes.decode("ascii")
    return base64_string
# --


# Decode -string base64- para -string normal-
def fromBase64(string):
    base64_bytes = string.encode("ascii")
    string_bytes = base64.b64decode(base64_bytes)
    string = string_bytes.decode("ascii")
    return string
# --


# Geracao de string com base64 para exportacao da chave
def encodeBASE64(data, key_type):
    out = "-----BEGIN " + key_type + "-----\n "
    out += toBase64(str(data))+ "\n"
    out += "-----END "+ key_type + "-----" 
    return out
# --


# Par de strings para exportacao da chave
def decodingBASE64(data):
    data = data.split("\n")
    data = data[1:-1][0]
    return fromBase64(data)
# --


# Data types para bytes
def tobytes(s, encoding="latin-1"):
        if isinstance(s, bytes):
            return s
        elif isinstance(s, bytearray):
            return bytes(s)
        elif isinstance(s,str):
            return s.encode(encoding)
        elif isinstance(s, memoryview):
            return s.tobytes()
        else:
            return bytes([s])
# --


# Byte-by-byte XOR of two byte arrays
def xor(x: bytes, y: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(x, y))
# --



# Texto para tupla "(1,2)" -> (1,2)
def totuple(text):
    text = text[1:-1]
    text = text.split(",")
    return (int(text[0]), int(text[1]))
# --




############################### - OAEP PRIMITIVE-  ###############################


# ( string em octeto em string) -> inteiro positivo 
def octetoParaInteiro(X):
    return int.from_bytes(X, byteorder='big')

# ( int>0 && comprimento "l" da string ) -> string em octeto de comprimento l
def inteiroParaOcteto(x: int, l: int):
    return x.to_bytes(l, byteorder='big')
   

# Hasher para nossa funcao de assinatura (encode e decode) OAEP 
def sha256(m):
    hasher = hashlib.sha1()
    hasher.update(m)
    return hasher.digest()




# A funcao mask gera uma Máscara baseada em uma função hash.
#  Entradas 1. Z - seed a partir da qual a máscara é gerada, uma string de octeto
#           2. emLen - comprimento pretendido em octetos da máscara, no máximo 2^32(hLen)
#  Saída:
#      1. máscara - uma string de octetos de comprimento l --- ou uma "máscara muito longa"

def mask(seed, emLen, hash=hashlib.sha256):

    # 1  Se emLen > 2^{32}*hLen, máscara de saída muito longa
    hLen = hash().digest_size
    if emLen > pow(2,32) * hLen:
        raise ValueError("máscara muito longa!")


    # 2. string de octetos vazia
    T = b""


    # 3. Para i = 0 in (emLen/hLen), faça
         # 3.1 Converte i em uma string de octeto C de comprimento 4 com o primitivo I2OSP:
         # C = I2OSP(i, 4).
         # 3.2 Concatena o hash da semente Z e C para a string de octeto T:
         # T = T + Hash(Z + C)
    for i in range(math.ceil(emLen / hLen)):
        c = inteiroParaOcteto (i, 4)
        hash().update(seed + c)
        T = T + hash().digest()
    assert(len(T) >= emLen)
    
    
    #4. Retorna l octetos principais de T como a máscara de string de octetos.
    return T[:emLen]
