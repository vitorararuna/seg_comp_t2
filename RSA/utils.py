import random
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
def euclidesEstendido(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = euclidesEstendido(b % a, a)
        return (g, x - (b // a) * y, y)
        
# Calcula inverso multipicativo (usando pow(a,b,c)) para encontrar chavePriv
def inversoMultiplicativo(a, m):
    g, x, y = euclidesEstendido(a, m)
    if g != 1:
        return -1
    else:
        return x % m




############################### - PRIMALIDADE -  ###############################

# Gerando primo aleatório de tamanho "bits":
def gerarPrimo(bits):
   
    while True:
        primoCandidato = obterPrimo(listaDePrimos, bits=bits)
        if testeMillerRabin(primoCandidato, k=20):
            return primoCandidato

# Retorna uma lista com primos menores ou iguais a "numero".
# Também é dado que len(lista) é um número pequeno.
def pequenaListaDePrimos(number):
    
    # Lista de primos até o número de entrada
    listaDePrimos = []       

    # Criando um array booleano "primo[0..n]" com todas as entradas como true:
    primo = [True for i in range(number+1)]
    # primeiro primo
    p = 2


    # algoritmo:
    while p * p <= number:
        if primo[p] == True:
        # Atualizando todos os múltiplos de p
            for i in range(p * p, number+1, p):
                primo[i] = False
        p+=1
       
       
    for i in range(number):
        if primo[i] == True:
            listaDePrimos.append(i)        
    print("lista De Primos de tam : ", len(listaDePrimos))
    return listaDePrimos[2:]

listaDePrimos = pequenaListaDePrimos(1000)

# nmr aleatório do tamanho de tamanho 2^{bits-1} a 2^bits ":
def numeroAleatorio(bits):
    return(random.randrange(2**(bits-1), 2**bits-1))

# -----<<<< Processo para obter Primo  >>>>-----
# - Divisão por primos pré-gerados:
            # O número que estamos testando é dividido pelos primos pré-gerados.
# -Verificação de divisibilidade:
            # Verificamos se o número é divisível por algum dos primos pré-gerados.
# -Geração de um novo primo:
            # Se o número for divisível por algum dos primos pré-gerados, escolhemos um novo número para testar.
# -Repetição do processo:
            # Repetimos os passos de divisão e verificação de divisibilidade até encontrar um número que não seja divisível por nenhum dos primos pré-gerados.
def obterPrimo(listaDePrimos, bits=1024):
   
    # primos até 1000
    while True:
        primoCandidato = numeroAleatorio(bits=bits) 
        for divisor in listaDePrimos: 
            if primoCandidato % divisor == 0 and divisor  ** 2 <= primoCandidato:
                break
                # Entao se nenhum divisor for encontrado, retorna o valor
            else:
                return primoCandidato

# Teste de Miller Rabin para k iterações"
def testeMillerRabin(n, k=10):
    for i in range(k):
        a = random.randrange(2, n - 1)
        if not iteracaoMillerRabin(n, a):
            return False
    return True

# iteração do teste Miller Rabin"
def iteracaoMillerRabin(n, a):
    exp = n - 1
    while not exp & 1:
        exp >>= 1
            
    if pow(a, exp, n) == 1:
        return True
            
    while exp < n - 1:
        if pow(a, exp, n) == n - 1:
            return True
        exp <<= 1
            
    return False
    



############################### - Auxiliares -  ###############################


# --
# Encode string para base64
def toBase64(string):
    string_bytes = string.encode("ascii")
    base64_bytes = base64.b64encode(string_bytes)
    base64_string = base64_bytes.decode("ascii")
    return base64_string

# Decode -string base64- para -string normal-
def fromBase64(string):
    base64_bytes = string.encode("ascii")
    string_bytes = base64.b64decode(base64_bytes)
    string = string_bytes.decode("ascii")
    return string
# --



# --
# Geracao de string com base64 para exportacao da chave
def encodeBASE64(data, key_type):
    out = "-----BEGIN " + key_type + "-----\n "
    out += toBase64(str(data))+ "\n"
    out += "-----END "+ key_type + "-----" 
    return out

# Par de strings para exportacao da chave
def decodingBASE64(data, key_type):
    data = data.split("\n")
    data = data[1:-1][0]
    return fromBase64(data)
# --


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


# Texto para tupla "(1,2)" -> (1,2)
def totuple(text):
    text = text[1:-1]
    text = text.split(",")
    return (int(text[0]), int(text[1]))


