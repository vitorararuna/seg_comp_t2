import random

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
# Também é dado que n ( len(lista) ) é um número pequeno.
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

    return listaDePrimos[2:]

listaDePrimos = pequenaListaDePrimos(1000)

# nmr aleatório do tamanho de tamanho 2^{bits-1} a 2^bits ":
def numeroAleatorio(bits):
    return(random.randrange(2**(bits-1), 2**bits-1))

# -----<<<< Processo para obter Primos  >>>>-----
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
    
