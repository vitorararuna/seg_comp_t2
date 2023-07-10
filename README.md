# Segurança Computacional - Unb 2023 - Trabalho 2

## Alunos

- Vitor Araruna - 202060980
- Bruno Xavier

## Requisitos

O segundo trabalho da disciplina de Segurança Computacional consiste em implementar:

    1. Cifração e decifração AES, chave 128 bits
    2. Geração de chaves com teste de primalidade (Miller-Rabin)
    3. Cifração/decifração assimétrica RSA usando OAEP.
    4. Assinatura RSA & verificacao 

# Algoritmos

## Geração de primos e método Miller-Rabin

A função Miller-Rabin desempenha um papel importante na geração de números primos, pois oferece um método probabilístico eficiente para testar a primalidade de um número. 

Encontrar números primos grandes é essencial na criptografia, pois eles são usados como componentes fundamentais em algoritmos criptográficos, como o RSA que será usado a partir desses primos. 

Como a fatoração de números grandes/compostos é um problema computacionalmente desafiador e consome consideráveis recursos de computação, Em vez de realizar a fatoração direta do número gerado, o teste de primalidade de Miller-Rabin é empregado para verificar se o número é provavelmente primo.

Este algoritmo é chamado `k` vezes, onde quanto maior o `k` maior é a probabilidade de sucesso. No algoritmo em questao foi usado um valor de 40 iteracoes, quantidade considerada suficiente para fornecer uma alta probabilidade de detecção de números compostos.

```

# Gerando primo aleatório de tamanho "bits":
def gerarPrimo(bits):
        return next(filter(millerRabin, iter(rand_odd(bits), 0)))

# valor aleatório de tamanho entre (2 ** (bits - 2), 2 ** (bits - 1)) * 2 - 1 ---2**(bits-1), 2**bits-1)
def rand_odd(bits=1024):
    return random.randrange(2 ** (bits - 2), 2 ** (bits - 1)) * 2 - 1

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

# ONDE: 

d = primo tal que : d * 2ˆr = n - 1, tal que r >= 1
a = aleatório entre 2 e n-1
x = a^d (mod n)
se x = 1 ou x = n-1, --número primo--
se não:
    x = xˆx (mod n)
    se x = 1, --número não primo--
    se x = n-1, --número é primo--


```



## RSA (Rivest, Shamir e Adleman)

É um algoritmo de criptografia assimétrica muito utilizado para proteger a comunicação e garantir a segurança das informações. Ele envolve o uso de duas chaves: uma chave pública para criptografar os dados e uma chave privada correspondente para descriptografá-los.

Além disso, é baseado em duas operações matemáticas fundamentais: a multiplicação de números primos grandes e o cálculo de exponenciação modular.

A segurança do algoritmo RSA é baseada no fato de que é computacionalmente difícil fatorar números primos grandes. A dificuldade de fatorização dificulta a obtenção da chave privada a partir da chave pública, fazendo com que o algoritmo seja resistente a ataques de força bruta, por exemplo.

    p = primo aleatório gerado no item anterior
    q = primo aleatório gerado no item anterior
    phi = função de Euler
    
