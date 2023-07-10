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
---
---

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
---
---

É um algoritmo de criptografia assimétrica muito utilizado para proteger a comunicação e garantir a segurança das informações. Ele envolve o uso de duas chaves: uma chave pública para criptografar os dados e uma chave privada correspondente para descriptografá-los.

Na presente implementacao a chave publica e privada sao compostas por (e, n) e (d, n), respectivamente!

A segurança do algoritmo RSA é baseada no fato de que é computacionalmente difícil fatorar números primos grandes. A dificuldade de fatorização dificulta a obtenção da chave privada a partir da chave pública, fazendo com que o algoritmo seja resistente a ataques de força bruta, por exemplo.

 - **GERAÇAO DE  "e"**
    - A partir desse momento, já temos p, q, n e phi, onde:
        - p = primo aleatório gerado no item anterior;
        - q = primo aleatório gerado no item anterior;
        - n = p*q [Monudlo "n"];
        - phi = (p-1)*(q-1) [valor de Euler];
    - O método **"gerarE"** é responsável por gerar esse valor no algoritmo RSA. Esse processo leva em consideração alguns critérios para garantir a correta escolha de e:
        - Ele precisa estar no intervalo 2**(self.size - 1) a 2**(self.size). Isso garante que e tenha o tamanho desejado em bits.
        - Ele precisa ser coprimo tanto com o valor de Euler (phi) quanto com o produto dos números primos (n) utilizados na geração das chaves. Essa condição é fundamental para a segurança do algoritmo, pois garante que o cálculo do inverso multiplicativo modular seja possível e que a chave privada possa ser usada para descriptografar corretamente.
        -  ```
            def gerarE(self):
                while True:
                    e = random.randrange(2**(self.size - 1), 2**(self.size))
                    if utils.coprimo(e, self.phi) and utils.coprimo(e, self.n):
                        return e
           ```
    
 - **GERAÇAO DE  "d"**
    - Agora que temos o valor de "e", conseguimos gerar nosso valor "d" para compor nossa chave privada através do método **"gerarD"** .
    - O método **"gerarD"** pode ser usado de 2 maneiras na geracao de "e". Uma com um algoritmo de euclides estendido (def euclidesInversoMultiplicativo()) construido no arquivo "RSA.utils" e outra semo uso e euclides, mas que também usa o conceito de inverso multiplicativo.
    - O uso do Euclides estendido permite calcular o inverso multiplicativo modular em uma ampla variedade de situações, inclusive quando o maior divisor comum entre "e" e self.phi não é igual a 1. Essa flexibilidade pode ser benéfica em determinados cenários de segurança.
    -  ```
            def gerarD(self, e):
                # d = utils.euclidesInversoMultiplicativo(e, self.phi)
                d = pow(e, -1, self.phi) # = onde d é inverso multiplicativo de "e" módulo self.phi
                return d
       ```


 - **EXPORTAÇAO DAS CHAVES**
     - As chaves (pub e priv) sao exportadas como string em base64 pela fucao "exportarChave" da nossa classe RSAKeys


## OAEP (Optimal Asymmetric Encryption Padding)
---
---
Para realizar a cifração/decifração assimétrica RSA, usamos o método OAEP. Este que é um esquema de preenchimento para criptografia assimétrica, frequentemente usado em conjunto com o RSA. Seu objetivo é melhorar a segurança e a aleatoriedade dos dados criptografados. O OAEP adiciona um preenchimento aleatório aos dados antes de criptografá-los, tornando mais difícil para um adversário realizar ataques de texto simples ou outros ataques criptográficos.

Obs.: Tanto a cifracao quanto a decifracao foram realizadas com o auxilio da primeira referencia desse documento (EME-OAEP e RSAES-OAEP). Todo processo desta etapda foi comentado nos scripts do arquivo "RSA.oaep" para melhor compreensao.


## Assinatura & Verificacao

- Para assinar, pegamos uma mensagem (a ser assinada) do usuário a chave privada para gerar a assinatura em base 64:

 ```
    def assinar(mensagem, chave: RSAKeys):
        mensagem = mensagem.encode('ascii')
        hash = int.from_bytes(sha512(mensagem).digest(), byteorder='big')
        assinatura = pow(hash, chave.chavePriv, chave.n)
        assinatura = utils.toBase64(str(assinatura)) # Assinatura para base 64
        return assinatura
 ```

- Já para verificar a assinatura, pegamos uma mensagem do usuario, a assinatura gerada no passo anterior e a chave publica de quem assinou. Com isso verificamos se a assinatura e a mensagem coincide, atraves do hash (512) da mensagem digitada e o hash da assinatura, que é um pow(assinatura, chavePub e n):

 ```
    def verificar(mensagem, assinatura, chave:RSAKeys) -> bool:
        mensagem = mensagem.encode('ascii')
        hash = int.from_bytes(sha512(mensagem).digest(), byteorder='big')
        assinatura = int(utils.fromBase64(assinatura))
        hashDaAssinatura = pow(assinatura, chave.chavePub, chave.n)
        return hash == hashDaAssinatura
 ```