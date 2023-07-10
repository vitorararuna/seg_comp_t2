import random
import RSA.utils as utils


class RSAKeys:
    def __init__(self, size=1024, primo1=0, primo2=0, e= 0, d = 0, modulus=0):
        self.size = size # Tamanho do nmr primo em bits:

        self._e = 0
        self._d = 0

        # Criacao de novas chaves
        if e == 0 and d == 0:
            # 1) Definicao de primos
            self.primo1 = utils.gerarPrimo()
            self.primo2 = utils.gerarPrimo()

            print('primo 1:', self.primo1)
            print('primo 2:', self.primo2)

            # 2) Calculando Modulo de N
            self._n = self.primo1 * self.primo2
            # 3) Calculando valor de Euler (phi(n))
            self.phi = (self.primo1 - 1) * (self.primo2-1)
            # 4) Escolhendo inteiro tal que 2 < e < phi(n) e mdc(e, phi(n)) = 1; isto é, e e phi(n) são primos primos
            self._e = self.gerarE()
            # 5) Determine d como d ≡ e−1 (mod phi(n)); isto é, d é o inverso multiplicativo modular de e módulo phi(n)
            self._d = self.gerarD(self._e)
            
        # chave privada :
        elif e == 0 and ((d and modulus) != 0):
            self._d = d
            self._n = modulus
        # chave publica:
        elif d == 0 and ((e and modulus) !=0):
            self._e = e
            self._n = modulus


# ------
    @property
    def n(self):
        return int(self._n)
    @property
    def e(self):
        return int(self._e)
    @property
    def d(self):
        return int(self._d)
    @property 
    def criarChavePublica(self):
        print("-> Criando chave publica...")
        if self._e != 0:
            return RSAKeys(e=self._e, modulus=self._n, d=0)
        else:
            raise ValueError("Esta é uma chave privada, você não pode obter a chave pública.")  
    @property 
    def criarChavePrivada(self):
        print("-> Criando chave privada...")
        if self._d != 0:
            return RSAKeys(d=self._d, modulus=self._n, primo1=self.primo1, primo2=self.primo2, e=0) 
        else:
            raise ValueError("Esta é uma chave pública, você não pode obter a chave privada.")  
 

# ------

     # Verdadeiro se a chave atual for pública
    def verificarPublica(self):
        if self._d == 0:
            return True
        return False
    
    # Verdadeiro se a chave atual for privada
    def verificarPrivada(self):
        if self._e == 0:
            return True
        return False  

    # Retorna um tupla da chave (e, n) para a pública e (d, n) para a privada
    def pegarChave(self):
        if self.verificarPublica():
            return (self.e, self.n)
        elif self.verificarPrivada():
            return (self.d, self.n)
        else: # MAYBE DESNCESS
            return ((self.e, self.n), (self.d, self.n))
    
   
# ------ Calculando novas chaves:



    # Gera um valor para e que seja:
            # 2 < e < phi(n) && ( n e phi(n) coprimos de e)
    def gerarE(self):
       
        while True:
            e = random.randrange(2**(self.size - 1), 2**(self.size))
            if utils.coprimo(e, self.phi) and utils.coprimo(e, self.n):
                return e
        
    # Podemos usar Euclides Estendido Ou Nao, basta escolher qual "d" retornar
    def gerarD(self, e):
        # d = utils.euclidesInversoMultiplicativo(e, self.phi)
        d = pow(e, -1, self.phi) # = inverso multiplicativo de "e" módulo self.phi
        return d

    # Exportando chave cifrada para base64 (string) => (e,n)/(d,n) 
    def exportarChave(self):
        if not self.verificarPublica():            
            tipoDaChave = 'CHAVE PRIVADA'
            str = utils.encodeBASE64(self.pegarChave(), tipoDaChave)
        else:
            tipoDaChave = "CHAVE PUBLICA"
            str = utils.encodeBASE64(self.pegarChave(), tipoDaChave)
            
        return utils.tobytes(str).decode('ascii')

# ------ Auxiliares

    def cifrar(self, text):
        return pow(text, self.c, self.n)
    def decifrar(self, cipher):
        if cipher > self.n:
            raise ValueError("Cipher too large")
        return pow(cipher, self.d, self.n)
   

    def tamanhoEmBits(self):
        return self._n.bit_length()
    def tamanhoEmBytes(self):
        return (self._n.bit_length()) // 8 




# ------------
def importarChave(path) -> RSAKeys:
    with open(path, 'r') as f:
        chaveExterna = f.read()
    
    tipoDaChave = tipoChave(chaveExterna)
    tokens = utils.decodingBASE64(chaveExterna) 
    key = utils.totuple(tokens)
    if tipoDaChave == "CHAVE PUBLICA":
        e, modulus = key
        return RSAKeys(e=e, modulus=modulus)
    else:
        d, modulus = key
        return RSAKeys(d=d, modulus=modulus)
    
def tipoChave(chaveExterna):
    if "CHAVE PUBLICA" in chaveExterna:
        return "CHAVE PUBLICA"
    else:
        return "CHAVE PRIVADA"
   