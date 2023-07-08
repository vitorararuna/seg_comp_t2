import random
import RSA.utils as utils


class RSAKeys:
    def __init__(self, size=1024, primo1=0, primo2=0, chavePub= 0, chavePriv = 0, modulus=0):
        self.size = size # Tamanho do nmr primo em bits:

        self._chavePub = 0
        self._chavePriv = 0

        # Criacao de novas chaves
        if chavePub == 0 and chavePriv == 0:
            # 1) Definicao de primos
            self.primo1 = utils.gerarPrimo(self.size)
            self.primo2 = utils.gerarPrimo(self.size)

            print('primo 1:', self.primo1)
            print('primo 2:', self.primo2)

            # 2) Calculando Modulo de N
            self._moduloN = self.primo1 * self.primo2
            # 3) Calculando valor de Euler (phi(n))
            self.phi = (self.primo1 - 1) * (self.primo2-1)
            # 4) Escolhendo inteiro tal que 2 < chavePub < phi(n) e mdc(chavePub, phi(n)) = 1; isto é, chavePub e phi(n) são primos primos
            self._chavePub = self.gerarChavePub()
            # 5) Determine chavePriv como chavePriv ≡ e−1 (mod phi(n)); isto é, chavePriv é o inverso multiplicativo modular de chavePub módulo phi(n)
            self._chavePriv = self.gerarChavePriv(self._chavePub)
            
        # chave privada :
        elif chavePub == 0 and ((chavePriv and modulus) != 0):
            self._chavePriv = chavePriv
            self._moduloN = modulus
        # chave publica:
        elif chavePriv == 0 and ((chavePub and modulus) !=0):
            self._chavePub = chavePub
            self._moduloN = modulus


# ------
    @property
    def moduloN(self):
        return int(self._moduloN)
    @property
    def chavePub(self):
        return int(self._chavePub)
    @property
    def chavePriv(self):
        return int(self._chavePriv)
    @property 
    def criarChavePublica(self):
        print("-> Criando chave publica...")
        if self._chavePub != 0:
            return RSAKeys(chavePub=self._chavePub, modulus=self._moduloN, chavePriv=0)
        else:
            raise ValueError("Esta é uma chave privada, você não pode obter a chave pública.")  
    @property 
    def criarChavePrivada(self):
        print("-> Criando chave privada...")
        if self._chavePriv != 0:
            return RSAKeys(chavePriv=self._chavePriv, modulus=self._moduloN, primo1=self.primo1, primo2=self.primo2, chavePub=0) 
        else:
            raise ValueError("Esta é uma chave pública, você não pode obter a chave privada.")  
 

# ------

     # Verdadeiro se a chave atual for pública
    def verificarPublica(self):
        if self._chavePriv == 0:
            return True
        return False
    
    # Verdadeiro se a chave atual for privada
    def verificarPrivada(self):
        if self._chavePub == 0:
            return True
        return False  

    # Retorna um tupla da chave (chavePub, moduloN) para a pública e (chavePriv, moduloN) para a privada
    def pegarChave(self):
        if self.verificarPublica():
            return (self.chavePub, self.moduloN)
        elif self.verificarPrivada():
            return (self.chavePriv, self.moduloN)
        else:
            return ((self.chavePub, self.moduloN), (self.chavePriv, self.moduloN))
    
   
# ------ Calculando novas chaves:



    # Gera um valor para ChavePub que seja:
            # 2 < ChavePub < phi(n) && ( n e phi(n) coprimos )
    def gerarChavePub(self):
       
        while True:
            chavePub = random.randrange(2**(self.size - 1), 2**(self.size))
            if utils.coprimo(chavePub, self.phi) and utils.coprimo(chavePub, self.moduloN):
                return chavePub
        
    # Gera um valor para ChavePriv que seja: 
            # ChavePriv * chavePub (mod phi(n))== 1 OR ChavePriv = inverso modulas da chavePub and phi(n)
    def gerarChavePriv(self, chavePub):
        return utils.inversoMultiplicativo(chavePub, self.phi)

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
        return self._moduloN.bit_length()
    def tamanhoEmBytes(self):
        return (self._moduloN.bit_length()) // 8 




# ------------
def importarChave(path) -> RSAKeys:
    with open(path, 'r') as f:
        extern_key = f.read()
    
    tipoDaChave = tipoChave(extern_key)
    tokens = utils.decodingBASE64(extern_key) 
    key = utils.totuple(tokens)
    if tipoDaChave == "CHAVE PUBLICA":
        chavePub, modulus = key
        return RSAKeys(chavePub=chavePub, modulus=modulus)
    else:
        chavePriv, modulus = key
        return RSAKeys(chavePriv=chavePriv, modulus=modulus)
    
def tipoChave(extern_key):
    if "CHAVE PUBLICA" in extern_key:
        return "CHAVE PUBLICA"
    else:
        return "CHAVE PRIVADA"
    