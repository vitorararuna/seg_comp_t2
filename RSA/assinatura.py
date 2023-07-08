from RSA.rsa import RSAKeys
from hashlib import sha512
import RSA.utils as utils
# https://cryptobook.nakov.com/digital-assinaturas/rsa-sign-verify-examples

# Devolve uma assinatura da msg com a chave privada
def assinar(mensagem, chave: RSAKeys):
    mensagem = mensagem.encode('ascii')
    hash = int.from_bytes(sha512(mensagem).digest(), byteorder='big')
    assinatura = pow(hash, chave.chavePriv, chave.moduloN)
    # Assinatura para base 64:
    assinatura = utils.toBase64(str(assinatura))
    return assinatura

# Verificacao se assinatura e mensagem sao iguais segundo a chave publica 
def verificar(mensagem, assinatura, chave:RSAKeys) -> bool:
    mensagem = mensagem.encode('ascii')
    assinatura = int(utils.fromBase64(assinatura))
    hash = int.from_bytes(sha512(mensagem).digest(), byteorder='big')
    hashDaAssinatura = pow(assinatura, chave.chavePub, chave.moduloN)
    return hash == hashDaAssinatura
