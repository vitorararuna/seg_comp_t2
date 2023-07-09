// Fonte:    http://csrc.nist.gov/archive/aes/rijndael/wsdindex.html

#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <cstddef>
#include <vector>


/* inicia valores iniciais e executa uma vez antes de usar o AES */
void aes_init_keygen_tables( void );

class AES128{

public:
    /* Cria instancia e expande a chave para criptografia/descriptografia */ 
    explicit AES128(const uint8_t *key );

    /* executa criptografia/descriptografia de qualquer tamanho */
    std::vector<uint8_t> encrypt(std::vector<uint8_t>& in);
    std::vector<uint8_t> decrypt(std::vector<uint8_t>& in);
    
    /* executa criptografia/descriptografia em blocos*/
    void encrypt_block(const uint8_t input[16], uint8_t output[16]);
    void decrypt_block(const uint8_t input[16], uint8_t output[16]);

private:
    int rounds = 10;    /* Contagem de Rodadas */  
    uint32_t erk[64];   /* Encryption Round Key */
    uint32_t drk[64];   /* Decryption Round Key */

};


#endif // AES_H

