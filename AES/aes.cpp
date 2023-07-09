#include "aes.h"

static uint8_t FSb[256];    // Forward substitution box (FSb)
static uint32_t FT0[256];   // Forward key schedule assembly tables
static uint32_t FT1[256];
static uint32_t FT2[256];
static uint32_t FT3[256];

static uint8_t RSb[256];    // Reverse substitution box (RSb)
static uint32_t RT0[256];   // Reverse key schedule assembly tables
static uint32_t RT1[256];
static uint32_t RT2[256];
static uint32_t RT3[256];

static uint32_t RCON[10];   // AES round constants

/* 
 * Platform Endianness Neutralizing Load and Store Macro definitions
 * AES wants platform-neutral Little Endian (LE) byte ordering
 */
#define GET_UINT32_LE(n,b,i) {                  \
    (n) = ( (uint32_t) (b)[(i)    ]       )     \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )     \
        | ( (uint32_t) (b)[(i) + 2] << 16 )     \
        | ( (uint32_t) (b)[(i) + 3] << 24 ); }

#define PUT_UINT32_LE(n,b,i) {                  \
    (b)[(i)    ] = (uint8_t) ( (n)       );       \
    (b)[(i) + 1] = (uint8_t) ( (n) >>  8 );       \
    (b)[(i) + 2] = (uint8_t) ( (n) >> 16 );       \
    (b)[(i) + 3] = (uint8_t) ( (n) >> 24 ); }

/*
 *  AES forward and reverse encryption round processing macros
 */
#define AES_FROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    X0 = *RK++ ^ FT0[ ( Y0       ) & 0xFF ] ^   \
                 FT1[ ( Y1 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y2 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y3 >> 24 ) & 0xFF ];    \
                                                \
    X1 = *RK++ ^ FT0[ ( Y1       ) & 0xFF ] ^   \
                 FT1[ ( Y2 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y3 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y0 >> 24 ) & 0xFF ];    \
                                                \
    X2 = *RK++ ^ FT0[ ( Y2       ) & 0xFF ] ^   \
                 FT1[ ( Y3 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y0 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y1 >> 24 ) & 0xFF ];    \
                                                \
    X3 = *RK++ ^ FT0[ ( Y3       ) & 0xFF ] ^   \
                 FT1[ ( Y0 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y1 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y2 >> 24 ) & 0xFF ];    \
}

#define AES_RROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    X0 = *RK++ ^ RT0[ ( Y0       ) & 0xFF ] ^   \
                 RT1[ ( Y3 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y2 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y1 >> 24 ) & 0xFF ];    \
                                                \
    X1 = *RK++ ^ RT0[ ( Y1       ) & 0xFF ] ^   \
                 RT1[ ( Y0 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y3 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y2 >> 24 ) & 0xFF ];    \
                                                \
    X2 = *RK++ ^ RT0[ ( Y2       ) & 0xFF ] ^   \
                 RT1[ ( Y1 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y0 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y3 >> 24 ) & 0xFF ];    \
                                                \
    X3 = *RK++ ^ RT0[ ( Y3       ) & 0xFF ] ^   \
                 RT1[ ( Y2 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y1 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y0 >> 24 ) & 0xFF ];    \
}

#define ROTL8(x) ( ( x << 8 ) & 0xFFFFFFFF ) | ( x >> 24 )
#define XTIME(x) ( ( x << 1 ) ^ ( ( x & 0x80 ) ? 0x1B : 0x00 ) )
#define MUL(x,y) ( ( x && y ) ? pow[(log[x]+log[y]) % 255] : 0 )
#define MIX(x,y) { y = ( (y << 1) | (y >> 7) ) & 0xFF; x ^= y; }


static int aes_tables_inited = 0;

void aes_init_keygen_tables( void )
{
    /* verifica se funcao ja foi chamada */
    if (aes_tables_inited) return;

    int i, x, y, z;
    int pow[256];
    int log[256];

    // preenche as tabelas 'pow' e 'log' com GF(2^8)
    for( i = 0, x = 1; i < 256; i++ )   {
        pow[i] = x;
        log[x] = i;
        x = ( x ^ XTIME( x ) ) & 0xFF;
    }
    // computa as constantes
    for( i = 0, x = 1; i < 10; i++ )    {
        RCON[i] = (uint32_t) x;
        x = XTIME( x ) & 0xFF;
    }
    // preenche as tabelas
    FSb[0x00] = 0x63;
    RSb[0x63] = 0x00;

    for( i = 1; i < 256; i++ )          {
        x = y = pow[255 - log[i]];
        MIX(x,y);
        MIX(x,y);
        MIX(x,y);
        MIX(x,y); 
        FSb[i] = (uint8_t) ( x ^= 0x63 );
        RSb[x] = (uint8_t) i;
    }
    // gerar as tabelas
    for( i = 0; i < 256; i++ )          {
        x = FSb[i];
        y = XTIME( x ) & 0xFF;
        z =  ( y ^ x ) & 0xFF;

        FT0[i] = ( (uint32_t) y       ) ^ ( (uint32_t) x <<  8 ) ^
                 ( (uint32_t) x << 16 ) ^ ( (uint32_t) z << 24 );

        FT1[i] = ROTL8( FT0[i] );
        FT2[i] = ROTL8( FT1[i] );
        FT3[i] = ROTL8( FT2[i] );

        x = RSb[i];

        RT0[i] = ( (uint32_t) MUL( 0x0E, x )       ) ^
                 ( (uint32_t) MUL( 0x09, x ) <<  8 ) ^
                 ( (uint32_t) MUL( 0x0D, x ) << 16 ) ^
                 ( (uint32_t) MUL( 0x0B, x ) << 24 );

        RT1[i] = ROTL8( RT0[i] );
        RT2[i] = ROTL8( RT1[i] );
        RT3[i] = ROTL8( RT2[i] );
    }
    aes_tables_inited = 1;  // flag
}

AES128::AES128(const uint8_t *key)
{
    int i, j;
    uint32_t *RK = this->erk;
    uint32_t *SK = this->drk;

    if (!aes_tables_inited)
        aes_init_keygen_tables();

    for( i = 0; i < 4; i++ ) {
        GET_UINT32_LE( RK[i], key, i << 2 );
    }

    for( i = 0; i < 10; i++, RK += 4 ) {
        RK[4]  = RK[0] ^ RCON[i] ^
        ( (uint32_t) FSb[ ( RK[3] >>  8 ) & 0xFF ]       ) ^
        ( (uint32_t) FSb[ ( RK[3] >> 16 ) & 0xFF ] <<  8 ) ^
        ( (uint32_t) FSb[ ( RK[3] >> 24 ) & 0xFF ] << 16 ) ^
        ( (uint32_t) FSb[ ( RK[3]       ) & 0xFF ] << 24 );

        RK[5]  = RK[1] ^ RK[4];
        RK[6]  = RK[2] ^ RK[5];
        RK[7]  = RK[3] ^ RK[6];
    }

    *SK++ = *RK++; *SK++ = *RK++; *SK++ = *RK++; *SK++ = *RK++; // copia 128bits
    for( i = this->rounds - 1, RK -= 8; i > 0; i--, RK -= 8 ) {
        for( j = 0; j < 4; j++, RK++ ) {
            *SK++ = RT0[ FSb[ ( *RK       ) & 0xFF ] ] ^
                    RT1[ FSb[ ( *RK >>  8 ) & 0xFF ] ] ^
                    RT2[ FSb[ ( *RK >> 16 ) & 0xFF ] ] ^
                    RT3[ FSb[ ( *RK >> 24 ) & 0xFF ] ];
        }
    }
    *SK++ = *RK++; *SK++ = *RK++; *SK++ = *RK++; *SK++ = *RK++; // copia 128bits
}

std::vector<uint8_t> AES128::decrypt(std::vector<uint8_t>& in)
{
    std::vector<uint8_t> out(in.size());

    for (unsigned int i = 0; i < out.size(); i += 16) {
        decrypt_block(in.data() + i, out.data() + i);
    }

    /* 
    Removendo padding do final da mensagem:
        msg - (0x00 + 0xFF...)
    */
   uint8_t * it = out.data() + out.size() - 1;
    if(*it == 0xFF){
        while(*it--);
        out.resize(it - out.data() + 1);
    }
    else if(*it == 0){
        out.resize(out.size() - 1);
    }
    return out;
}

std::vector<uint8_t> AES128::encrypt(std::vector<uint8_t>& in)
{
    size_t in_size = in.size();
    size_t pad_size = (16 - (in_size + 1)) % 16;
    size_t buff_size = pad_size + 1 + in_size;

    std::vector<uint8_t> out(buff_size, 0x00);

    /* 
    Adicionando padding ao final da mensagem:
        msg + 0x00 + 0xFF...
    */
    in.resize(buff_size, 255);
    in[in_size] = 0;

    uint8_t * in_p = in.data();
    uint8_t * out_p = out.data();

    for (unsigned int i = 0; i < out.size(); i += 16) {
        encrypt_block(in_p + i, out_p + i);
    }

    return out;
}

void AES128::decrypt_block( const uint8_t input[16], uint8_t output[16] )
{
    int i;
    uint32_t *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    RK = this->drk;

    GET_UINT32_LE( X0, input,  0 ); X0 ^= *RK++;    // carrega bloco de 128 bits
    GET_UINT32_LE( X1, input,  4 ); X1 ^= *RK++;
    GET_UINT32_LE( X2, input,  8 ); X2 ^= *RK++;
    GET_UINT32_LE( X3, input, 12 ); X3 ^= *RK++;

    for( i = 4; i > 0; i-- )
    {
        AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
        AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );
    }

    AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

    X0 = *RK++ ^ \
            ( (uint32_t) RSb[ ( Y0       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( Y3 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( Y2 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( Y1 >> 24 ) & 0xFF ] << 24 );

    X1 = *RK++ ^ \
            ( (uint32_t) RSb[ ( Y1       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( Y0 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( Y3 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( Y2 >> 24 ) & 0xFF ] << 24 );

    X2 = *RK++ ^ \
            ( (uint32_t) RSb[ ( Y2       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( Y1 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( Y0 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( Y3 >> 24 ) & 0xFF ] << 24 );

    X3 = *RK++ ^ \
            ( (uint32_t) RSb[ ( Y3       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( Y2 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( Y1 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( Y0 >> 24 ) & 0xFF ] << 24 );

    PUT_UINT32_LE( X0, output,  0 );    // descarrega bloco de 128 bits
    PUT_UINT32_LE( X1, output,  4 );
    PUT_UINT32_LE( X2, output,  8 );
    PUT_UINT32_LE( X3, output, 12 );
}

void AES128::encrypt_block( const uint8_t input[16], uint8_t output[16] )
{
    int i;
    uint32_t *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    RK = this->erk;

    GET_UINT32_LE( X0, input,  0 ); X0 ^= *RK++; // carrega bloco de 128 bits
    GET_UINT32_LE( X1, input,  4 ); X1 ^= *RK++;
    GET_UINT32_LE( X2, input,  8 ); X2 ^= *RK++;
    GET_UINT32_LE( X3, input, 12 ); X3 ^= *RK++;

    for( i = 4; i > 0; i-- )
    {
        AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
        AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );
    }

    AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

    X0 = *RK++ ^ \
            ( (uint32_t) FSb[ ( Y0       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( Y1 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( Y2 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( Y3 >> 24 ) & 0xFF ] << 24 );

    X1 = *RK++ ^ \
            ( (uint32_t) FSb[ ( Y1       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( Y2 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( Y3 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( Y0 >> 24 ) & 0xFF ] << 24 );

    X2 = *RK++ ^ \
            ( (uint32_t) FSb[ ( Y2       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( Y3 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( Y0 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( Y1 >> 24 ) & 0xFF ] << 24 );

    X3 = *RK++ ^ \
            ( (uint32_t) FSb[ ( Y3       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( Y0 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( Y1 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( Y2 >> 24 ) & 0xFF ] << 24 );


    PUT_UINT32_LE( X0, output,  0 ); // descarrega bloco de 128 bits
    PUT_UINT32_LE( X1, output,  4 );
    PUT_UINT32_LE( X2, output,  8 );
    PUT_UINT32_LE( X3, output, 12 );
}
