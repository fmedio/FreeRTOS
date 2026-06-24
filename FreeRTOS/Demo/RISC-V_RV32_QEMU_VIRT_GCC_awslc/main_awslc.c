/*
 * FreeRTOS RV32 + AWS-LC live-progress smoke test.
 *
 * Instead of calling BORINGSSL_self_test() (one opaque call, no output until
 * the very end), this drives each primitive individually so the UART shows
 * incremental progress with timestamps.
 *
 * Each step is a self-contained function that returns 1 on success / 0 on
 * failure. The driver prints "start" before and "done" after every step, so
 * even a hang in the middle of e.g. RSA keygen is visible.
 *
 * configTICK_RATE_HZ is 1000, so xTaskGetTickCount() ticks == ms.
 */

#include "FreeRTOS.h"
#include "task.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/curve25519.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#define awslcTASK_STACK_WORDS    ( 16 * 1024 )    /* 64 KB stack */
#define awslcTASK_PRIORITY       ( tskIDLE_PRIORITY + 1 )

static StaticTask_t xAwsLcTaskTCB;
static StackType_t  uxAwsLcTaskStack[ awslcTASK_STACK_WORDS ];

/*-----------------------------------------------------------*/
/* Small helpers.                                            */
/*-----------------------------------------------------------*/

/* Known-answer for SHA-256 of the empty string, from FIPS 180-4. */
static const uint8_t kEmptySha256[ 32 ] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

/* Known-answer for SHA-512 of the empty string. */
static const uint8_t kEmptySha512[ 64 ] = {
    0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
    0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
    0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
    0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
    0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
    0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
    0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
    0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
};

/* Known-answer for SHA3-256 of the empty string. */
static const uint8_t kEmptySha3_256[ 32 ] = {
    0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
    0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
    0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
    0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
};

static int bytes_equal( const uint8_t * a, const uint8_t * b, size_t n )
{
    return memcmp( a, b, n ) == 0;
}

static int bytes_nonzero( const uint8_t * a, size_t n )
{
    for( size_t i = 0; i < n; i++ )
    {
        if( a[ i ] != 0 ) return 1;
    }
    return 0;
}

/*-----------------------------------------------------------*/
/* Individual tests.                                         */
/*-----------------------------------------------------------*/

static int t_sha256( void )
{
    uint8_t out[ SHA256_DIGEST_LENGTH ];
    SHA256( ( const uint8_t * ) "", 0, out );
    return bytes_equal( out, kEmptySha256, sizeof( out ) );
}

static int t_sha512( void )
{
    uint8_t out[ SHA512_DIGEST_LENGTH ];
    SHA512( ( const uint8_t * ) "", 0, out );
    return bytes_equal( out, kEmptySha512, sizeof( out ) );
}

static int t_sha3_256( void )
{
    uint8_t out[ 32 ];
    unsigned int out_len = 0;
    if( !EVP_Digest( ( const uint8_t * ) "", 0, out, &out_len,
                     EVP_sha3_256(), NULL ) || out_len != 32 )
    {
        return 0;
    }
    return bytes_equal( out, kEmptySha3_256, sizeof( out ) );
}

static int t_hmac_sha256( void )
{
    /* RFC 4231 test case 1. */
    const uint8_t key[ 20 ] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    };
    const uint8_t expected[ 32 ] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    };
    uint8_t out[ 32 ];
    unsigned int out_len = sizeof( out );
    if( HMAC( EVP_sha256(), key, sizeof( key ),
              ( const uint8_t * ) "Hi There", 8, out, &out_len ) == NULL ||
        out_len != sizeof( expected ) )
    {
        return 0;
    }
    return bytes_equal( out, expected, sizeof( expected ) );
}

static int t_hkdf_sha256( void )
{
    /* RFC 5869 test case 1 (basic test with SHA-256). */
    const uint8_t ikm[ 22 ] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    };
    const uint8_t salt[ 13 ] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    };
    const uint8_t info[ 10 ] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    };
    const uint8_t expected[ 42 ] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
        0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
        0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
        0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    };
    uint8_t out[ 42 ];
    if( !HKDF( out, sizeof( out ), EVP_sha256(),
               ikm, sizeof( ikm ),
               salt, sizeof( salt ),
               info, sizeof( info ) ) )
    {
        return 0;
    }
    return bytes_equal( out, expected, sizeof( expected ) );
}

static int t_aes_cbc( void )
{
    /* AES-128 CBC round-trip: encrypt, decrypt, check we recover the input. */
    uint8_t key[ 16 ] = "BoringCrypto Key";
    uint8_t iv[ 16 ]  = { 0 };
    uint8_t pt[ 32 ]  = "Some forty-eight-byte plaintext";
    uint8_t ct[ 32 ];
    uint8_t rt[ 32 ];
    AES_KEY ek, dk;
    uint8_t iv_copy[ 16 ];

    if( AES_set_encrypt_key( key, 128, &ek ) != 0 ) return 0;
    memcpy( iv_copy, iv, 16 );
    AES_cbc_encrypt( pt, ct, sizeof( pt ), &ek, iv_copy, AES_ENCRYPT );

    if( AES_set_decrypt_key( key, 128, &dk ) != 0 ) return 0;
    memcpy( iv_copy, iv, 16 );
    AES_cbc_encrypt( ct, rt, sizeof( ct ), &dk, iv_copy, AES_DECRYPT );

    return bytes_equal( pt, rt, sizeof( pt ) ) &&
           !bytes_equal( pt, ct, sizeof( pt ) );  /* ct must differ from pt */
}

static int t_aes_gcm( void )
{
    /* AES-128-GCM round-trip via the AEAD interface. */
    const uint8_t key[ 16 ] = "BoringCrypto Key";
    const uint8_t nonce[ 12 ] = { 0 };
    const uint8_t pt[ 19 ]  = "AWS-LC GCM on RV32!";
    uint8_t ct[ 19 + 16 ];   /* plaintext + 16-byte tag */
    uint8_t rt[ 19 ];
    size_t out_len;

    EVP_AEAD_CTX ctx;
    EVP_AEAD_CTX_zero( &ctx );

    if( !EVP_AEAD_CTX_init( &ctx, EVP_aead_aes_128_gcm(),
                            key, sizeof( key ), 16, NULL ) )
    {
        return 0;
    }
    if( !EVP_AEAD_CTX_seal( &ctx, ct, &out_len, sizeof( ct ),
                            nonce, sizeof( nonce ),
                            pt, sizeof( pt ), NULL, 0 ) ||
        out_len != sizeof( ct ) )
    {
        EVP_AEAD_CTX_cleanup( &ctx );
        return 0;
    }
    if( !EVP_AEAD_CTX_open( &ctx, rt, &out_len, sizeof( rt ),
                            nonce, sizeof( nonce ),
                            ct, sizeof( ct ), NULL, 0 ) ||
        out_len != sizeof( rt ) )
    {
        EVP_AEAD_CTX_cleanup( &ctx );
        return 0;
    }
    EVP_AEAD_CTX_cleanup( &ctx );
    return bytes_equal( pt, rt, sizeof( pt ) );
}

static int t_rand_bytes( void )
{
    /* First RAND_bytes call triggers lazy init of the jitter-entropy
     * collector (~100ms+ on QEMU virt), runs the SP 800-90B startup health
     * tests on the cycle counter, allocates the DRBG state, and produces
     * the first batch of bytes. Subsequent calls only re-enter the DRBG
     * (fast) until reseeding is due.
     *
     * We print the first few bytes so the run is visibly distinct from a
     * deterministic-mode build (where these would be the same on every
     * boot). */
    uint8_t buf[ 64 ];
    memset( buf, 0, sizeof( buf ) );
    if( !RAND_bytes( buf, sizeof( buf ) ) ) return 0;
    if( !bytes_nonzero( buf, sizeof( buf ) ) ) return 0;

    printf( "        first random bytes: %02x%02x%02x%02x %02x%02x%02x%02x"
            " %02x%02x%02x%02x %02x%02x%02x%02x\r\n",
            buf[0],  buf[1],  buf[2],  buf[3],
            buf[4],  buf[5],  buf[6],  buf[7],
            buf[8],  buf[9],  buf[10], buf[11],
            buf[12], buf[13], buf[14], buf[15] );
    return 1;
}

static int t_ed25519( void )
{
    uint8_t pub[ ED25519_PUBLIC_KEY_LEN ];
    uint8_t priv[ ED25519_PRIVATE_KEY_LEN ];
    uint8_t sig[ ED25519_SIGNATURE_LEN ];
    const uint8_t msg[] = "Ed25519 on RV32+FreeRTOS";

    ED25519_keypair( pub, priv );
    if( !ED25519_sign( sig, msg, sizeof( msg ), priv ) ) return 0;
    if( !ED25519_verify( msg, sizeof( msg ), sig, pub ) ) return 0;

    /* Mutate the message and confirm verify rejects it. */
    uint8_t bad[ sizeof( msg ) ];
    memcpy( bad, msg, sizeof( msg ) );
    bad[ 0 ] ^= 1;
    if( ED25519_verify( bad, sizeof( bad ), sig, pub ) ) return 0;
    return 1;
}

static int t_ecdsa_p256( void )
{
    EC_KEY * key = EC_KEY_new_by_curve_name( NID_X9_62_prime256v1 );
    if( key == NULL ) return 0;
    if( !EC_KEY_generate_key( key ) ) { EC_KEY_free( key ); return 0; }

    uint8_t digest[ 32 ];
    SHA256( ( const uint8_t * ) "ECDSA test", 10, digest );

    uint8_t sig[ 80 ];  /* DER ECDSA-P256 sig is <= ~72 bytes */
    unsigned int sig_len = sizeof( sig );
    int ok = ECDSA_sign( 0, digest, sizeof( digest ), sig, &sig_len, key ) &&
             ECDSA_verify( 0, digest, sizeof( digest ), sig, sig_len, key );

    /* Flip a digest bit; verify must now reject. */
    if( ok )
    {
        digest[ 0 ] ^= 1;
        if( ECDSA_verify( 0, digest, sizeof( digest ), sig, sig_len, key ) )
        {
            ok = 0;
        }
    }
    EC_KEY_free( key );
    return ok;
}

static int t_ecdh_p256( void )
{
    EC_KEY * a = EC_KEY_new_by_curve_name( NID_X9_62_prime256v1 );
    EC_KEY * b = EC_KEY_new_by_curve_name( NID_X9_62_prime256v1 );
    int ok = 0;
    uint8_t sa[ 32 ], sb[ 32 ];

    if( a == NULL || b == NULL ) goto done;
    if( !EC_KEY_generate_key( a ) || !EC_KEY_generate_key( b ) ) goto done;

    if( ECDH_compute_key( sa, sizeof( sa ),
                          EC_KEY_get0_public_key( b ), a, NULL ) <= 0 ) goto done;
    if( ECDH_compute_key( sb, sizeof( sb ),
                          EC_KEY_get0_public_key( a ), b, NULL ) <= 0 ) goto done;
    ok = bytes_equal( sa, sb, 32 );

done:
    EC_KEY_free( a );
    EC_KEY_free( b );
    return ok;
}

static int t_rsa_2048( void )
{
    /* Heaviest test in the suite -- RSA-2048 keygen + sign + verify. May
     * take many seconds on the QEMU virt RV32 model. */
    RSA *    rsa = RSA_new();
    BIGNUM * e   = BN_new();
    int ok = 0;
    uint8_t digest[ 32 ];
    uint8_t * sig = NULL;
    unsigned int sig_len = 0;

    if( rsa == NULL || e == NULL ) goto done;
    if( !BN_set_word( e, RSA_F4 ) ) goto done;
    if( !RSA_generate_key_ex( rsa, 2048, e, NULL ) ) goto done;

    sig = ( uint8_t * ) OPENSSL_malloc( RSA_size( rsa ) );
    if( sig == NULL ) goto done;

    SHA256( ( const uint8_t * ) "RSA test", 8, digest );
    if( !RSA_sign( NID_sha256, digest, sizeof( digest ),
                   sig, &sig_len, rsa ) ) goto done;
    if( !RSA_verify( NID_sha256, digest, sizeof( digest ),
                     sig, sig_len, rsa ) ) goto done;

    /* Tamper with the signature; verify must reject. */
    sig[ 0 ] ^= 1;
    if( RSA_verify( NID_sha256, digest, sizeof( digest ),
                    sig, sig_len, rsa ) ) goto done;

    ok = 1;
done:
    OPENSSL_free( sig );
    BN_free( e );
    RSA_free( rsa );
    return ok;
}

/*-----------------------------------------------------------*/
/* Driver.                                                   */
/*-----------------------------------------------------------*/

typedef int ( * test_fn_t )( void );

typedef struct
{
    const char * name;
    test_fn_t    fn;
} test_entry_t;

static const test_entry_t kTests[] =
{
    /* Fast deterministic checks first, so a failure in basic primitives
     * surfaces before we pay the jitter-init cost. */
    { "SHA-256 (empty)",         t_sha256      },
    { "SHA-512 (empty)",         t_sha512      },
    { "SHA3-256 (empty)",        t_sha3_256    },
    { "HMAC-SHA-256 (RFC 4231)", t_hmac_sha256 },
    { "HKDF-SHA-256 (RFC 5869)", t_hkdf_sha256 },
    { "AES-128-CBC round-trip",  t_aes_cbc     },
    { "AES-128-GCM round-trip",  t_aes_gcm     },
    /* First entropy consumer: triggers jitter-entropy startup health tests
     * and DRBG seeding. Expect this single call to take ~100ms+. */
    { "RAND_bytes (jitter+DRBG)", t_rand_bytes },
    /* The rest consume the now-seeded DRBG. */
    { "Ed25519 keygen/sign/verify",  t_ed25519    },
    { "ECDSA-P256 sign/verify",  t_ecdsa_p256  },
    { "ECDH-P256 agreement",     t_ecdh_p256   },
    { "RSA-2048 keygen/sign/verify", t_rsa_2048 },
};

#define NUM_TESTS ( sizeof( kTests ) / sizeof( kTests[ 0 ] ) )

static void prv_print_ts( void )
{
    unsigned ms = ( unsigned ) xTaskGetTickCount();
    printf( "[t=%5u.%03us] ", ms / 1000, ms % 1000 );
}

static void prv_drain_err_queue( void )
{
    unsigned long e;
    const char * file;
    int line;
    while( ( e = ERR_get_error_line( &file, &line ) ) != 0 )
    {
        printf( "        err: %08lx at %s:%d\r\n",
                e, file ? file : "?", line );
    }
}

static void prvAwsLcSelfTestTask( void * pvParameters )
{
    ( void ) pvParameters;

    prv_print_ts();
    printf( "=== AWS-LC FreeRTOS live test ===\r\n" );
    prv_print_ts();
    printf( "Free heap: %u bytes\r\n",
            ( unsigned ) xPortGetFreeHeapSize() );

    unsigned passed = 0;
    unsigned failed = 0;

    for( unsigned i = 0; i < NUM_TESTS; i++ )
    {
        prv_print_ts();
        printf( "[%u/%u] start: %s\r\n",
                i + 1, ( unsigned ) NUM_TESTS, kTests[ i ].name );

        TickType_t t0 = xTaskGetTickCount();
        int ok = kTests[ i ].fn();
        TickType_t dt = xTaskGetTickCount() - t0;

        prv_print_ts();
        printf( "        done : %s -- %s (%ums, heap=%u)\r\n",
                kTests[ i ].name,
                ok ? "PASS" : "FAIL",
                ( unsigned ) dt,
                ( unsigned ) xPortGetFreeHeapSize() );

        if( ok ) { passed++; }
        else
        {
            failed++;
            prv_drain_err_queue();
        }
    }

    prv_print_ts();
    printf( "=== summary: %u passed, %u failed (of %u) ===\r\n",
            passed, failed, ( unsigned ) NUM_TESTS );
    prv_print_ts();
    printf( "Min heap ever: %u bytes\r\n",
            ( unsigned ) xPortGetMinimumEverFreeHeapSize() );

    /* Power off QEMU virt via the SiFive test-finisher MMIO. */
    *( volatile uint32_t * ) 0x100000UL = ( failed == 0 ) ? 0x5555 : 0x3333;

    for( ;; )
    {
        vTaskDelay( portMAX_DELAY );
    }
}

void main_awslc( void )
{
    xTaskCreateStatic( prvAwsLcSelfTestTask,
                       "awslc",
                       awslcTASK_STACK_WORDS,
                       NULL,
                       awslcTASK_PRIORITY,
                       uxAwsLcTaskStack,
                       &xAwsLcTaskTCB );

    vTaskStartScheduler();

    /* Should never get here. */
    for( ;; )
    {
    }
}
