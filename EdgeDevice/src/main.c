#include <zephyr.h>
#include <sys/printk.h>

#include <stdio.h>
#include <stdlib.h>
#include <timing/timing.h>

#include "../c25519/src/c25519.h"
#include "../c25519/src/ed25519.h"
#include "../c25519/src/sha256.h"

 // Key Manager Functions
uint8_t SK_S[ED25519_EXPONENT_SIZE];
uint8_t pks_x[F25519_SIZE];
uint8_t pks_y[F25519_SIZE];
struct ed25519_pt PK_S;

//Parameters for User A
uint8_t SK_A[ED25519_EXPONENT_SIZE], tk_a[ED25519_EXPONENT_SIZE];
uint8_t tka_x[F25519_SIZE], tka_y[F25519_SIZE];
struct ed25519_pt TK_A;

//Rekey Parameters
uint8_t rka_x[F25519_SIZE], rka_y[F25519_SIZE];
struct ed25519_pt RKA_S;

//Hash Parameters
uint8_t HM[F25519_SIZE];
struct tc_sha256_state_struct stx;

//Process Parameters
uint8_t c_i[F25519_SIZE], r_i_x[F25519_SIZE], r_i_y[F25519_SIZE], sum_hash[F25519_SIZE];
uint8_t e_i[ED25519_EXPONENT_SIZE];
uint8_t s_i[F25519_SIZE];
uint8_t HM_A[F25519_SIZE]; 
uint8_t HM_SUM[F25519_SIZE];
struct ed25519_pt RK_I;

//Performance Parameters (Time Measurements)
timing_t stA, etA;
uint64_t tA_cycles;
uint64_t tA_ns;

// =============================================================================================================================================

static void displayHex(const uint8_t *hex){
    int i;
    printf(" ");
    for (i = 0; i < F25519_SIZE; i++){
        printf("%02x", hex[i]);
    }
    printf("\n");
}

static void print_point(const uint8_t *x, const uint8_t *y)
{
    int i;

    printf("  ");
    for (i = 0; i < F25519_SIZE; i++)
        printf("%02x", x[i]);
    printf(", ");
    for (i = 0; i < F25519_SIZE; i++)
        printf("%02x", y[i]);
    printf("\n");
}

static void GenKey(uint8_t *key){
    timing_t start_time, end_time;
    uint64_t total_cycles;
    uint64_t total_ns;

    //timing_init();
    //timing_start();
    start_time = timing_counter_get();
    for (int i = 0; i < ED25519_EXPONENT_SIZE; i++){
        key[i] = rand();
    }
    c25519_prepare(key);
    end_time = timing_counter_get();

    total_cycles = timing_cycles_get(&start_time, &end_time);
    total_ns = timing_cycles_to_ns(total_cycles);
    //timing_stop();

    displayHex(key);

}


static void performExp(struct ed25519_pt *out, struct ed25519_pt *base, uint8_t * pwr, uint8_t *ax, uint8_t *ay){
    ed25519_smult(out, base, pwr);
    ed25519_unproject(ax, ay, out);

    print_point(ax, ay);
}




static void Hash256(uint8_t *digest, const char *msg, struct tc_sha256_state_struct stx){
    (void)tc_sha256_init(&stx);
    tc_sha256_update(&stx, (const uint8_t *)msg, strlen(msg));
    (void)tc_sha256_final(digest, &stx);
}




void main(void)
{
    timing_t st, et;
    uint64_t total_cycles;
    uint64_t total_ns;
    srand(546);

    timing_init();
    timing_start();


    //Generate Private key using a random generator
    printf("KM Key Generation Process ....\n");
    printf("SK_A:");
    GenKey(SK_S);
    printf("\n");

    //Generate DA public key using the ed25519 base generator 
    st = timing_counter_get();
    //ed25519_smult(&PK_S, &ed25519_base, SK_S);
    printf("DA Key:KM :");
    performExp(&PK_S, &ed25519_base, SK_S, pks_x, pks_y);
    //ed25519_unproject(pks_x, pks_y, &PK_S);
    et = timing_counter_get();
    total_cycles = timing_cycles_get(&st, &et);
    total_ns = timing_cycles_to_ns(total_cycles);

    //double t = (double)total_ns / 1000000000;

    printf("\nExp Time = %lld nano seconds\n\n", total_ns);

    //Key Generation at User A
    printf("SK_A:");
    GenKey(SK_A);                                               // k_i
    printf("\n");
    
    f25519_inv(tk_a, SK_A);                                     // 1/k_i
    
    printf("Transfer Key for A:");
    performExp(&TK_A, &ed25519_base, tk_a, tka_x, tka_y);       // rk_A = h^(1/k_i)
    printf("\n");

    //KM ReKey Process
    printf("ReKey for A:KM:");
    performExp(&RKA_S, &TK_A, SK_S, rka_x, rka_y);              // rk_i_s = (h^(1/k_i))^k
    printf("\n");

    //Process Function -> KM
    const uint8_t x_i[F25519_SIZE] = {
                                    0x4e, 0xdb, 0x9d, 0x4d, 0xa2, 0xd9, 0x11, 0x7f,
                                    0xad, 0x01, 0xf4, 0x36, 0x7b, 0x03, 0xd9, 0xa3,
                                    0x87, 0xe7, 0x58, 0x8e, 0x96, 0x21, 0xac, 0xf6,
                                    0x84, 0xc1, 0x46, 0xbc, 0xd2, 0x28, 0x24, 0x1b
                                };

    //Multiply key and message (k_i.x_i_t) + H(t)
    const char *tmstmp = "255";
    stA = timing_counter_get();
    Hash256(HM, tmstmp, stx);                                   // H(t)
    printf("Hashed Timestamp (255):");
    displayHex(HM);
    printf("\n");

    f25519_mul(c_i, x_i, SK_A);                                 // k_i * x_i_t
    f25519_add(c_i, c_i, HM);                                   // c_i = k_i * x_i_t + H(t)
    printf("First-Level Cipher:");
    displayHex(c_i);
    printf("\n");

    printf("E_I: ");
    GenKey(e_i);
    printf("\n");

    printf("Process Key:A :");
    performExp(&RK_I, &ed25519_base, e_i, r_i_x, r_i_y);        // r_i_t = h^(e_i_t)
    printf("\n");

    f25519_add(e_i, e_i, x_i);                                  // e_i = x_i + e_i_t
    
    //H(t||r_i_t) = Using addition to simplify the implementation
    f25519_add(sum_hash, r_i_x, r_i_y);
    f25519_add(sum_hash, sum_hash, (uint8_t *)tmstmp);
    Hash256(HM_SUM, (char *)sum_hash, stx);

    f25519_add(s_i, e_i, HM_SUM);                               // (x_i + e_i_t + H(t||r_i_t))
    f25519_mul(s_i, SK_A, s_i);                                 // k_i(x_i + e_i_t + H(t||r_i_t))

    printf("First-Level Tag:");
    displayHex(s_i);
    printf("\n");

    etA = timing_counter_get();
    tA_cycles = timing_cycles_get(&stA, &etA);
    tA_ns = timing_cycles_to_ns(tA_cycles);

    printf("\nProcess Function Time = %lld nano seconds\n", tA_ns);

    printf("Process Completed\n");
    timing_stop();
}
