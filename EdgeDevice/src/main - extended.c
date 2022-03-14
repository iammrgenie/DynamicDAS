#include <zephyr.h>
#include <sys/printk.h>

#include <stdio.h>
#include <stdlib.h>
#include <timing/timing.h>

#include "../c25519/src/c25519.h"
#include "../c25519/src/ed25519.h"
#include "../c25519/src/sha256.h"

// Aggregator Functions
uint8_t K_A[ED25519_EXPONENT_SIZE];
uint8_t pka_x[F25519_SIZE];
uint8_t pka_y[F25519_SIZE];
struct ed25519_pt PK_A;


//Parameters for User A
uint8_t SK_I[ED25519_EXPONENT_SIZE], tk_i[ED25519_EXPONENT_SIZE];
uint8_t tki_x[F25519_SIZE], tki_y[F25519_SIZE];
struct ed25519_pt TK_I;

//Process Parameters
uint8_t E_I[ED25519_EXPONENT_SIZE], S_I[ED25519_EXPONENT_SIZE];
uint8_t tmp1[ED25519_EXPONENT_SIZE], tmp2[ED25519_EXPONENT_SIZE];
struct ed25519_pt R_I;
struct ed25519_pt C_1;
struct ed25519_pt C_2;
struct ed25519_pt tmp3;
struct ed25519_pt tmp4;

//Hash Parameters
uint8_t HM1[F25519_SIZE], HM2[F25519_SIZE];
struct tc_sha256_state_struct stx;


//Performance Parameters (Time Measurements)
//timing_t stA, etA;
//uint64_t tA_cycles;
//uint64_t tA_ns;

// =============================================================================================================================================


const char *tmstmp = "20220216";

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

static void ECDisplay(struct ed25519_pt *in)
{
    uint8_t x[F25519_SIZE], y[F25519_SIZE];
    ed25519_unproject(x, y, in);
    
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
    //timing_t start_time, end_time;
    //uint64_t total_cycles;
    //uint64_t total_ns;

    //timing_init();
    //timing_start();
    //start_time = timing_counter_get();
    for (int i = 0; i < ED25519_EXPONENT_SIZE; i++){
        key[i] = rand();
    }
    c25519_prepare(key);
    //end_time = timing_counter_get();

    //total_cycles = timing_cycles_get(&start_time, &end_time);
    //total_ns = timing_cycles_to_ns(total_cycles);
    //timing_stop();

    displayHex(key);

}


static void performExp(struct ed25519_pt *out, struct ed25519_pt *base, uint8_t * pwr, uint8_t *ax, uint8_t *ay){
    ed25519_smult(out, base, pwr);
    ed25519_unproject(ax, ay, out);

    print_point(ax, ay);
}




static void Hash256(uint8_t *digest, const char *msg){
    (void)tc_sha256_init(&stx);
    tc_sha256_update(&stx, (const uint8_t *)msg, strlen(msg));
    (void)tc_sha256_final(digest, &stx);
}

static void PointMul(struct ed25519_pt *out, struct ed25519_pt *in1, struct ed25519_pt *in2){
    uint8_t ax[F25519_SIZE], ay[F25519_SIZE], bx[F25519_SIZE], by[F25519_SIZE], cx[F25519_SIZE], cy[F25519_SIZE];
    //ed25519_unproject(ax, ay, out);
    ed25519_unproject(bx, by, in1);
    ed25519_unproject(cx, cy, in2);

    f25519_mul(ax, bx, cx);
    f25519_mul(ay, by, cy);

    ed25519_project(out, ax, ay);
}


static void ProcessKey(uint8_t *KI){
    uint8_t r_i_x[F25519_SIZE], r_i_y[F25519_SIZE];
    
    //random plaintext value for test purposes
    const uint8_t x_i[F25519_SIZE] = {
                                    0x4e, 0xdb, 0x9d, 0x4d, 0xa2, 0xd9, 0x11, 0x7f,
                                    0xad, 0x01, 0xf4, 0x36, 0x7b, 0x03, 0xd9, 0xa3,
                                    0x87, 0xe7, 0x58, 0x8e, 0x96, 0x21, 0xac, 0xf6,
                                    0x84, 0xc1, 0x46, 0xbc, 0xd2, 0x28, 0x24, 0x1b
                                };
    //generate E_I
    printf("Parameter E_I ");
    GenKey(E_I);

    //generate R_I
    ed25519_smult(&R_I, &ed25519_base, E_I);
    ed25519_unproject(r_i_x, r_i_y, &R_I);
    printf("Paramter R_I");
    ECDisplay(&R_I);

    //Hash of Timestamp and E_I
    f25519_add(tmp1, E_I, (uint8_t *)tmstmp);
    Hash256(HM1, (char *)tmp1);
    printf("Hash of Timestamp and E_I = ");
    displayHex(HM1);

    //Multiply k_i * H(t||e_I)
    f25519_mul(tmp2, KI, HM1);
    //Ci_t(1)
    ed25519_smult(&C_1, &ed25519_base, tmp2);
    printf("First Level Ciphertext 1 = ");
    ECDisplay(&C_1);
    
    //h^x_i
    ed25519_smult(&tmp3, &ed25519_base, x_i);
    //Z^H(t||e_i)
    ed25519_smult(&tmp4, &ed25519_base, HM1);

    //Ci_t(2)
    PointMul(&C_2, &tmp3, &tmp4);
    printf("First Level Ciphertext 2 = ");
    ECDisplay(&C_2);

    //S_I
    f25519_add(tmp1, x_i, E_I);
    f25519_add(tmp2, r_i_x, r_i_y);
    f25519_add(tmp2, tmp2, (uint8_t *)tmstmp);
    Hash256(HM2, (char *)tmp2);
    printf("Hash of Timestamp and R_I = ");
    displayHex(HM2);

    f25519_add(tmp1, tmp1, HM2);
    f25519_mul(S_I, KI, tmp1);
    printf("First Level Verification Tag = ");
    displayHex(S_I);

}

void main(void)
{
    timing_t proc1, proc2;
    timing_t exp1, exp2;
    uint64_t total_cycles;
    uint64_t proc_ns, exp_ns;
    srand(1546);

    timing_init();
    
    timing_start();
    //Generate Private key using a random generator
    printf("Key Generation Process for the Aggregator....\n");
    printf("K_A:");
    GenKey(K_A);
    printf("\n");

    exp1 = timing_counter_get();
    ed25519_smult(&PK_A, &ed25519_base, K_A);
    exp2 = timing_counter_get();
    total_cycles = timing_cycles_get(&exp1, &exp2);
    exp_ns = timing_cycles_to_ns(total_cycles);

    //Key Generation at User A
    printf("SK_I:");
    GenKey(SK_I);                                               // k_i
    printf("\n");
    
    f25519_inv(tk_i, SK_I);                                     // 1/k_i
    
    printf("Transfer Key for A:");
    performExp(&TK_I, &PK_A, tk_i, tki_x, tki_y);               // rk_i = PK_A^(1/k_i)
    printf("\n");

    printf("Process Function ============================================================================================ \n");
    proc1 = timing_counter_get();
    ProcessKey(SK_I);
    proc2 = timing_counter_get();
    total_cycles = timing_cycles_get(&proc1, &proc2);
    proc_ns = timing_cycles_to_ns(total_cycles);

    printf("\nKey Process Function took %lld nano seconds\n\n", proc_ns);
    printf("One Exponentiation took %lld nano seconds\n\n", exp_ns);


    //timing_stop();
}
