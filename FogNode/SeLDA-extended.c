#include "pbc.h"
#include <string.h>
#include <time.h>

typedef struct {
	char ID[5];
	element_t K_I;
	element_t TK_I;
	element_t C_I_1;
	element_t C_I_2;
	element_t C_1;
	element_t C_2;
	element_t S_I;
	element_t S_2;
	element_t R_I;

} USERS;

USERS U[5000];

int cnt = 1500;

const char *tmstmp = "20220215";


static void reProcessUsers(pairing_t pairing, element_t g){
	element_t r_p, tmp1;

	element_init_Zr(r_p, pairing);
	element_init_G1(tmp1, pairing);

	element_random(r_p);

	element_pow_zn(tmp1, g, r_p);

	for (int i = 0; i<cnt; i++){
		element_init_GT(U[i].C_1, pairing);
		element_init_G1(U[i].C_2, pairing);
		element_init_G1(U[i].S_2, pairing);

		// e(c_i, rk_A)
		element_pairing(U[i].C_1, U[i].C_I_1, U[i].TK_I);
		//element_printf("Pairing = %B\n", U[i].C_1);

		element_mul(U[i].C_2, tmp1, U[i].C_I_2);
		//element_printf("\n\nPoint Mul = %B\n", U[i].C_2);

		element_pow_zn(U[i].S_2, U[i].TK_I, U[i].S_I);

	}

	element_clear(r_p);
	element_clear(tmp1);


}

static void Aggregation(pairing_t pairing, element_t K) {
	element_t CT_1, CT_2, ST;
	element_t V_T, K_inv, tmp;

	element_init_GT(CT_1, pairing);
	element_init_G1(CT_2, pairing);
	element_init_G1(ST, pairing);

	element_init_G1(V_T, pairing);
	element_init_Zr(K_inv, pairing);
	element_init_G1(tmp, pairing);

	element_set1(CT_1);
	element_set1(CT_2);
	element_set1(ST);

	for (int i = 0; i < cnt; i++){
		element_mul(CT_1, CT_1, U[i].C_1);
		element_mul(CT_2, CT_2, U[i].C_2);
		element_mul(ST, ST, U[i].S_2);
	}

	element_printf("\nAggregated Ciphertext 1 for %d Users = %B\n", cnt, CT_1);
	element_printf("\nAggregated Ciphertext 2 for %d Users = %B\n", cnt, CT_2);
	element_printf("\nAggregated Verification Tag for %d Users = %B\n", cnt, ST);

	//Solve for V_t
	element_invert(K_inv, K);
	element_pow_zn(tmp, CT_1, K_inv);
	element_div(V_T, CT_2, tmp);

	element_printf("\nDLP Variable = %B\n", V_T);

	element_clear(tmp);
	element_clear(K_inv);
	element_clear(CT_1);
	element_clear(CT_2);
	element_clear(ST);
	element_clear(V_T);

}

static void ProcessUsers(pairing_t pairing, element_t g, element_t h, element_t Z){
	for (int i = 0; i< cnt; i++) {
		element_t e_i, r_i, Hash_T, Hash_R, KH, X_I;
		element_t tmp1, tmp2, tmp3, tmp4;
		//unsigned char *R_I_x, *R_I_y;
		char EI[20];
		char RI[65];
		unsigned char *x_i = "Dummy Data 1";

		char msg1[50];
		char msg2[100];
		element_init_Zr(e_i, pairing);
		element_init_Zr(Hash_T, pairing);
		element_init_Zr(Hash_R, pairing);
		element_init_Zr(KH, pairing);
		element_init_Zr(X_I, pairing);

		//Initiate temporary variables
		element_init_G1(tmp1, pairing);
		element_init_G1(tmp2, pairing);
		element_init_Zr(tmp3, pairing);
		element_init_Zr(tmp4, pairing);

		//
		element_init_G1(U[i].C_I_1, pairing);
		element_init_G1(U[i].C_I_2, pairing);
		element_init_Zr(U[i].S_I, pairing);
		element_init_G1(U[i].R_I, pairing);

		element_init_G1(r_i, pairing);

		element_random(e_i);
		element_printf("e_i = %B\n", e_i);
		element_pow_zn(r_i, g, e_i);
		element_printf("r_i = %B\n", r_i);

		//Convert Elements to Bytes
		element_to_bytes_compressed(RI, r_i);
		element_to_bytes(EI, e_i);

		//Concatenate EI and Timestamp
		snprintf(msg1, 30, "%s%s", EI, tmstmp);
		element_from_hash(Hash_T, (void*)msg1, 30);
		element_printf("H(tmstmp||e_i) = %B\n", Hash_T);

		element_from_bytes(X_I, x_i);
		element_printf("X_I = %B\n", X_I);

		//k_i * H(t||e_i)
		element_mul(KH, U[i].K_I, Hash_T);
		//h^x_i
		element_pow_zn(tmp1, g, X_I);
		//Z^H(t||e_i)
		element_pow_zn(tmp2, Z, Hash_T);
		//C_I_2 = h^x_i * Z^H(t||e_i)
		element_mul(U[i].C_I_2, tmp1, tmp2);
		//C_I_1 = g^k.H(t||e_i)
		element_pow_zn(U[i].C_I_1, g, KH);

		//Calculate the verification tag
		//Concatenate RI and Timestamp
		snprintf(msg2, 75, "%s%s", RI, tmstmp);
		element_from_hash(Hash_R, (void*)msg2, 75);
		element_printf("H(tmstmp||r_i) = %B\n", Hash_R);

		element_add(tmp3, X_I, e_i);
		element_add(tmp3, tmp3, Hash_R);
		element_mul(U[i].S_I, U[i].K_I, tmp3);

		element_set(U[i].R_I, r_i);

		element_clear(tmp1);
		element_clear(tmp2);
		element_clear(tmp3);
		element_clear(KH);
		element_clear(X_I);
		element_clear(Hash_T);
		element_clear(e_i);
		element_clear(r_i);
	}
}

int main(){
	clock_t proc1, proc2, reproc1, reproc2, agg1, agg2;
	double procT, reprocT, aggT;

	pairing_t pairing;
	char param[1024];
	size_t count = fread(param, 1, 1024, stdin);

	if (!count)
		pbc_die("Input Error");

	pairing_init_set_buf(pairing, param, count);

	element_t g, h, Z;

	element_t SK_A, PK_A;

	//Generating System Parameters (g,h,Z)
	element_init_G1(g, pairing);
	element_init_GT(h, pairing);
	element_init_GT(Z, pairing);

	element_random(g);
	element_printf("System Generator 'g' = %B\n", g);

	element_random(h);
	element_printf("System Generator 'h' = %B\n", h);

	element_pairing(Z, g, g);
	element_printf("System Parameter 'Z' = %B\n", Z);

	//Generate Aggregator Secret Key and Public Key
	element_init_Zr(SK_A, pairing);
	element_init_G1(PK_A, pairing);
	
	//Aggregator Credentials
	element_random(SK_A);
	element_pow_zn(PK_A, g, SK_A);
	element_printf("Aggregator Public Key = %B\n\n", PK_A);


	//Generate Secret Key for Each user > 4 users
	for (int i = 0; i < cnt; i++){
		element_t N;
		snprintf(U[i].ID, 5, "%d", i);
		element_init_Zr(U[i].K_I, pairing);
		element_init_G1(U[i].TK_I, pairing);
		element_init_Zr(N, pairing);

		element_random(U[i].K_I);
		//Invert the secret key
		element_invert(N, U[i].K_I);
		//Create Transfer Key
		element_pow_zn(U[i].TK_I, PK_A, N);
	}

	printf("\n Key Processing ============================================================================================ \n");
	proc1 = clock();
	ProcessUsers(pairing, g, h, Z);
	proc2 = clock();
	procT = ((double) (proc2 - proc1)) / CLOCKS_PER_SEC;

	printf("\n Key reProcessing ============================================================================================ \n");
	reproc1 = clock();
	reProcessUsers(pairing, g);
	reproc2 = clock();
	reprocT = ((double) (reproc2 - reproc1)) / CLOCKS_PER_SEC;

	//Access all Data
	for (int i = 0; i < cnt; i++){
		element_printf("Secret Key for User %s = %B\n", U[i].ID, U[i].K_I);
		element_printf("Transfer Key for User %s = %B\n\n", U[i].ID, U[i].TK_I);
		element_printf("1st Level Ciphertext 1 for User %s = %B\n\n", U[i].ID, U[i].C_I_1);
		element_printf("1st Level Ciphertext 2 for User %s = %B\n\n", U[i].ID, U[i].C_I_2);
		element_printf("1st Level Verification Tag 1 for User %s = %B\n\n", U[i].ID, U[i].S_I);
		element_printf("1st Level Verification Tag 2 for User %s = %B\n\n", U[i].ID, U[i].R_I);	
		element_printf("2nd Level Ciphertext 1 for User %s = %B\n\n", U[i].ID, U[i].C_1);
		element_printf("2nd Level Ciphertext 2 for User %s = %B\n\n", U[i].ID, U[i].C_2);
		element_printf("2nd Level Verification Tag for User %s = %B\n\n", U[i].ID, U[i].S_2);
	}

	printf("\n Data Aggregation ============================================================================================ \n");
	agg1 = clock();
	Aggregation(pairing, SK_A);
	agg2 = clock();
	aggT = ((double) (agg2 - agg1)) / CLOCKS_PER_SEC;

	printf("\n Performace Resu;ts ============================================================================================ \n");
	printf("Key Processing for %d Users took = %f seconds\n", cnt, procT);
	printf("Key reProcessing for %d Users took = %f seconds\n", cnt, reprocT);
	printf("Data Aggregation for %d Users took = %f seconds\n", cnt, aggT);

	element_clear(g);
	element_clear(h);
	element_clear(Z);
	element_clear(SK_A);
	element_clear(PK_A);

	//element_pow_zn(public_key, g, secret_key);
}