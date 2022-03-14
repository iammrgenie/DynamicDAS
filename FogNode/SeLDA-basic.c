#include "pbc.h"
#include <string.h>
#include <time.h>

typedef struct {
	char ID[5];
	element_t K_I;
	element_t TK_I;
	element_t RK_I;
	element_t C_I;
	element_t C_2;
	element_t S_I;
	element_t S_2;
	element_t R_I;

} USERS;

USERS U[5000];

int cnt = 1500;

const char *tmstmp = "20220215";


static void reProcessUsers(pairing_t pairing){
	element_t tmp1;

	char msg1[10];
	element_init_Zr(tmp1, pairing);

	//Hash Timestamp
	snprintf(msg1, 8, "%s", tmstmp);
	element_from_hash(tmp1, (void*)msg1, 8);
	element_printf("H(tmstmp) = %B\n", tmp1);

	for (int i = 0; i<cnt; i++){
		element_init_G1(U[i].C_2, pairing);
		element_init_G1(U[i].S_2, pairing);

		element_t tmp2;
		element_init_Zr(tmp2, pairing);

		//c_i - H(t)
		element_sub(tmp2, U[i].C_I, tmp1);

		//(rki->S)^(c_i - H(t))
		element_pow_zn(U[i].C_2, U[i].RK_I, tmp2);

		//(rki->S)^s_i
		element_pow_zn(U[i].S_2, U[i].RK_I, U[i].S_I);

		element_clear(tmp2);
	}

	element_clear(tmp1);
}

static void Aggregation(pairing_t pairing) {
	element_t CT, ST;
	//element_t V_T, K_inv, tmp;

	element_init_G1(CT, pairing);
	element_init_G1(ST, pairing);

	element_set1(CT);
	element_set1(ST);

	for (int i = 0; i < cnt; i++){
		element_mul(CT, CT, U[i].C_2);
		element_mul(ST, ST, U[i].S_2);
	}

	element_printf("\nAggregated Ciphertext for %d Users = %B\n", cnt, CT);
	element_printf("\nAggregated Verification Tag for %d Users = %B\n", cnt, ST);

	element_clear(CT);
	element_clear(ST);

}

static void ProcessUsers(pairing_t pairing, element_t g){
	for (int i = 0; i< cnt; i++) {
		element_t e_i, r_i, Hash_T, Hash_R, X_I;
		element_t tmp1, tmp2, tmp3;
		char RI[65];
		unsigned char *x_i = "Dummy Data 1";
		

		char msg1[10];
		char msg2[100];

		element_init_Zr(e_i, pairing);
		element_init_Zr(Hash_T, pairing);
		element_init_Zr(Hash_R, pairing);
		//element_init_Zr(KH, pairing);
		element_init_Zr(X_I, pairing);

		//Initiate temporary variables
		element_init_Zr(tmp1, pairing);
		element_init_Zr(tmp2, pairing);
		element_init_Zr(tmp3, pairing);
		//element_init_G1(tmp4, pairing);

		//
		element_init_Zr(U[i].C_I, pairing);
		element_init_Zr(U[i].S_I, pairing);
		element_init_G1(U[i].R_I, pairing);

		element_init_G1(r_i, pairing);

		//Generate random x_i
		element_from_bytes(X_I, x_i);
		element_printf("X_I = %B\n", X_I);

		//k_i * x_i
		element_mul(tmp1, X_I, U[i].K_I);
		//k_i * x_i + H(t)
		//Hash Timestamp
		snprintf(msg1, 8, "%s", tmstmp);
		element_from_hash(Hash_T, (void*)msg1, 8);
		element_printf("H(tmstmp) = %B\n", Hash_T);
		element_add(U[i].C_I, tmp1, Hash_T);

		element_random(e_i);
		element_printf("e_i = %B\n", e_i);
		element_pow_zn(r_i, g, e_i);
		element_printf("r_i = %B\n", r_i);

		//Convert Elements to Bytes
		element_to_bytes_compressed(RI, r_i);

		//Calculate the verification tag
		//Concatenate RI and Timestamp
		snprintf(msg2, 75, "%s%s", RI, tmstmp);
		element_from_hash(Hash_R, (void*)msg2, 75);
		element_printf("H(tmstmp||r_i) = %B\n", Hash_R);

		//x_i + e_i
		element_add(tmp2, X_I, e_i);
		//x_i + e_i + H(t||r_i)
		element_add(tmp3, tmp2, Hash_R);
		//s_i = k_i(x_i + e_i + H(t||r_i))
		element_mul(U[i].S_I, tmp3, U[i].K_I);

		element_set(U[i].R_I, r_i);

		element_clear(tmp1);
		element_clear(tmp2);
		element_clear(tmp3);
		element_clear(Hash_R);
		element_clear(X_I);
		element_clear(Hash_T);
		element_clear(e_i);
		element_clear(r_i);
	}
}

static void reKey(pairing_t pairing, element_t K) {
	//ReKey Process by the KM
	for (int i = 0; i < cnt; i ++){
		element_init_G1(U[i].RK_I, pairing);
		element_pow_zn(U[i].RK_I, U[i].TK_I, K);
	}
}

int main(){
	clock_t proc1, proc2, reproc1, reproc2, agg1, agg2, rek1, rek2;
	double procT, reprocT, aggT, rekT;

	pairing_t pairing;
	char param[1024];
	size_t count = fread(param, 1, 1024, stdin);

	if (!count)
		pbc_die("Input Error");

	pairing_init_set_buf(pairing, param, count);

	//Group generator
	element_t g;

	element_t SK_KM;

	//Generating System Parameters (g,h,Z)
	element_init_G1(g, pairing);

	element_random(g);
	element_printf("System Generator 'g' = %B\n", g);


	//Generate KM Secret Key
	element_init_Zr(SK_KM, pairing);
	
	//Aggregator Credentials
	element_random(SK_KM);
	element_printf("KM Secret Key = %B\n\n", SK_KM);


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
		element_pow_zn(U[i].TK_I, g, N);
	}

	printf("\n reKey Process ============================================================================================ \n");
	rek1 = clock();
	reKey(pairing, SK_KM);
	rek2 = clock();
	rekT = ((double) (rek2 - rek1)) / CLOCKS_PER_SEC;

	printf("\n Key Processing ============================================================================================ \n");
	proc1 = clock();
	ProcessUsers(pairing, g);
	proc2 = clock();
	procT = ((double) (proc2 - proc1)) / CLOCKS_PER_SEC;

	printf("\n Key reProcessing ============================================================================================ \n");
	reproc1 = clock();
	reProcessUsers(pairing);
	reproc2 = clock();
	reprocT = ((double) (reproc2 - reproc1)) / CLOCKS_PER_SEC;

	//Access all Data
	for (int i = 0; i < cnt; i++){
		element_printf("Secret Key for User %s = %B\n", U[i].ID, U[i].K_I);
		element_printf("Transfer Key for User %s = %B\n\n", U[i].ID, U[i].TK_I);
		element_printf("reKey for User %s by KM = %B\n\n", U[i].ID, U[i].RK_I);
		element_printf("1st Level Ciphertext for User %s = %B\n\n", U[i].ID, U[i].C_I);
		element_printf("1st Level Verification Tag 1 for User %s = %B\n\n", U[i].ID, U[i].S_I);
		element_printf("1st Level Verification Tag 2 for User %s = %B\n\n", U[i].ID, U[i].R_I);	
		element_printf("2nd Level Ciphertext for User %s = %B\n\n", U[i].ID, U[i].C_2);
		element_printf("2nd Level Verification Tag for User %s = %B\n\n", U[i].ID, U[i].S_2);
	}

	printf("\n Data Aggregation ============================================================================================ \n");
	agg1 = clock();
	Aggregation(pairing);
	agg2 = clock();
	aggT = ((double) (agg2 - agg1)) / CLOCKS_PER_SEC;

	printf("\n Performace Resu;ts ============================================================================================ \n");
	printf("reKey Processing for %d Users took = %f seconds\n", cnt, rekT);
	printf("Key Processing for %d Users took = %f seconds\n", cnt, procT);
	printf("Key reProcessing for %d Users took = %f seconds\n", cnt, reprocT);
	printf("Data Aggregation for %d Users took = %f seconds\n", cnt, aggT);

	element_clear(g);
	element_clear(SK_KM);

	//element_pow_zn(public_key, g, secret_key);
}