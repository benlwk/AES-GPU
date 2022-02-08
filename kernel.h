
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>//#include <sys/time.h>
#include <sys/stat.h>
#include <string.h>
#include <assert.h>

__constant__ uint32_t rkC[60]; 
#define msgSize 	256*1024*1024	// size in word (4 bytes)
#define threadSize 	1024	// Minimum 256 Threads
#define REPEAT		32
#define gridSize 	msgSize/threadSize/4 // Each thread encrypt one counter value, which is 16 bytes or 4 words.  
#define ITERATION 	10	// Calculate the average time
#define DEBUG 			// Check results against CPU
#define pret3Size	msgSize/4/16777216
#define pret2Size	msgSize/4/65536

void AESPrepareKey(char *dec_key, const char *enc_key, unsigned int key_bits);
void AES_128_encrypt_CTR(unsigned int *out, const unsigned int *rk, unsigned int counter, uint32_t* in);
void AES_128_encrypt_CTR_pret2(unsigned int *out, const unsigned int *rk, unsigned int counter, uint32_t* in, uint32_t *pret2, uint32_t *pret3);
void AES_128_encrypt_CTR_pret3(unsigned int *out, const unsigned int *rk, unsigned int counter, uint32_t* in, uint32_t *pret2, uint32_t *pret3);
__global__ void encGPUshared(unsigned int *out, const unsigned int *roundkey, uint32_t* in, uint32_t *pret3);
__global__ void OneTblBytePermReuse(uint32_t *out, uint32_t* rk, uint32_t* t0G, uint32_t* in, uint32_t *pret3); 
__global__ void OneTblBytePermReuseUnroll(uint32_t *out, uint32_t* rk, uint32_t* t0G, uint32_t* in, uint32_t *pret2, uint32_t *pret3);
__global__ void OneTblBytePermOri(uint32_t *out, uint32_t* rk, uint32_t* t0G, uint32_t* t4_0G, uint32_t* t4_1G, uint32_t* t4_2G, uint32_t* t4_3G, uint32_t* in); 
__global__ void OneTblBytePermSBoxOri(uint32_t* out, uint32_t* rk, uint32_t* t0G, uint32_t* t4G, uint8_t* SAES, uint32_t* in); 
__global__ void OneTblBytePermSBoxComb(uint32_t* out, uint32_t* rk, uint32_t* t0G, uint32_t* t4G, uint8_t* SAES, uint32_t* in); 
