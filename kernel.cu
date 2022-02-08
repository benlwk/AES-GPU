
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include "kernel.h"
#include <stdio.h>
#include "tables.h"

__global__ void test()
{
	uint32_t a = 0xfffefd01, b = 0x00000000, c = 0x00000000;
	b = __byte_perm(a, b, 0x1456);
	// BytePerm(a, 21554);
	printf("------------------------------------\n");
	printf("%08x %08x\n", a, b);
}

void testAES(char* keyBuf)
{
	double kernelSpeed = 0, kernelSpeed2 = 0;
	cudaEvent_t start, stop;
	float miliseconds = 0;

	uint32_t* counter, * gpuBuf, * outBuf, *inBuf;
	uint32_t* dev_outBuf, * dev_rk, *dev_inBuf;
	// char* keyBuf;												// Securitz Key
	char* m_EncryptKey = (char*)malloc(16 * 11 * sizeof(char));	// Expanded Keys
 	cudaSharedMemConfig pConfig;
	cudaDeviceSetSharedMemConfig(cudaSharedMemBankSizeEightByte);

	cudaEventCreate(&start);	cudaEventCreate(&stop);
	counter = (uint32_t*)malloc(msgSize * sizeof(uint32_t));
	cudaMallocHost((void**)&gpuBuf, msgSize * sizeof(uint32_t));
	cudaMallocHost((void**)&outBuf, msgSize * sizeof(uint32_t));
	cudaMallocHost((void**)&inBuf, msgSize * sizeof(uint32_t));
	// cudaMallocHost((void**)&keyBuf, 16 * sizeof(char));
	cudaMalloc((void**)&dev_outBuf, msgSize * sizeof(uint32_t));
	cudaMalloc((void**)&dev_inBuf, msgSize * sizeof(uint32_t));
	cudaMalloc((void**)&dev_rk, 60 * sizeof(uint32_t));	// AES-128 use 44

	memset(outBuf, msgSize * sizeof(uint32_t), 0);
	memset(counter, msgSize * sizeof(uint32_t), 0);
	cudaMemset(dev_outBuf, 0, msgSize * sizeof(uint32_t));

	// //key for test vector, FIPS-197 0x000102030405060708090A0B0C0D0E0F
	// for (int i = 0; i < 16; i++) keyBuf[i] = i;

	if (counter == NULL || gpuBuf == NULL || outBuf == NULL || keyBuf == NULL)
	{
		printf("Memory Allocatation Failed!");
		return;
	}

	for (int i = 0; i < 11 * 16; i++)	m_EncryptKey[i] = 0;

	AESPrepareKey(m_EncryptKey, keyBuf, 128);

// One-T
	// Allocate Tables
	uint8_t *SAES_d;
	uint32_t *t0, *t1, *t2, *t3, *t4, *t4_0, *t4_1, *t4_2, *t4_3, *pret2, *pret3;
	uint32_t *dt0, *dt1, *dt2, *dt3, *dt4, *dt4_0, *dt4_1, *dt4_2, *dt4_3, *dev_pret2, *dev_pret3;
	cudaMallocHost((void**)&t0, TABLE_SIZE * sizeof(uint32_t));
	cudaMallocHost((void**)&t1, TABLE_SIZE * sizeof(uint32_t));
	cudaMallocHost((void**)&t2, TABLE_SIZE * sizeof(uint32_t));
	cudaMallocHost((void**)&t3, TABLE_SIZE * sizeof(uint32_t));
	cudaMallocHost((void**)&t4, TABLE_SIZE * sizeof(uint32_t));
	cudaMallocHost((void**)&t4_0, TABLE_SIZE * sizeof(uint32_t));
	cudaMallocHost((void**)&t4_1, TABLE_SIZE * sizeof(uint32_t));
	cudaMallocHost((void**)&t4_2, TABLE_SIZE * sizeof(uint32_t));
	cudaMallocHost((void**)&t4_3, TABLE_SIZE * sizeof(uint32_t));
	cudaMallocHost((void**)&pret3, pret3Size * sizeof(uint32_t));
	cudaMallocHost((void**)&pret2, pret2Size * sizeof(uint32_t));
	cudaMalloc((void**)&dt0, TABLE_SIZE * sizeof(uint32_t));
	cudaMalloc((void**)&dt1, TABLE_SIZE * sizeof(uint32_t));
	cudaMalloc((void**)&dt2, TABLE_SIZE * sizeof(uint32_t));
	cudaMalloc((void**)&dt3, TABLE_SIZE * sizeof(uint32_t));
	cudaMalloc((void**)&dt4, TABLE_SIZE * sizeof(uint32_t));
	cudaMalloc((void**)&dt4_0, TABLE_SIZE * sizeof(uint32_t));
	cudaMalloc((void**)&dt4_1, TABLE_SIZE * sizeof(uint32_t));
	cudaMalloc((void**)&dt4_2, TABLE_SIZE * sizeof(uint32_t));
	cudaMalloc((void**)&dt4_3, TABLE_SIZE * sizeof(uint32_t));
	cudaMalloc((void**)&dev_pret3, pret3Size * sizeof(uint32_t));
	cudaMalloc((void**)&dev_pret2, pret2Size * sizeof(uint32_t));
	cudaMallocManaged(&SAES_d, 256 * sizeof(uint8_t));
	for (int i = 0; i < TABLE_SIZE; i++) {
		t0[i] = T0[i];	t1[i] = T1[i];	
		t2[i] = T2[i];	t3[i] = T3[i];	t4[i] = T4[i];
		t4_0[i] = T4_0[i];		t4_1[i] = T4_1[i];
		t4_2[i] = T4_2[i];		t4_3[i] = T4_3[i];
	}
	for (int i = 0; i < 256; i++) SAES_d[i] = SAES[i]; 
	for (int i = 0; i < msgSize; i++) inBuf[i] = i;

	//plaintext for test vector, FIPS-197 0x00112233445566778899AABBCCDDEEFF
	//key 0x000102030405060708090a0b0c0d0e0f
	//ciphertext shoud be 0x69c4e0d86a7b0430d8cdb78070b4c55a
	// counter[0] = 0x00112233;
	// counter[1] = 0x44556677;
	// counter[2] = 0x8899AABB;
	// counter[3] = 0xCCDDEEFF;
	//Test for correctness
	//AES_128_encrypt(outBuf, (uint32_t *)m_EncryptKey, counter);
	//printf("Input data :   ");
	//printf("%x%x%x%x\n", counter[0], counter[1], counter[2], counter[3]);
	//printf("Output data :   ");
	//printf("%x%x%x%x\n", outBuf[0], outBuf[1], outBuf[2], outBuf[3]);
	//printf("\nMessage size: %d Bytes", msgSize*4);
	// Create an array of counter to encrypt
#ifdef DEBUG
	printf("\n|	Encryption in CPU: Started	|\n");
	
	for (int i = 0; i < msgSize / 4; i++)
	{
		// AES_128_encrypt_CTR(outBuf + 4 * i, (uint32_t*)m_EncryptKey, i, inBuf + 4 * i);
		AES_128_encrypt_CTR(outBuf + i, (uint32_t*)m_EncryptKey, i, inBuf + i);		
	}

	printf("\nOutput data (First 32 Bytes):   \n");
	printf("%x%x%x%x\n", outBuf[0], outBuf[1], outBuf[2], outBuf[3]);	
	printf("%x%x%x%x\n", outBuf[4], outBuf[5], outBuf[6], outBuf[7]);

	printf("\n|	Encryption in GPU: Started	|\n");
#endif
		
	//	 For GPU version, we do not pass in the counter array, because we can use the threadIdx as counter value for free!
		cudaMemset(dev_outBuf, 0, msgSize * sizeof(uint32_t));
		for(int i=0; i<msgSize; i++)	gpuBuf[i] = 0;

		 //Coarse grain -  One T-box
		for(int i=0; i<ITERATION; i++)
		{
			cudaMemcpy(dev_rk, m_EncryptKey, 60 * sizeof(uint32_t), cudaMemcpyHostToDevice);
			cudaMemcpy(dev_inBuf, inBuf, msgSize*sizeof(uint32_t), cudaMemcpyHostToDevice);
			cudaMemcpy(dt0, t0, TABLE_SIZE * sizeof(uint32_t), cudaMemcpyHostToDevice);
			cudaMemcpy(dt1, t1, TABLE_SIZE * sizeof(uint32_t), cudaMemcpyHostToDevice);	
			cudaMemcpy(dt2, t2, TABLE_SIZE * sizeof(uint32_t), cudaMemcpyHostToDevice);
			cudaMemcpy(dt3, t3, TABLE_SIZE * sizeof(uint32_t), cudaMemcpyHostToDevice);						
			cudaMemcpy(dt4_0, t4_0, TABLE_SIZE * sizeof(uint32_t), cudaMemcpyHostToDevice);
			cudaMemcpy(dt4_1, t4_1, TABLE_SIZE * sizeof(uint32_t), cudaMemcpyHostToDevice);
			cudaMemcpy(dt4_2, t4_2, TABLE_SIZE * sizeof(uint32_t), cudaMemcpyHostToDevice);
			cudaMemcpy(dt4_3, t4_3, TABLE_SIZE * sizeof(uint32_t), cudaMemcpyHostToDevice);
			cudaMemcpy(dev_pret2, pret2, pret2Size*sizeof(uint32_t), cudaMemcpyHostToDevice);			
			cudaMemcpy(dev_pret3, pret3, pret3Size*sizeof(uint32_t), cudaMemcpyHostToDevice);				
			
			cudaEventRecord(start);
			for (int i = 0; i < msgSize / 4; i+=16777216)
				AES_128_encrypt_CTR_pret3(outBuf + i, (uint32_t*)m_EncryptKey, i, inBuf + i, pret2, pret3);		
			for (int i = 0; i < msgSize / 4; i+=65536)
				AES_128_encrypt_CTR_pret2(outBuf + i, (uint32_t*)m_EncryptKey, i, inBuf + i, pret2, pret3);		
			OneTblBytePermReuseUnroll<<<gridSize/REPEAT, threadSize>>>(dev_outBuf, dev_rk, dt0, dev_inBuf, dev_pret2, dev_pret3); // fastest
			// OneTblBytePermOri<<<gridSize, threadSize>>>(dev_outBuf, dev_rk, dt0, dt4_0, dt4_1, dt4_2, dt4_3, dev_inBuf); // faster
			// OneTblBytePermSBoxOri << <gridSize, threadSize>> > (dev_outBuf, dev_rk, t0, t4, SAES_d, dev_inBuf);		// slow
			// OneTblBytePermSBoxComb << <gridSize, threadSize>> > (dev_outBuf, dev_rk, t0, t4, SAES_d, dev_inBuf);	// slow			
			cudaEventSynchronize(stop);
			cudaEventRecord(stop);
			cudaMemcpy(gpuBuf, dev_outBuf, msgSize*sizeof(uint32_t), cudaMemcpyDeviceToHost);
			cudaEventElapsedTime(&miliseconds, start, stop);
			kernelSpeed2 += 8*(4*(msgSize/1024)) / (miliseconds);
		}
		printf("\nAES GPU (one-T): %u MB of data. Kernel: %.4f [Gbps]\n", 4*(msgSize/1024/1024), kernelSpeed2/1024/ITERATION);
		printf("GPU (one-T) Output data (First 32 Bytes):   \n");
		printf("%x%x%x%x\n", gpuBuf[0], gpuBuf[1], gpuBuf[2], gpuBuf[3]);
		printf("%x%x%x%x\n", gpuBuf[4], gpuBuf[5], gpuBuf[6], gpuBuf[7]);

#ifdef DEBUG
	for (int i = 0; i < msgSize; i++)
	{
		if (gpuBuf[i] != outBuf[i])
		{
			printf("AES wrong at %d gpu: %x cpu: %x\n", i, gpuBuf[i], outBuf[i]);
			return;
		}
	}
	printf("The results in CPU and GPU match!\n");
#endif
}

int main(int argc, char** argv)
{
	int i, j;
	char* user_key = (char*) malloc(16*sizeof(char));
	printf("<------ TESTING AES-128 CTR Mode ------>\n");

	if(argc==1)
	{
		printf("Use Default Key:\n");
		//key for test vector, FIPS-197 0x000102030405060708090A0B0C0D0E0F
		for(j=0; j<16; j++) user_key[j] = j;
	}
	else if(argc==2)
	{
		printf("New User Key:\n");
		strcpy(user_key, argv[1]);
  		for(j=0; j<16; j++) printf("%c ", user_key[j]);
  	}
  	else
  	{
  		printf("Wrong Arguments!\n");
  		return 0;
  	}


	cudaSharedMemConfig pConfig;
	cudaDeviceSetSharedMemConfig(cudaSharedMemBankSizeEightByte);// Avoid bank conflict for 64 bit access. 
	cudaDeviceGetSharedMemConfig(&pConfig);
	//printf("Share mem config: %d\n", pConfig);
	cudaDeviceSetCacheConfig(cudaFuncCachePreferNone);
	cudaDeviceProp deviceProp;
	cudaGetDeviceProperties(&deviceProp, 0);
	printf("\nGPU Compute Capability = [%d.%d], clock: %d asynCopy: %d MapHost: %d SM: %d\n",
		deviceProp.major, deviceProp.minor, deviceProp.clockRate, deviceProp.asyncEngineCount, deviceProp.canMapHostMemory, deviceProp.multiProcessorCount);
	printf("msgSize: %lu MB\t counter blocks: %u M Block\n", msgSize * 4 / 1024 / 1024, msgSize / 1024 / 1024);
	printf("%u blocks and %u threads\n", gridSize, threadSize);
	testAES(user_key);
	// cudaDeviceReset must be called before exiting in order for profiling and tracing tools such as Nsight and Visual Profiler to show complete traces.
	cudaDeviceReset();


	return 0;

}
