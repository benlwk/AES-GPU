# AES-GPU
This repository contains the GPU implementation of AES-128 operating in CTR and ECB modes. The codes are verified on V100, T4 and RTX 3080, but they should work for all NVIDIA GPU architectures starting from Kepler onward.

# How to use
1) Edit the Makefile to choose your target GPU architecture. For RTX 3080, use -arch=sm_86; for V100, use -arch=sm_70; for T4, use -arch=sm_75; 
2) Compile the code on your termnial: 
#make
