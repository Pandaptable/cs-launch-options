#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cuda_runtime.h>
#define STRINGTOKEN_MURMURHASH_SEED 0x31415926
#define cudaCheckError(ans)                   \
	{                                         \
		gpuAssert((ans), __FILE__, __LINE__); \
	}
inline void gpuAssert(cudaError_t code, const char *file, int line, bool abort = true)
{
	if (code != cudaSuccess)
	{
		fprintf(stderr, "GPUassert: %s %s %d\n", cudaGetErrorString(code), file, line);
		if (abort)
			exit(code);
	}
}
__device__ uint32_t MurmurHash2_gpu(const void *key, int len, uint32_t seed)
{
	const uint32_t m = 0x5bd1e995;
	const int r = 24;
	uint32_t h = seed ^ len;
	const unsigned char *data = (const unsigned char *)key;
	while (len >= 4)
	{
		uint32_t k;
		// Use memcpy for unaligned loads on GPU
		memcpy(&k, data, sizeof(uint32_t));
		k *= m;
		k ^= k >> r;
		k *= m;
		h *= m;
		h ^= k;
		data += 4;
		len -= 4;
	}
	switch (len)
	{
	case 3:
		h ^= data[2] << 16;
	case 2:
		h ^= data[1] << 8;
	case 1:
		h ^= data[0];
		h *= m;
	};
	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;
	return h;
}
__global__ void MurmurHashKernel(const char *d_data, const int *d_offsets, const int *d_lens, uint32_t *d_results, int count, uint32_t seed)
{
	int idx = blockIdx.x * blockDim.x + threadIdx.x;
	if (idx < count)
	{
		d_results[idx] = MurmurHash2_gpu(&d_data[d_offsets[idx]], d_lens[idx], seed);
	}
}
int main(int argc, char **argv)
{
	if (argc <= 1)
	{
		printf("Usage: %s <string1> <string2> ...\n", argv[0]);
		return 1;
	}
	int count = argc - 1;

	int *h_lens = (int *)malloc(count * sizeof(int));
	int *h_offsets = (int *)malloc(count * sizeof(int));
	int total_chars = 0;
	for (int i = 0; i < count; i++)
	{
		h_lens[i] = (int)strlen(argv[i + 1]);
		h_offsets[i] = total_chars;
		total_chars += h_lens[i];
	}
	char *h_flat_strings = (char *)malloc(total_chars > 0 ? total_chars : 1);
	for (int i = 0; i < count; i++)
	{
		memcpy(&h_flat_strings[h_offsets[i]], argv[i + 1], h_lens[i]);
	}
	char *d_data;
	int *d_offsets, *d_lens;
	uint32_t *d_results;
	cudaCheckError(cudaMalloc(&d_data, total_chars > 0 ? total_chars : 1));
	cudaCheckError(cudaMalloc(&d_offsets, count * sizeof(int)));
	cudaCheckError(cudaMalloc(&d_lens, count * sizeof(int)));
	cudaCheckError(cudaMalloc(&d_results, count * sizeof(uint32_t)));
	cudaCheckError(cudaMemcpy(d_data, h_flat_strings, total_chars, cudaMemcpyHostToDevice));
	cudaCheckError(cudaMemcpy(d_offsets, h_offsets, count * sizeof(int), cudaMemcpyHostToDevice));
	cudaCheckError(cudaMemcpy(d_lens, h_lens, count * sizeof(int), cudaMemcpyHostToDevice));
	int threadsPerBlock = 256;
	int blocksPerGrid = (count + threadsPerBlock - 1) / threadsPerBlock;

	MurmurHashKernel<<<blocksPerGrid, threadsPerBlock>>>(d_data, d_offsets, d_lens, d_results, count, STRINGTOKEN_MURMURHASH_SEED);

	cudaCheckError(cudaGetLastError());
	cudaCheckError(cudaDeviceSynchronize());
	uint32_t *h_results = (uint32_t *)malloc(count * sizeof(uint32_t));
	cudaCheckError(cudaMemcpy(h_results, d_results, count * sizeof(uint32_t), cudaMemcpyDeviceToHost));
	for (int i = 0; i < count; i++)
	{
		printf("%10u: %s\n", h_results[i], argv[i + 1]);
	}
	free(h_lens);
	free(h_offsets);
	free(h_flat_strings);
	free(h_results);
	cudaFree(d_data);
	cudaFree(d_offsets);
	cudaFree(d_lens);
	cudaFree(d_results);
	return 0;
}