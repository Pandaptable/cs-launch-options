#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdlib>
#include <cuda_runtime.h>
#include <climits>

#define STRINGTOKEN_MURMURHASH_SEED 0x31415926
#define MAX_TARGETS 64
#define MAX_STRING_LEN 256

__constant__ char PREFIXES[2] = {'-', '+'};
__constant__ char CHARS[38] = "abcdefghijklmnopqrstuvwxyz0123456789_";
__constant__ uint32_t d_targets[MAX_TARGETS];
__constant__ int d_num_targets;

struct MatchResult
{
	char str[MAX_STRING_LEN];
	uint32_t hash;
	int len;
};

__device__ int d_match_count = 0;
__device__ MatchResult d_matches[1024];

__device__ uint32_t murmur_hash2_device(const unsigned char *key, int len, uint32_t seed)
{
	const uint32_t m = 0x5bd1e995;
	const int r = 24;
	uint32_t h = seed ^ len;

	int i = 0;
	while (len >= 4)
	{
		uint32_t k = key[i] | (key[i + 1] << 8) | (key[i + 2] << 16) | (key[i + 3] << 24);
		k *= m;
		k ^= k >> r;
		k *= m;

		h *= m;
		h ^= k;

		i += 4;
		len -= 4;
	}

	switch (len)
	{
	case 3:
		h ^= key[i + 2] << 16;
	case 2:
		h ^= key[i + 1] << 8;
	case 1:
		h ^= key[i];
		h *= m;
	}

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}

__global__ void bruteforce_kernel(int length, unsigned long long offset, unsigned long long total_combinations)
{
	unsigned long long idx = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x + offset;

	if (idx >= total_combinations)
		return;

	unsigned char buf[MAX_STRING_LEN];

	buf[0] = PREFIXES[idx % 2];
	unsigned long long temp = idx / 2;

	for (int i = 1; i < length; i++)
	{
		buf[i] = CHARS[temp % 37];
		temp /= 37;
	}

	uint32_t h = murmur_hash2_device(buf, length, STRINGTOKEN_MURMURHASH_SEED);

	for (int i = 0; i < d_num_targets; ++i)
	{
		if (h == d_targets[i])
		{
			int index = atomicAdd(&d_match_count, 1);
			if (index < 1024)
			{
				for (int c = 0; c < length; ++c)
				{
					d_matches[index].str[c] = buf[c];
				}
				d_matches[index].str[length] = '\0';
				d_matches[index].hash = h;
				d_matches[index].len = length;
			}
		}
	}
}

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		std::cerr << "Usage: " << argv[0] << " <hash1> [hash2 ...]\n";
		return 1;
	}

	std::vector<uint32_t> host_targets;
	for (int i = 1; i < argc; ++i)
	{
		if (host_targets.size() >= MAX_TARGETS)
		{
			std::cerr << "Warning: Maximum of " << MAX_TARGETS << " targets allowed.\n";
			break;
		}
		host_targets.push_back(std::stoul(argv[i], nullptr, 0));
	}

	int num_targets = host_targets.size();

	cudaMemcpyToSymbol(d_targets, host_targets.data(), num_targets * sizeof(uint32_t));
	cudaMemcpyToSymbol(d_num_targets, &num_targets, sizeof(int));

	std::ofstream out_file("found_hashes.txt", std::ios::app);
	if (!out_file.is_open())
	{
		std::cerr << "Failed to open output file.\n";
		return 1;
	}

	int threadsPerBlock = 256;
	unsigned long long batch_size = 256ULL * 1024 * 1024;

	int length = 2;
	while (true)
	{
		unsigned long long total_combinations = 2;
		bool overflow = false;
		for (int i = 1; i < length; i++)
		{
			if (ULLONG_MAX / 37 < total_combinations)
			{
				overflow = true;
				break;
			}
			total_combinations *= 37;
		}

		if (overflow)
		{
			std::cerr << "\nReached maximum logical limits.\n";
			break;
		}

		std::cerr << "\n--- Checking Length " << length << " (" << total_combinations << " combinations) ---\n";

		for (unsigned long long offset = 0; offset < total_combinations; offset += batch_size)
		{

			double current_progress = ((double)offset / (double)total_combinations) * 100.0;

			fprintf(stderr, "\rLength %d Progress: %.2f%%", length, current_progress);

			unsigned long long current_batch = std::min(batch_size, total_combinations - offset);
			int blocksPerGrid = (current_batch + threadsPerBlock - 1) / threadsPerBlock;

			bruteforce_kernel<<<blocksPerGrid, threadsPerBlock>>>(length, offset, total_combinations);
			cudaDeviceSynchronize();

			int match_count = 0;
			cudaMemcpyFromSymbol(&match_count, d_match_count, sizeof(int));

			if (match_count > 0)
			{
				MatchResult *host_matches = new MatchResult[match_count];
				cudaMemcpyFromSymbol(host_matches, d_matches, match_count * sizeof(MatchResult));

				for (int i = 0; i < match_count; i++)
				{
					std::string found_str(host_matches[i].str);

					std::cerr << "\n[+] MATCH FOUND: " << found_str << std::endl;

					if (found_str[0] == '-' || found_str[0] == '+')
					{
						out_file << found_str << " = " << host_matches[i].hash << "\n";
						out_file.flush();
					}
				}
				delete[] host_matches;

				int zero = 0;
				cudaMemcpyToSymbol(d_match_count, &zero, sizeof(int));
			}
		}
		length++;
	}

	out_file.close();
	return 0;
}