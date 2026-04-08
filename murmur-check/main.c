#include <stdint.h>
#include <stdio.h>
#include <string.h>

inline uint32_t LittleDWord(uint32_t val)
{
	int test = 1;
	if (*(char *)&test == 1)
		return val;

	uint32_t temp;
	temp = *((uint32_t *)&val) >> 24;
	temp |= ((*((uint32_t *)&val) & 0x00FF0000) >> 8);
	temp |= ((*((uint32_t *)&val) & 0x0000FF00) << 8);
	temp |= ((*((uint32_t *)&val) & 0x000000FF) << 24);
	return temp;
}

#define STRINGTOKEN_MURMURHASH_SEED 0x31415926
uint32_t MurmurHash2(const void *key, int len, uint32_t seed)
{
	const uint32_t m = 0x5bd1e995;
	const int r = 24;

	uint32_t h = seed ^ len;
	const unsigned char *data = (const unsigned char *)key;
	while (len >= 4)
	{
		uint32_t k = LittleDWord(*(uint32_t *)data);
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

int main(int argc, char **argv)
{
	if (argc <= 1)
	{
		printf("Missing argument, each argument is MurMur2 hashed\n");
		return 1;
	}

	for (int i = 1; i < argc; i++)
	{
		uint32_t hash =
			MurmurHash2(argv[i], strlen(argv[i]), STRINGTOKEN_MURMURHASH_SEED);
		printf("%10u: %s\n", hash, argv[i]);
	}
	return 0;
}