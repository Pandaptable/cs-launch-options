# cs2 launch option reversal

`hashes.txt` is the up to date list of launch option <-> hashes

`launch-options.txt` is a compiled version of every launch option i could find, from source 1, and previous depots before launch options were hashed.

`launch-options-plus.txt` is the same, just for ones beginning with `+` (very few have special logic, but some do)

for the above i made the below bash script to check the lists automatically against the file
```bash
mc () {
    local input_file="$1"
    [[ ! -f "$input_file" ]] && echo "Input file not found" && return 1

    while IFS= read -r opt || [[ -n "$opt" ]]; do
        # Clean the input option (remove Windows line endings)
        opt=$(echo "$opt" | tr -d '\r')
        [[ -z "$opt" ]] && continue

        # Get the hash for this option
        local hash
        hash=$(./murmur-check.exe "$opt" | tr -d '\r')

        # Use sed to update hashes.txt in-place.
        # It only matches lines that are EXACTLY the hash (to avoid double-prefixing).
        # The | delimiter is used in case the option contains slashes.
        sed -i "s|^$hash\r*$|$opt, $hash|" hashes.txt
    done < "$input_file"
}
```

`murmur-check.exe` is just an implementation of below to easily check the hash of a launch option (lost source code)
```cpp
#include "hash.hpp"
#include <bit>
#include <cstdint>

uint32_t MurmurHash2(const void *key, int len, uint32_t seed)
{
    const uint32_t m = 0x5bd1e995;
    const int      r = 24;

    uint32_t             h    = seed ^ len;
    const unsigned char *data = (const unsigned char *)key;
    while (len >= 4)
    {
        uint32_t k = *(uint32_t *)data;
        if constexpr (std::endian::native != std::endian::little)
            k = std::byteswap(k);

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


inline uint32_t CalculateStringHashOptimizedAlreadyLowercase(const std::string_view str)
{
    static constexpr uint32_t STRINGTOKEN_MURMURHASH_SEED = 0x31415926;
    return MurmurHash2(str.data(), str.size(), STRINGTOKEN_MURMURHASH_SEED);
}
```

`cuda-code.exe` is a brute forcer, originally written and then vibecoded to cuda with gemini

`word-list.txt` is for use with hashcat brute forcing, no proper script for hashcat usage but we did find a few with it

`hashcat.patch` is a patch for hashcat to implement mmh2 32bit into it (it just replaces mmh1, so `hashcat -m 25700 -a 0` is the usage)

in `find-hashes` you can find a vibecoded rust snippet to check a dll for hashed command line arguments (somehow it always finds everything)

in `hashcat-auto` it's the python script to automatically use hashcat specifically for launch options, could be better tho