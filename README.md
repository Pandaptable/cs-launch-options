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

check `murmur-check` folder now for source (newer version)

```
>main.exe meow a
3158276541: meow
516911585: a
```

`word-list.txt` is for use with hashcat brute forcing, no proper script for hashcat usage but we did find a few with it

`hashcat.patch` is a patch for hashcat to implement mmh2 32bit into it (it just replaces mmh1, so `hashcat -m 25700 -a 0` is the usage)

in `find-hashes` you can find a vibecoded rust snippet to check a dll for hashed command line arguments (somehow it always finds everything)

in `hashcat-auto` it's the python script to automatically use hashcat specifically for launch options, could be better tho

`deadlock.txt` is the same as `launch-options.txt` just gathered from https://github.com/SteamTracking/GameTracking-Deadlock string dumps instead of CS2 game tracking