# cs2 launch option reversal

`hashes.txt` is the up to date list of launch option <-> hashes

`launch-options.txt` is a compiled version of every launch option i could find, from source 1, and previous depots before launch options were hashed.

`launch-options-plus.txt` is the same, just for ones beginning with `+` (very few have special logic, but some do)

for the above i made the below bash script to check the lists automatically against the file
```bash
mc () {
	_process_output() {
		while IFS=':' read -r hash opt || [[ -n "$hash" ]]; do
			hash=$(echo "$hash" | tr -d ' \r ')
			opt=$(echo "$opt" | sed 's/^ //' | tr -d '\r')

			[[ -z "$hash" || -z "$opt" ]] && continue

			sed -i "s|^$hash\r*$|$opt, $hash|" hashes.txt
		done
	}

	if [[ "$1" == "-f" ]]; then
		local input_file="$2"
		[[ ! -f "$input_file" ]] && echo "Input file not found" && return 1

		xargs ./mmc.exe < "$input_file" | _process_output
	else
		./mmc.exe "$@" | _process_output
	fi
}
```

`murmur-check` folder is just an implementation of the hashing that valve uses to easily check the hash of a launch option

```
>mmc.exe meow a
3158276541: meow
516911585: a
```

`word-list.txt` is for use with hashcat brute forcing, no proper script for hashcat usage but we did find a few with it

`hashcat.patch` is a patch for hashcat to implement mmh2 32bit into it (it just replaces mmh1, so `hashcat -m 25700 -a 0` is the usage)

in `find-hashes` you can find a vibecoded rust snippet to check a dll for hashed command line arguments (somehow it always finds everything)

in `hashcat-auto` it's the python script to automatically use hashcat specifically for launch options, could be better tho

`deadlock.txt` is the same as `launch-options.txt` just gathered from https://github.com/SteamTracking/GameTracking-Deadlock string dumps instead of CS2 game tracking