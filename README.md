# cs2 launch option reversal


`launch-options.txt` is a compiled version of every launch option i could find, from source 1, and previous depots from deadlock and CS2 (add any new launch options found to this as well).

`murmur-check` folder is just an implementation of the hashing that valve uses to easily check the hash of a launch option

```
>mmc.exe meow a
3158276541: meow
516911585: a
```

`bruteforce` has a character bruteforcer, not realistic to run any more than like 9-10 characters, but we did find some from it.

`word-list.txt` is for use with hashcat brute forcing, no proper script for hashcat usage but we did find a few with it

`unmapped.txt` currently unknown hashes that need to be found.

`hashcat.patch` is a patch for hashcat to implement mmh2 32bit into it (it just replaces mmh1, so `hashcat -m 25700 -a 0` is the usage)

in `find-hashes` you can find a vibecoded rust snippet to check a dll for hashed command line arguments (somehow it always finds everything there are a *couple* false matches... `7` is an example of a hash that doesn't actually map to a launch option.. have to look into it at some point:tm:)

`mc.py` is for use with `launch-options.txt` and the output of `find-hashes`

I have a file up to 11 characters (10 character launch option) of hash collisions, if you want access to search through feel free to reach out.

it's **1.8 GB** lmfao (148873221 collisions)


other commands
```
# check count of unnmapped launch options
grep -hroE "^[0-9]+" ./hashes/cs2 | sort -u | wc -l

# output unmapped launch options to file
grep -hroE "^[0-9]+" ./hashes/cs2 | sort -u > unmapped.txt
```