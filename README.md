# cs2 launch option reversal


`launch-options.txt` is a compiled version of every launch option i could find, from source 1, and previous depots from deadlock and CS2.

`launch-options-plus.txt` are + launch options that *seem* viable to exist (+ some actually existing ones)

`launch-options-deadlock.txt` is basically just launch options parsed from https://github.com/SteamTracking/GameTracking-Deadlock

`launch-options-cs2.txt` is same as above, + known ones

`murmur-check` folder is just an implementation of the hashing that valve uses to easily check the hash of a launch option

```
>mmc.exe meow a
3158276541: meow
516911585: a
```

`bruteforce` has a character bruteforcer, not realistic to run any more than like 9-10 characters, but we did find some from it.

`word-list.txt` is for use with hashcat brute forcing, no proper script for hashcat usage but we did find a few with it

`hashcat.patch` is a patch for hashcat to implement mmh2 32bit into it (it just replaces mmh1, so `hashcat -m 25700 -a 0` is the usage)

in `find-hashes` you can find a vibecoded rust snippet to check a dll for hashed command line arguments (somehow it always finds everything there are a *couple* false matches... `7` is an example of a hash that doesn't actually map to a launch option.. have to look into it at some point:tm:)

`mc.py` is for use with `launch-options.txt` and the output of `find-hashes`