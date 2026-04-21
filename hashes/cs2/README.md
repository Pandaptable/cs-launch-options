below is a list of launch options that for one reason or another aren't picked up, or were found because of previous false positives.

`-multiple_tools_instances` was found from the below ida psuedocode... i was matching a hash of `21` in `toolframework2.dll` which is just not true. 2993312251 is also not a hash.

```c
v3 = CommandLine();
v4 = *(__int64 (__fastcall **)(__int64, _QWORD))(*(_QWORD *)v3 + 32LL);
v5 = sub_18004E060("tiple_tools_instances", 21, 2993312251LL);
v6 = v4(v3, v5);
```

`-rtest1` is basically the same, was just found from the hash of `7` being falsely matched in both `rendersystemdx11.dll` and `rendersystemvulkan.dll`

```c
if ( GetGameInfoBool("NVNGX/ReflexLateWarp", 0)
||(v14 = CommandLine(),
	v15 = *(unsigned __int8 (__fastcall **)(__int64, _QWORD))(*(_QWORD *)v14 + 144LL),
	v16 = sub_180012300("-rtest1", 7, 826366241),
	v15(v14, v16)) )
```