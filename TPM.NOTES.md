



OVMF log:
```
0000: 43616C6C696E6720454649204170706C69636174696F6E2066726F6D20426F6F
0020: 74204F7074696F6E
  Event:
    PCRIndex  - 4
    EventType - 0x80000003
    DigestCount: 0x00000002
      HashAlgo : 0x0004
      Digest(0): 2B 94 C3 30 95 80 DC 03 C0 12 1C 8B EF B5 7E 76 FE 0E 6A 2F
      HashAlgo : 0x000B
      Digest(1): 78 6E AA A8 C6 2B 2A 77 8E 4B EC AC 87 30 77 7F 0D 6C 8A E7 BB 0B 9F 2B E7 81 AC DC 60 70 2C 5B
```

python:
```
filenames = {
   'image': '/nix/store/c7pavvr3v6d8gv9220n1qf0adyal8c1j-netboot.efi/linux.efi',
#   'ovmf': '/run/libvirt/nix-ovmf/OVMF_CODE.fd',
}

for name, filename in filenames.items():
    print("=== %s ===" % name)
    h = hash_pecoff(filename)
    print("=== generic ===")
    for alg, v in h['generic'].items():
        print((alg, v.hex()))
    print("=== authentihash ===")
    for alg, v in h['authentihash'].items():
        print((alg, v.hex()))
```
```
=== image ===
=== generic ===
('sha1', '4b37e108ea8b0c1245be071cc1a4c3e3b22b7f7b')
('sha256', '645eb65eee5c15f7bbbab7fe295908879463b849a2c4b192f0ac98a6a822ac02')
=== authentihash ===
('sha1', '2b94c3309580dc03c0121c8befb57e76fe0e6a2f')
('sha256', '786eaaa8c62b2a778e4becac8730777f0d6c8ae7bb0b9f2be781acdc60702c5b')
```

get eventlog, get it signed

https://tpm2-software.github.io/2020/06/12/Remote-Attestation-With-tpm2-tools.html

