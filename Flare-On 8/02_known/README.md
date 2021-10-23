# Flare-On 8, Challenge 2, known

## Task

We need your help with a ransomware infection that tied up some of our critical files. Good luck.

## Files

Filename | Size | SHA256
--- | --- | ---
UnlockYourFiles.exe | 6,144 bytes | 435366bfc2e8aff17ff107bf1274b7dca0b189be54e7251aa192ec8e73064424
Files\capa.png.encrypted | 10,565 bytes | 0418b3bdf8c3ef240a3e4e0b10c5a3d5d23e8f970dd92a90bd64b80a1e415af9
Files\cicero.txt.encrypted | 1,712 bytes | 68eded545fd661e31f2749983f2b94bfc67e85d204ab1d15e46be142667bc209
Files\commandovm.gif.encrypted | 49,071 bytes | 1b43fee0d0f931acb683f555dd7321fbbfb9fee071dfefd0c01615c7c101dbf9
Files\critical_data.txt.encrypted | 64 bytes | d24a3044906542caeb5b9353f87c4ff831dfb50845589ba1de2c71b0a98de79b
Files\flarevm.jpg.encrypted | 26,658 bytes | 7644e4d6fbade684dd6f3cf94599a7b2bdf90257a5d2d2b68ba4615dbb11802d
Files\latin_alphabet.txt.encrypted | 26 bytes | 5d6f1f04c40b2a46876c553ec18df7aea6923eaa0cbb9082f12b20f2cc111dd7

## High Level Summary

- UnlockYourFiles.exe seems to be a decrypting tool for the files that have been encrypted in the directory **Files/**.
- The decryption function applies ROL, XOR and SUB index on each byte (`p[i] = ROL(key[i] ^ c[i], i) - i`) in blocks of eight byte, which is the key length.
- The key can be recovered through known plaintext attacks (e.g. latin_alphabet is likely to contain upper- or lowercase alphabet a-z, PNG and JPG headers begin with >= 8 bytes magic header).
- One solution is to take the first 8 magic bytes of a plaintext JPG header (`b"\xFF\xD8\xFF\xE0\x00\x10\x4A\x46"`).
- Dissolving the decryption formula to key[i] (`key[i] = ROR(p[i] + i, i) ^ c[i]`) yields the key `No1Trust`.
- The flag is found in the decrypted file critial_data.txt as `You_Have_Awakened_Me_Too_Soon_EXE@flare-on.com`.
