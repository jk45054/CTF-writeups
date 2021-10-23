# Flare-On 8, Challenge 6, PetTheKitty

## Task

Hello,

Recently we experienced an attack against our super secure MEOW-5000 network. Forensic analysis discovered evidence of the files PurrMachine.exe and PetTheKitty.jpg; however, these files were ultimately unrecoverable. We suspect PurrMachine.exe to be a downloader and do not know what role PetTheKitty.jpg plays (likely a second-stage payload). Our incident responders were able to recover malicious traffic from the infected machine. Please analyze the PCAP file and extract additional artifacts.

Looking forward to your analysis, ~Meow

## Files

Filename | Size | SHA256
--- | --- | ---
IR_PURRMACHINE.pcapng | 709,108 bytes | 14FA7D5F7359E4F09756ACB1C46734E893411E0792C9D72B359B0BE7375984E5
README.txt | 565 bytes | 366A26474E986494F9E400E8449FD08A32DD9A02BED9A05A15CA83A78AD6831E

## High Level Summary

- The pcapng file contains two TCP streams
  - Stream 0 contains two file transfers using the custom network file transfer protocol `ME0W`.
    - File transfer 1 is requested in packet #6 `MeeooowwwMeme`, which is a 664,784 bytes sized PNG file including an ASCII art overlay of 363 bytes.
    - File transfer 2 is requested in packet #54 `MeeeeeooooowwWare`, which is a 10,673 bytes sized (Microsoft Windows delta-) patch file.
    - Applying the delta patch **MeeeeeooooowwWare** to the PNG file **MeeooowwwMeme** yields the 1,438,208 bytes sized next stage implant (32 Bit Windows PE DLL).
    - This DLL implant uses `CreateDeltaB()` and `ApplyDeltaB()` in combination with an XOR cipher (key `meoow`) to communicate with is C2 server.
  - Stream 1 contains the following interactive remote (shell) command execution and their corresponding results.
    - Packet number #164 contains the flag **1m_H3rE_Liv3_1m_n0t_a_C4t@flare-on.com**, hidden in line 18 of a rick roll song text.
