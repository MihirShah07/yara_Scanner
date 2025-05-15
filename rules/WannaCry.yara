/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp1_0mmye4
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule WannaCry {
   meta:
      description = "tmp1_0mmye4 - file WannaCry.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "be22645c61949ad6a077373a7d6cd85e3fae44315632f161adc4c99d5a8e6844"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" />" fullword ascii /* score: '15.00'*/
      $s2 = "       <!-- Windows 7 -->" fullword ascii /* score: '12.00'*/
      $s3 = "       <!-- Windows 10 --> " fullword ascii /* score: '12.00'*/
      $s4 = "       <!-- Windows 8.1 -->" fullword ascii /* score: '12.00'*/
      $s5 = "       <!-- Windows Vista -->" fullword ascii /* score: '12.00'*/
      $s6 = "       <!-- Windows 8 -->" fullword ascii /* score: '12.00'*/
      $s7 = "            processorArchitecture=\"*\"" fullword ascii /* score: '10.00'*/
      $s8 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s9 = "            version=\"6.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s10 = "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" fullword ascii /* score: '7.00'*/
      $s11 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii /* score: '7.00'*/
      $s12 = "  </compatibility>" fullword ascii /* score: '7.00'*/
      $s13 = "WANNACRY" fullword ascii /* score: '6.50'*/
      $s14 = "PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii /* score: '6.50'*/
      $s15 = "PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii /* score: '6.50'*/
      $s16 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii /* score: '6.50'*/
      $s17 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii /* score: '6.50'*/
      $s18 = "            name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* score: '6.00'*/
      $s19 = " inflate 1.1.3 Copyright 1995-1998 Mark Adler " fullword ascii /* score: '6.00'*/
      $s20 = "s- Lz,'I" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

