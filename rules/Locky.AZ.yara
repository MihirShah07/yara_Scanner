/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpa6z4xtfy
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Locky_AZ {
   meta:
      description = "tmpa6z4xtfy - file Locky.AZ.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "2e4319ff62c03a539b2b2f71768a0cfc0adcaedbcca69dbf235081fe2816248b"
   strings:
      $s1 = "kernel86.dll" fullword ascii /* score: '23.00'*/
      $s2 = "Alert.dll" fullword wide /* score: '23.00'*/
      $s3 = "David De Groot" fullword wide /* score: '7.00'*/
      $s4 = "ujberx" fullword ascii /* score: '5.00'*/
      $s5 = "QpiM})PW" fullword ascii /* score: '4.00'*/
      $s6 = "PVouE~6b6" fullword ascii /* score: '4.00'*/
      $s7 = "SkiN?!" fullword ascii /* score: '4.00'*/
      $s8 = "PqQC34 " fullword ascii /* score: '4.00'*/
      $s9 = "Bluefive software" fullword wide /* score: '4.00'*/
      $s10 = "Alert clock" fullword wide /* score: '4.00'*/
      $s11 = "\\p:DLT" fullword ascii /* score: '2.00'*/
      $s12 = "\\!ufu " fullword ascii /* score: '2.00'*/
      $s13 = "8 888F8[8f8" fullword ascii /* score: '1.00'*/
      $s14 = "ixo$w@j" fullword ascii /* score: '1.00'*/
      $s15 = "vLU1(u" fullword ascii /* score: '1.00'*/
      $s16 = "_u3873" fullword ascii /* score: '1.00'*/
      $s17 = "gd|/J`O)" fullword ascii /* score: '1.00'*/
      $s18 = ":PAa! Y" fullword ascii /* score: '1.00'*/
      $s19 = "aPP:9q" fullword ascii /* score: '1.00'*/
      $s20 = "V8X $U(" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

