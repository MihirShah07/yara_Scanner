/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp98pu_z2b
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule PowerPoint {
   meta:
      description = "tmp98pu_z2b - file PowerPoint.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "9c3f8df80193c085912c9950c58051ae77c321975784cc069ceacd4f57d5861d"
   strings:
      $s1 = "sqlhost.dll" fullword ascii /* score: '28.00'*/
      $s2 = "fucked-up-shit" fullword ascii /* score: '13.00'*/
      $s3 = "\\sys3.exe" fullword ascii /* score: '13.00'*/
      $s4 = "\\systm.txt" fullword ascii /* score: '12.00'*/
      $s5 = "onyzaehe" fullword ascii /* score: '8.00'*/
      $s6 = "vssssssssssa" fullword ascii /* score: '8.00'*/
      $s7 = "xaklkffxu" fullword ascii /* score: '8.00'*/
      $s8 = "kjefnfyk" fullword ascii /* score: '8.00'*/
      $s9 = "fkbonyn" fullword ascii /* score: '8.00'*/
      $s10 = "hhhhhlmm" fullword ascii /* score: '8.00'*/
      $s11 = "pRqwyyyyyyyyyyyyyyyyyyyyyyyyq" fullword ascii /* score: '7.00'*/
      $s12 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s13 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii /* score: '6.50'*/
      $s14 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s15 = "\\\\.\\PHYSICALDRIVE0" fullword ascii /* score: '6.00'*/
      $s16 = "dzsttz" fullword ascii /* score: '5.00'*/
      $s17 = "iinzyc" fullword ascii /* score: '5.00'*/
      $s18 = "fcmfnb" fullword ascii /* score: '5.00'*/
      $s19 = "zftyct" fullword ascii /* score: '5.00'*/
      $s20 = "jhjjlf" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

