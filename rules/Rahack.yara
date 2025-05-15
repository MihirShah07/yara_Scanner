/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp_k9na5f3
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp_k9na5f3_Rahack {
   meta:
      description = "tmp_k9na5f3 - file Rahack.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "400c72ef312e3b46fe417aa82d6691d18a07c0708e94b6fa7b47934909d3db7c"
   strings:
      $s1 = "iizYQDD" fullword ascii /* score: '4.00'*/
      $s2 = "CteVGH," fullword ascii /* score: '4.00'*/
      $s3 = "BIbk\\=>" fullword ascii /* score: '4.00'*/
      $s4 = "keRegisterWaitForSingleObjectEx" fullword ascii /* score: '4.00'*/
      $s5 = "daNeedCurrentDirectoryForExePathW" fullword ascii /* score: '4.00'*/
      $s6 = "CPepjyb|" fullword ascii /* score: '4.00'*/
      $s7 = "Mka!RkdyvM4B" fullword ascii /* score: '4.00'*/
      $s8 = "@jfonf05P" fullword ascii /* score: '4.00'*/
      $s9 = "F5.Wkc" fullword ascii /* score: '4.00'*/
      $s10 = "pzfq'=M" fullword ascii /* score: '4.00'*/
      $s11 = "]{ShZG8&k" fullword ascii /* score: '4.00'*/
      $s12 = "zKkP7.4d" fullword ascii /* score: '4.00'*/
      $s13 = "pDgzkWx" fullword ascii /* score: '4.00'*/
      $s14 = "ApNlsConvertIntegerToString" fullword ascii /* score: '4.00'*/
      $s15 = "gzqaS!" fullword ascii /* score: '4.00'*/
      $s16 = "eUHeapValidate" fullword ascii /* score: '4.00'*/
      $s17 = "dgs3333" fullword ascii /* score: '2.00'*/
      $s18 = "&t%Bw=n" fullword ascii /* score: '1.00'*/
      $s19 = ";9 |H1V" fullword ascii /* score: '1.00'*/
      $s20 = "NAy(~Sav" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

