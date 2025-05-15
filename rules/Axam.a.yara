/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpgt_qhae9
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpgt_qhae9_Axam_a {
   meta:
      description = "tmpgt_qhae9 - file Axam.a.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "4ae7d63ec497143c2acde1ba79f1d9eed80086a420b6f0a07b1e2917da0a6c74"
   strings:
      $s1 = "Axam.exe" fullword wide /* score: '22.00'*/
      $s2 = "M#VBA6.DLL" fullword ascii /* score: '17.00'*/
      $s3 = "WKERNEL32'" fullword ascii /* score: '9.00'*/
      $s4 = "VGetShortPathNeA" fullword ascii /* score: '9.00'*/
      $s5 = "C:\\Progr}" fullword ascii /* score: '7.00'*/
      $s6 = "ONextG9" fullword ascii /* score: '5.00'*/
      $s7 = "`.data," fullword ascii /* score: '5.00'*/
      $s8 = "Zkpkfa\\WXxk" fullword ascii /* score: '4.00'*/
      $s9 = "QueryInu" fullword ascii /* score: '4.00'*/
      $s10 = "WBgs02ac" fullword ascii /* score: '4.00'*/
      $s11 = "MFCwGFoa" fullword ascii /* score: '4.00'*/
      $s12 = "soft Visual Stu" fullword ascii /* score: '4.00'*/
      $s13 = "FcIsLQrst/" fullword ascii /* score: '4.00'*/
      $s14 = "rmhc^YT" fullword ascii /* score: '4.00'*/
      $s15 = "eToolhelpcSnaps\\2" fullword ascii /* score: '4.00'*/
      $s16 = "ZOJE@;6" fullword ascii /* score: '4.00'*/
      $s17 = " Files\\Mic" fullword ascii /* score: '4.00'*/
      $s18 = "r%Wr !\"Wr%W#$%%Wr%&'r%Wr()*Wr%W+,-%Wr%./r%Wr012Wr%W345%Wr%67r%Wr89:Wr%W;<=%Wr%>?r%Wr@ABWr%WCDE%Wr%FGr%WrHIJWr%WKLM%Wr%NOr%WrPQ" ascii /* score: '4.00'*/
      $s19 = "-D,Function8" fullword ascii /* score: '4.00'*/
      $s20 = "cN?]0;" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      8 of them
}

