/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpgt3xdr6n
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpgt3xdr6n_Avoid {
   meta:
      description = "tmpgt3xdr6n - file Avoid.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "3ac8cc58dcbceaec3dab046aea050357e0e2248d30b0804c738c9a5b037c220d"
   strings:
      $s1 = "avoid.exe" fullword wide /* score: '22.00'*/
      $s2 = "www.rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s3 = "RJLLOGO" fullword wide /* score: '11.50'*/
      $s4 = "a!%i-1uEI" fullword ascii /* score: '6.50'*/
      $s5 = "ToUKhN6" fullword ascii /* score: '5.00'*/
      $s6 = "dpoXSROGGSIIQ0" fullword ascii /* score: '5.00'*/
      $s7 = "J -&ZK" fullword ascii /* score: '5.00'*/
      $s8 = "cpomdc" fullword ascii /* score: '5.00'*/
      $s9 = "jlhgkc" fullword ascii /* score: '5.00'*/
      $s10 = "fsZLvC4" fullword ascii /* score: '5.00'*/
      $s11 = "+ esv+" fullword ascii /* score: '5.00'*/
      $s12 = "jbJRi\"" fullword ascii /* score: '4.00'*/
      $s13 = "NoPGeH]" fullword ascii /* score: '4.00'*/
      $s14 = "wC.seE>" fullword ascii /* score: '4.00'*/
      $s15 = "mHWx>BW" fullword ascii /* score: '4.00'*/
      $s16 = "[NiOPiQZrYSiT" fullword ascii /* score: '4.00'*/
      $s17 = "fSKz`4TPT" fullword ascii /* score: '4.00'*/
      $s18 = "(lfEaTUQI%<" fullword ascii /* score: '4.00'*/
      $s19 = "TDLksrTF" fullword ascii /* score: '4.00'*/
      $s20 = "eSGuW\\G" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

