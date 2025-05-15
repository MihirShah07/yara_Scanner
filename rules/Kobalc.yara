/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp3affw9wn
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp3affw9wn_Kobalc {
   meta:
      description = "tmp3affw9wn - file Kobalc.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "db6cea7e8d62d3b21efe3b423b48c131e345cb55f168cbe1f142e491bb812747"
   strings:
      $s1 = " Windows NET Runtime Optimization Service" fullword wide /* score: '10.00'*/
      $s2 = "Id:\"]R" fullword ascii /* score: '7.00'*/
      $s3 = "EhzW'*<Wst" fullword ascii /* score: '4.00'*/
      $s4 = ")ze.mnR" fullword ascii /* score: '4.00'*/
      $s5 = "jqHK){IT" fullword ascii /* score: '4.00'*/
      $s6 = "d<mHYvib*" fullword ascii /* score: '4.00'*/
      $s7 = "%QHkKy>;^/" fullword ascii /* score: '4.00'*/
      $s8 = "qmrw}.W" fullword ascii /* score: '4.00'*/
      $s9 = "`qytFRk2'" fullword ascii /* score: '4.00'*/
      $s10 = "QNuf\\b" fullword ascii /* score: '4.00'*/
      $s11 = "RSrN4$c" fullword ascii /* score: '4.00'*/
      $s12 = "{{u`8RVBPbn`" fullword ascii /* score: '4.00'*/
      $s13 = "qsqE?)" fullword ascii /* score: '4.00'*/
      $s14 = "TNDPF)\"" fullword ascii /* score: '4.00'*/
      $s15 = "\\M ^fI" fullword ascii /* score: '2.00'*/
      $s16 = "\\,nYME" fullword ascii /* score: '2.00'*/
      $s17 = "lhAls3" fullword ascii /* score: '2.00'*/
      $s18 = "ApjZ53" fullword ascii /* score: '2.00'*/
      $s19 = "?+:k0X" fullword ascii /* score: '1.00'*/
      $s20 = "J^(9D:" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

