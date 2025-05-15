/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp1b7mtdew
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp1b7mtdew_Winevar {
   meta:
      description = "tmp1b7mtdew - file Winevar.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "e68ebecd17bb8e91079bd4fe9bd24059a2bc007b4baac477127eda7c5d5c6706"
   strings:
      $s1 = "http://www.sex.com/" fullword ascii /* score: '17.00'*/
      $s2 = "VjAjTjAjD" fullword ascii /* base64 encoded string 'V0#N0#' */ /* score: '14.00'*/
      $s3 = "Symantec Microsoft Corp0\\0" fullword ascii /* score: '6.00'*/
      $s4 = "%c%c%c%c%s" fullword ascii /* score: '5.00'*/
      $s5 = "n, 25 Nov 2002 16:05:48 Elena Primorye >> [RUS] Mon, 25 Nov 2002 11:15:39 1 2 >> [RUS] Mon, 25 Nov 2002 14:40:53 Vika Krypton >>" ascii /* score: '4.00'*/
      $s6 = "Mh^kmVfXVFaZhdgb`mT;WiU9[\\lfhn" fullword ascii /* score: '4.00'*/
      $s7 = "lekfhjV" fullword ascii /* score: '4.00'*/
      $s8 = " [RUS] Mon, 25 Nov 2002 15:01:14 Zlodey ZloVNaeM >> [RUS] Mon, 25 Nov 2002 15:55:10 Manager Dixis >> [RUS] Tue, 26 Nov 2002 15:0" ascii /* score: '4.00'*/
      $s9 = "0uNVjTjIjUjQ" fullword ascii /* score: '4.00'*/
      $s10 = "`ridfhZk^fZkj" fullword ascii /* score: '4.00'*/
      $s11 = "VWuBhtEA" fullword ascii /* score: '4.00'*/
      $s12 = "\"WWSh,EA" fullword ascii /* score: '4.00'*/
      $s13 = "HtXHt!H" fullword ascii /* score: '4.00'*/
      $s14 = "HhTd<jX\\irq" fullword ascii /* score: '4.00'*/
      $s15 = "\"%s\" ~~%d" fullword ascii /* score: '4.00'*/
      $s16 = "hsrm6*)pwv,puh[gtda+_jg(" fullword ascii /* score: '4.00'*/
      $s17 = "6:59 ADVERT smb >> [RUS] Wed, 27 Nov 2002 15:30:13 Masha OfisReklama >> " fullword ascii /* score: '4.00'*/
      $s18 = "`lqeqckmr" fullword ascii /* score: '4.00'*/
      $s19 = "SVWj@Z3" fullword ascii /* score: '4.00'*/
      $s20 = ">AVAR Ti-Virus Management Syste" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

