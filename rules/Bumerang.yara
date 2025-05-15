/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpa7ypwey9
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Bumerang {
   meta:
      description = "tmpa7ypwey9 - file Bumerang.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "706fce69fea67622b03fafb51ece076c1fdd38892318f8cce9f2ec80aabca822"
   strings:
      $s1 = "$Info: Bumerang  is packed with the UPX executable packer http://upx.tsx.org $" fullword ascii /* score: '18.00'*/
      $s2 = "KERNELDLL" fullword ascii /* score: '11.50'*/
      $s3 = "GetLa>Ag" fullword ascii /* score: '9.00'*/
      $s4 = "Closed|Mh_" fullword ascii /* score: '7.00'*/
      $s5 = "me error" fullword ascii /* score: '6.00'*/
      $s6 = "$Id: UPX 1.02 Copyright (C) 1996-2000 the UPX Team. All Rights Reserved. $" fullword ascii /* score: '6.00'*/
      $s7 = "[p@gram Jm6" fullword ascii /* score: '4.00'*/
      $s8 = "WideCharIlu" fullword ascii /* score: '4.00'*/
      $s9 = "ablto iniValiz" fullword ascii /* score: '4.00'*/
      $s10 = "ugh spac#f{lowi8" fullword ascii /* score: '4.00'*/
      $s11 = "p32Snapshot" fullword ascii /* score: '4.00'*/
      $s12 = "essageBoxA_$" fullword ascii /* score: '4.00'*/
      $s13 = "CommT[" fullword ascii /* score: '4.00'*/
      $s14 = "hgiMr:fPv" fullword ascii /* score: '4.00'*/
      $s15 = "qRtlUnw" fullword ascii /* score: '4.00'*/
      $s16 = "[SeOdHand" fullword ascii /* score: '4.00'*/
      $s17 = "d$AWD/ARichTD/A" fullword ascii /* score: '4.00'*/
      $s18 = "FJUORueE" fullword ascii /* score: '4.00'*/
      $s19 = "8argu(sX" fullword ascii /* score: '4.00'*/
      $s20 = "FileBufft" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      8 of them
}

