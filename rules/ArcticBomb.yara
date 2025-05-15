/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmplicoiokg
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule ArcticBomb {
   meta:
      description = "tmplicoiokg - file ArcticBomb.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "322eb96fc33119d8ed21b45f1cd57670f74fb42fd8888275ca4879dce1c1511c"
   strings:
      $s1 = "okernel32.dll" fullword ascii /* score: '23.00'*/
      $s2 = "GetLongPathNameA&O" fullword ascii /* score: '9.00'*/
      $s3 = "Portions Copyright (c) 1+`" fullword ascii /* score: '9.00'*/
      $s4 = "qcomct" fullword ascii /* score: '8.00'*/
      $s5 = " O:\\wQ" fullword ascii /* score: '7.00'*/
      $s6 = "ThreadArray" fullword ascii /* score: '7.00'*/
      $s7 = "HotkeysJ0L" fullword ascii /* score: '7.00'*/
      $s8 = "ASTUVWXYZ" fullword ascii /* score: '6.50'*/
      $s9 = "$Id: UPX 1.06 Copyright (C) 1996-2001 the UPX Team. All Rights Reserved. $" fullword ascii /* score: '6.00'*/
      $s10 = "Inverflowy" fullword ascii /* score: '6.00'*/
      $s11 = "OwnerH8" fullword ascii /* score: '5.00'*/
      $s12 = "- x 4>P" fullword ascii /* score: '5.00'*/
      $s13 = "rfaced" fullword ascii /* score: '5.00'*/
      $s14 = "G%s_%d" fullword ascii /* score: '5.00'*/
      $s15 = "tifyEvemM" fullword ascii /* score: '4.00'*/
      $s16 = "SOFTWARE\\Borlan" fullword ascii /* score: '4.00'*/
      $s17 = "PurpleGTeal'v" fullword ascii /* score: '4.00'*/
      $s18 = "oRadioP" fullword ascii /* score: '4.00'*/
      $s19 = "nross&$" fullword ascii /* score: '4.00'*/
      $s20 = "ySTf+hTO" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

