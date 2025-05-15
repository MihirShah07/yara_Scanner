/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp9zg3p1lk
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Sasser_A {
   meta:
      description = "tmp9zg3p1lk - file Sasser.A.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "b2fa6edaa5ffc51d12150424355a0c86ac9f46d7ec772d35ab8d9f4fe7996d91"
   strings:
      $x1 = "echo off&echo open %s 5554>>cmd.ftp&echo anonymous>>cmd.ftp&echo user&echo bin>>cmd.ftp&echo get %i_up.exe>>cmd.ftp&echo bye>>cm" ascii /* score: '35.00'*/
      $x2 = "d.ftp&echo on&ftp -s:cmd.ftp&%i_up.exe&echo off&del cmd.ftp&echo on" fullword ascii /* score: '32.00'*/
      $s3 = "echo off&echo open %s 5554>>cmd.ftp&echo anonymous>>cmd.ftp&echo user&echo bin>>cmd.ftp&echo get %i_up.exe>>cmd.ftp&echo bye>>cm" ascii /* score: '27.00'*/
      $s4 = "c:\\win.log" fullword ascii /* score: '22.00'*/
      $s5 = "avserve.exe" fullword ascii /* score: '22.00'*/
      $s6 = "er32.dll" fullword ascii /* score: '20.00'*/
      $s7 = "C:\\TRABAJO\\A.EX" fullword ascii /* score: '13.00'*/
      $s8 = "brary %s.Qor" fullword ascii /* score: '10.00'*/
      $s9 = "avserve" fullword ascii /* score: '8.00'*/
      $s10 = "#%s could not b" fullword ascii /* score: '7.00'*/
      $s11 = "\\\\192.168.1.210\\IPC$" fullword wide /* score: '7.00'*/
      $s12 = "dinal %d" fullword ascii /* score: '4.00'*/
      $s13 = "\"WWSh(o@" fullword ascii /* score: '4.00'*/
      $s14 = "Entry Point No" fullword ascii /* score: '4.00'*/
      $s15 = "VWuBhdT@" fullword ascii /* score: '4.00'*/
      $s16 = "edure e#p" fullword ascii /* score: '4.00'*/
      $s17 = " dynamic link li`" fullword ascii /* score: '4.00'*/
      $s18 = "Jobaka3l" fullword ascii /* score: '4.00'*/
      $s19 = "ernel\"Exit+@P" fullword ascii /* score: '4.00'*/
      $s20 = "YZqvgff" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

