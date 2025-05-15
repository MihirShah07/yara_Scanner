/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp33i40qcl
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp33i40qcl_MsWorld {
   meta:
      description = "tmp33i40qcl - file MsWorld.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "56511f0b28f28c23b5a1a3c7d524ee25a4c6df9ac2b53797c95199534f86bbd2"
   strings:
      $s1 = "C:\\Autoexec.bat" fullword wide /* score: '28.00'*/
      $s2 = "MissWrld.exe" fullword wide /* score: '22.00'*/
      $s3 = "http://www.macromedia.com" fullword ascii /* score: '21.00'*/
      $s4 = "Scripting.FileSystemObject" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s5 = "*\\AE:\\MANIYA\\Visual Basic\\Flash\\Flash.vbp" fullword wide /* score: '17.00'*/
      $s6 = "System.dat" fullword wide /* score: '17.00'*/
      $s7 = "F:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii /* score: '13.00'*/
      $s8 = " /q /autotest" fullword wide /* score: '12.00'*/
      $s9 = "GetNameSpace" fullword wide /* score: '9.00'*/
      $s10 = "GetDefaultFolder" fullword wide /* score: '9.00'*/
      $s11 = "GetSpecialFolder" fullword wide /* score: '9.00'*/
      $s12 = "Email1Address" fullword wide /* score: '7.00'*/
      $s13 = "System.da0" fullword wide /* score: '7.00'*/
      $s14 = "User.da0" fullword wide /* score: '7.00'*/
      $s15 = " Enjoy the latest pictures of Miss World from various Country" fullword wide /* score: '6.00'*/
      $s16 = "Project1" fullword ascii /* score: '5.00'*/
      $s17 = "Module1" fullword ascii /* score: '5.00'*/
      $s18 = "dPerObProject1" fullword ascii /* score: '5.00'*/
      $s19 = "This Everything for my Girl Friend........., (CatEyes, KRSSL, SS Hostel) " fullword wide /* score: '5.00'*/
      $s20 = "KXVO:wN+p05V" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

