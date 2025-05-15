/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp5sxs_c_6
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Lentin_c {
   meta:
      description = "tmp5sxs_c_6 - file Lentin.c.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "50d60cd841a18b05e00ab4691fc1e30f6a099a65a58ba51080304205fbb0d666"
   strings:
      $x1 = "Command line: /S /Y /* /M /B /P /V /H /W=new.LOG d:\\new " fullword ascii /* score: '38.00'*/
      $x2 = "\\BUTTSN~1.ZIP/dump/BUTTSniff.dll" fullword ascii /* score: '31.00'*/
      $x3 = "~1\\WPC(WI~1.ZIP/WPC - WinCrash Password Cracker.exe" fullword ascii /* score: '31.00'*/
      $s4 = "d:\\new\\SCRIPT~1.EXE" fullword ascii /* score: '27.00'*/
      $s5 = "\\BUTTSN~1.ZIP/dump/BUTTSniff.exe" fullword ascii /* score: '26.00'*/
      $s6 = "d:\\new\\TOGETHER.EXE" fullword ascii /* score: '26.00'*/
      $s7 = "\\ASSSNI~1.ZIP/AssSniffer 1.0.1/settings.dll" fullword ascii /* score: '26.00'*/
      $s8 = "~1\\MUNGAW~1.ZIP/mbhttpbf.exe/BOOTLNG.DLL" fullword ascii /* score: '23.00'*/
      $s9 = "~1\\MUNGAW~1.ZIP/mbhttpbf.exe/OLEAUT32.DLL" fullword ascii /* score: '23.00'*/
      $s10 = "~1\\MUNGAW~1.ZIP/mbhttpbf.exe/SETUPLNG.DLL" fullword ascii /* score: '23.00'*/
      $s11 = "~1\\MUNGAW~1.ZIP/mbhttpbf.exe/ASYCFILT.DLL" fullword ascii /* score: '23.00'*/
      $s12 = "~1\\MUNGAW~1.ZIP/mbhttpbf.exe/OLEPRO32.DLL" fullword ascii /* score: '23.00'*/
      $s13 = "~1\\MUNGAW~1.ZIP/mbhttpbf.exe/msvbvm60.dll" fullword ascii /* score: '23.00'*/
      $s14 = "~1\\GETCPASS.ZIP/getcpass.exe" fullword ascii /* score: '23.00'*/
      $s15 = "dialog(name: '$$$/Dialogs/Import', target_id: 'text')" fullword ascii /* score: '22.00'*/
      $s16 = "d:\\new\\NETSCAN.EXE" fullword ascii /* score: '22.00'*/
      $s17 = "~1\\MUNGAW~1.ZIP/mbhttpbf.exe/COMCAT.DLL" fullword ascii /* score: '22.00'*/
      $s18 = "d:\\new\\VBSCRYPT.EXE" fullword ascii /* score: '21.00'*/
      $s19 = "d:\\new\\JAPANIZE.EXE" fullword ascii /* score: '21.00'*/
      $s20 = "d:\\new\\BIGBRO~1.EXE" fullword ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

