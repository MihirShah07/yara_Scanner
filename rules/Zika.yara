/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpbdivzvbd
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpbdivzvbd_Zika {
   meta:
      description = "tmpbdivzvbd - file Zika.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "1a904494bb7a21512af6013fe65745e7898cdd6fadac8cb58be04e02346ed95f"
   strings:
      $x1 = "C:\\Users\\int\\Documents\\Visual Studio 2015\\Projects\\desktopcube\\desktopcube\\obj\\x86\\Release\\Zika.pdb" fullword ascii /* score: '33.00'*/
      $x2 = "zSystem.Windows.Forms.AxHost+State, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089PADPh" ascii /* score: '32.00'*/
      $x3 = "zSystem.Windows.Forms.AxHost+State, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089PADPh" ascii /* score: '32.00'*/
      $x4 = "7TLoginCredentialService.GetLoginCredentials$1172$ActRec," fullword ascii /* score: '31.00'*/
      $s5 = "C:\\Users\\Angus\\Documents\\Dev\\DXE2\\Components\\VirtualTrees\\VirtualTrees.pas" fullword wide /* score: '30.00'*/
      $s6 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s7 = ".TDefaultLoginCredentials.LoginEvent$833$ActRec4" fullword ascii /* score: '24.00'*/
      $s8 = "get_serviceLoginSignedIn" fullword ascii /* score: '23.00'*/
      $s9 = "AxInterop.WMPLib.dll" fullword wide /* score: '23.00'*/
      $s10 = "TLoginCredentialService(kD" fullword ascii /* score: '23.00'*/
      $s11 = "get_serviceLoginVisible" fullword ascii /* score: '23.00'*/
      $s12 = "actForwardExecute" fullword ascii /* score: '23.00'*/
      $s13 = "WMPLib.dll" fullword ascii /* score: '23.00'*/
      $s14 = "Interop.WMPLib.dll" fullword wide /* score: '23.00'*/
      $s15 = "/c ping 127.0.0.1 -n 2 && del /A:H \"" fullword wide /* score: '23.00'*/
      $s16 = "Zika.exe" fullword wide /* score: '22.00'*/
      $s17 = "getProxyBypassForLocal" fullword ascii /* score: '22.00'*/
      $s18 = "attemptLogin" fullword ascii /* score: '22.00'*/
      $s19 = "Operation failed. \"Template needs to be compiled (F5))Size: %d " fullword wide /* score: '22.00'*/
      $s20 = "=This control requires version 4.70 or greater of COMCTL32.DLLEInvalid backslash (valid options are - \\\\, \\\", \\n, \\t, \\00" wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 17000KB and
      1 of ($x*) and 4 of them
}

