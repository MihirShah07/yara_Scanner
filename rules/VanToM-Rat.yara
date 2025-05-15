/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp1nxklark
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule VanToM_Rat {
   meta:
      description = "tmp1nxklark - file VanToM-Rat.bat"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "b15c7cf9097195fb5426d4028fd2f6352325400beb1e32431395393910e0b10a"
   strings:
      $x1 = "cmd.exe /k ping 0 & del \"" fullword wide /* score: '42.00'*/
      $s2 = "%SystemRoot%\\system32\\SHELL32.dll,3" fullword wide /* score: '30.00'*/
      $s3 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s4 = "GetProcesses" fullword wide /* PEStudio Blacklist: strings */ /* score: '25.00'*/
      $s5 = "mozutils.dll" fullword wide /* score: '23.00'*/
      $s6 = "plds4.dll" fullword wide /* score: '23.00'*/
      $s7 = "ssutil3.dll" fullword wide /* score: '23.00'*/
      $s8 = "getsystempath" fullword wide /* score: '23.00'*/
      $s9 = "Stub.exe" fullword ascii /* score: '22.00'*/
      $s10 = "VanToM.exe" fullword wide /* score: '22.00'*/
      $s11 = "|URL| http://Yahoo.com" fullword wide /* score: '21.00'*/
      $s12 = "|URL| http://hotmail.com" fullword wide /* score: '21.00'*/
      $s13 = "|URL| http://no-ip.com" fullword wide /* score: '21.00'*/
      $s14 = "|URL| http://Paltalk.com" fullword wide /* score: '21.00'*/
      $s15 = "|URL| http://DynDns.com" fullword wide /* score: '21.00'*/
      $s16 = "gettemppath" fullword wide /* score: '20.00'*/
      $s17 = "WScript.Shell" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s18 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s19 = "SELECT * FROM moz_logins;" fullword wide /* score: '19.00'*/
      $s20 = "downloadfile" fullword wide /* PEStudio Blacklist: strings */ /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

