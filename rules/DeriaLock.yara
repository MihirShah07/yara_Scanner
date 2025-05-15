/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpgeyvkn0h
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule DeriaLock {
   meta:
      description = "tmpgeyvkn0h - file DeriaLock.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "4f5bff64160044d9a769ab277ff85ba954e2a2e182c6da4d0672790cf1d48309"
   strings:
      $x1 = "http://arizonacode.bplaced.net/HF/SystemLocker/UNLOCKKEYS/LOGON.exe" fullword wide /* score: '36.00'*/
      $s2 = "LOGON.exe" fullword wide /* score: '30.00'*/
      $s3 = "C:\\Windows.old\\Users\\ArizonaCode\\Documents\\Visual Studio 2013\\Projects\\LOGON\\LOGON\\obj\\Debug\\LOGON.pdb" fullword ascii /* score: '30.00'*/
      $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s5 = "C:\\Users\\" fullword wide /* score: '24.00'*/
      $s6 = "up\\LOGON.exe" fullword wide /* score: '23.00'*/
      $s7 = "C:\\Windows\\explorer.exe" fullword wide /* score: '21.00'*/
      $s8 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s9 = "http://arizonacode.bplaced.net/HF/SystemLocker/unlock-everybody.txt" fullword wide /* score: '17.00'*/
      $s10 = "schen Sie den requestedExecutionLevel-Knoten." fullword ascii /* score: '16.00'*/
      $s11 = "EncryptOrDecryptFile" fullword ascii /* score: '16.00'*/
      $s12 = "http://arizonacode.bplaced.net/HF/SystemLocker/UNLOCKKEYS/" fullword wide /* score: '16.00'*/
      $s13 = "LOGON.EnIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII" ascii /* score: '15.00'*/
      $s14 = "8.1 kompatibel ist, die Kommentierung des folgenden supportedOS-Knotens aufheben.-->" fullword ascii /* score: '15.00'*/
      $s15 = "LOGON.DeIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII" ascii /* score: '15.00'*/
      $s16 = "LOGON.MainIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII" ascii /* score: '15.00'*/
      $s17 = "LOGON.DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD.resources" fullword ascii /* score: '15.00'*/
      $s18 = "LOGON.EnIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII" ascii /* score: '15.00'*/
      $s19 = "LOGON.DeIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII" ascii /* score: '15.00'*/
      $s20 = "LOGON.MainIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

