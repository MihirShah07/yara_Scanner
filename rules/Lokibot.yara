/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpkahys1kf
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpkahys1kf_Lokibot {
   meta:
      description = "tmpkahys1kf - file Lokibot.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "a885b1f5377c2a1cead4e2d7261fab6199f83610ffdd35d20c653d52279d4683"
   strings:
      $s1 = "%s\\%s%i\\encPws\\GoFTP\\settings\\Connections.txt" fullword wide /* score: '28.50'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADr" fullword ascii /* score: '27.00'*/
      $s4 = "sCrypt32.dll" fullword wide /* score: '23.00'*/
      $s5 = "ryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logit" fullword ascii /* score: '22.00'*/
      $s6 = "SmtpPassword" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s7 = "SMTP Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s8 = "FtpPassword" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s9 = "%s\\%s%i\\data\\settings\\ftpd.jsd" fullword wide /* score: '21.50'*/
      $s10 = "More information: http://www.ibsensoftware.co1  -  the smaller the better :)" fullword ascii /* score: '19.00'*/
      $s11 = "%s%s\\Login Data" fullword wide /* score: '19.00'*/
      $s12 = "RFQ For New Supply #PO_0004571385412_pdf.exe" fullword wide /* score: '19.00'*/
      $s13 = "%s\\%s%i\\data\\settings\\sshProfFtp" fullword wide /* score: '18.50'*/
      $s14 = "%s\\%s\\User Data\\Default\\Logs>" fullword wide /* score: '17.50'*/
      $s15 = "%s\\%s\\%s.exe" fullword wide /* score: '17.50'*/
      $s16 = "SMTP User" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s17 = "SmtpAccount" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s18 = "PopPassword" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
      $s19 = "Software\\Microsoft\\Windows NT\\CurPassword" fullword wide /* score: '17.00'*/
      $s20 = "POP3 Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

