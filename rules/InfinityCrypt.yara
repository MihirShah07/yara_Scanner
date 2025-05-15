/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp4l5jizb5
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule InfinityCrypt {
   meta:
      description = "tmp4l5jizb5 - file InfinityCrypt.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "f5d002bfe80b48386a6c99c41528931b7f5df736cd34094463c3f85dde0180bf"
   strings:
      $s1 = "F:\\Windows.old\\Users\\ArizonaCode\\Documents\\Visual Studio 2013\\Projects\\UI\\UI\\obj\\Debug\\UI.pdb" fullword ascii /* score: '30.00'*/
      $s2 = "gSystem.Drawing.SizeF, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Size, Sy" ascii /* score: '27.00'*/
      $s3 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s4 = "System.Windows.Forms.FormStartPosition, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089g" ascii /* score: '27.00'*/
      $s5 = "System.Drawing.Point, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '27.00'*/
      $s6 = "stem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '24.00'*/
      $s7 = "C:\\Users\\" fullword wide /* score: '24.00'*/
      $s8 = "C:\\\\Users\\\\" fullword wide /* score: '24.00'*/
      $s9 = ">encrypt.exe -alldata -randomkeysend -rsa2048 -alldrives" fullword wide /* score: '23.00'*/
      $s10 = "/C ping 1.1.1.1 -n 1 -w 1 > Nul & Del \"" fullword wide /* score: '23.00'*/
      $s11 = "PremiereCrack.exe" fullword wide /* score: '22.00'*/
      $s12 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s13 = "F:\\DESKTOP!\\ChkDsk\\ChkDsk\\obj\\Debug\\PremiereCrack.pdb" fullword ascii /* score: '19.00'*/
      $s14 = ">sendhelp.exe -incmd -me" fullword wide /* score: '18.00'*/
      $s15 = "TargetKey" fullword ascii /* score: '17.00'*/
      $s16 = "UI.exe" fullword wide /* score: '16.00'*/
      $s17 = "EncryptOrDecryptFile" fullword ascii /* score: '16.00'*/
      $s18 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s19 = ">setinstuctions.exe -silent -desktop" fullword wide /* score: '15.00'*/
      $s20 = "QzpcVXNlcnNc" fullword wide /* base64 encoded string 'C:\Users\' */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

