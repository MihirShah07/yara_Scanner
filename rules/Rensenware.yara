/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpmd5376xx
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Rensenware {
   meta:
      description = "tmpmd5376xx - file Rensenware.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "7bf5623f0a10dfa148a35bebd899b7758612f1693d2a9910f716cf15a921a76a"
   strings:
      $x1 = "C:\\Users\\mkang\\Documents\\Visual Studio 2017\\Projects\\renseiWare\\rensenWare\\obj\\Release\\rensenWare.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADAd" fullword ascii /* score: '27.00'*/
      $s4 = "rensenWare.exe" fullword wide /* score: '22.00'*/
      $s5 = "That's easy. You just play TH12 ~ Undefined Fantastic Object and score over 0.2 billion in LUNATIC level. this application will " ascii /* score: '16.00'*/
      $s6 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s7 = "TH12 Process Status : " fullword wide /* score: '15.00'*/
      $s8 = "Process Killed!" fullword wide /* score: '15.00'*/
      $s9 = "Process Working" fullword wide /* score: '15.00'*/
      $s10 = "targetExtensions" fullword ascii /* score: '14.00'*/
      $s11 = "If there are encrypted files exists, use manual decrypter with key/IV files saved in desktop!" fullword wide /* score: '14.00'*/
      $s12 = "\\randomkey.bin" fullword wide /* score: '14.00'*/
      $s13 = "Key/IV Binary File (*.bin)|*.bin" fullword wide /* score: '13.00'*/
      $s14 = "get_randomKey" fullword ascii /* score: '12.00'*/
      $s15 = " ENCRYPTION KEY!" fullword ascii /* score: '12.00'*/
      $s16 = "Your system have been encrypted by Rensenware!" fullword wide /* score: '12.00'*/
      $s17 = "detect TH12 process and score automatically. DO NOT TRY CHEATING OR TEMRMINATE THIS APPLICATION IF YOU DON'T WANT TO BLOW UP THE" ascii /* score: '11.00'*/
      $s18 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s19 = "Decryption Complete!" fullword wide /* score: '11.00'*/
      $s20 = "\\randomiv.bin" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

