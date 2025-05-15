/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpe6jc7yjm
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpe6jc7yjm_Remcos {
   meta:
      description = "tmpe6jc7yjm - file Remcos.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "c851749fd6c9fa19293d8ee2c5b45b3dc8561115ddfe7166fbaefcb9b353b7c4"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $x2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $x3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii /* score: '34.00'*/
      $x4 = "C:\\WINDOWS\\system32\\userinit.exe" fullword ascii /* score: '32.00'*/
      $s5 = "C:\\WINDOWS\\system32\\userinit.exe, " fullword ascii /* score: '28.00'*/
      $s6 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" fullword ascii /* score: '23.00'*/
      $s7 = "eventvwr.exe" fullword ascii /* score: '22.00'*/
      $s8 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii /* score: '22.00'*/
      $s9 = "PING 127.0.0.1 -n 2 " fullword ascii /* score: '20.00'*/
      $s10 = "remscriptexecd" fullword ascii /* score: '19.00'*/
      $s11 = "clearlogins" fullword ascii /* score: '19.00'*/
      $s12 = "execcom" fullword ascii /* score: '19.00'*/
      $s13 = "getofflinelogs" fullword ascii /* score: '18.00'*/
      $s14 = "update.bat" fullword ascii /* score: '18.00'*/
      $s15 = "autogetofflinelogs" fullword ascii /* score: '18.00'*/
      $s16 = "mscfile\\shell\\open\\command" fullword ascii /* score: '17.00'*/
      $s17 = "deletekeylog" fullword ascii /* score: '16.00'*/
      $s18 = "\\logins.json" fullword ascii /* score: '16.00'*/
      $s19 = "[Firefox StoredLogins cleared!]" fullword ascii /* score: '15.00'*/
      $s20 = "[Firefox StoredLogins not found]" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

