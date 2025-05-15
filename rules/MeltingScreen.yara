/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp7jaic1i0
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule MeltingScreen {
   meta:
      description = "tmp7jaic1i0 - file MeltingScreen.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "9d355e4f9a51536b05269f696b304859155985957ba95eb575f3f38c599d913c"
   strings:
      $s1 = "MeltingScreen.exe" fullword wide /* score: '22.00'*/
      $s2 = "VB5DE.DLL" fullword ascii /* score: '20.00'*/
      $s3 = "*\\AI:\\DevStudio\\VB\\Own\\Buddy\\V11_final\\MeltingScreen.vbp" fullword wide /* score: '17.00'*/
      $s4 = "\\MeltingScreen.exe" fullword wide /* score: '16.00'*/
      $s5 = "I:\\DevStudio\\VB\\VB5.OLB" fullword ascii /* score: '13.00'*/
      $s6 = "\\__*.exe" fullword wide /* score: '13.00'*/
      $s7 = "\\*.exe" fullword wide /* score: '13.00'*/
      $s8 = "RegGetString" fullword ascii /* score: '9.00'*/
      $s9 = "GetNameSpace" fullword wide /* score: '9.00'*/
      $s10 = "Hello my friend !" fullword wide /* score: '9.00'*/
      $s11 = "valname" fullword ascii /* score: '8.00'*/
      $s12 = "AlreadySendMails" fullword ascii /* score: '7.00'*/
      $s13 = ":$:,:8:<:H:L:P:T:X:\\:`:d:h:l:p:t:x:|:" fullword ascii /* score: '7.00'*/
      $s14 = "AddressLists" fullword wide /* score: '7.00'*/
      $s15 = "AddressEntries" fullword wide /* score: '7.00'*/
      $s16 = "p.s.: Please install the Runtime Library for VB 5.0, before you run the ScreenSaver." fullword wide /* score: '7.00'*/
      $s17 = "MeltingScreen" fullword wide /* score: '4.00'*/
      $s18 = "SaveSettingString" fullword ascii /* score: '4.00'*/
      $s19 = "Form_Load" fullword ascii /* score: '4.00'*/
      $s20 = "hInKey" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      8 of them
}

