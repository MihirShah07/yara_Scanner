/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpv23049yd
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpv23049yd_Amus {
   meta:
      description = "tmpv23049yd - file Amus.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "b5fc4fd50e4ba69f0c8c8e5c402813c107c605cab659960ac31b3c8356c4e0ec"
   strings:
      $s1 = "c:\\masum.exe" fullword wide /* score: '24.00'*/
      $s2 = "masum.exe" fullword wide /* score: '22.00'*/
      $s3 = "Masum.exe" fullword wide /* score: '22.00'*/
      $s4 = "@*\\AX:\\Vx\\New_Worm\\Masum.vbp" fullword wide /* score: '17.00'*/
      $s5 = "\\KdzEregli.exe" fullword wide /* score: '16.00'*/
      $s6 = "\\Messenger.exe" fullword wide /* score: '16.00'*/
      $s7 = "\\My_Pictures.exe" fullword wide /* score: '16.00'*/
      $s8 = "\\Meydanbasi.exe" fullword wide /* score: '16.00'*/
      $s9 = "\\Pide.exe" fullword wide /* score: '16.00'*/
      $s10 = "\\Pire.exe" fullword wide /* score: '16.00'*/
      $s11 = "\\Cekirge.exe" fullword wide /* score: '16.00'*/
      $s12 = "\\Ankara.exe" fullword wide /* score: '16.00'*/
      $s13 = "\\Adapazari.exe" fullword wide /* score: '16.00'*/
      $s14 = "\\Anti_Virus.exe" fullword wide /* score: '16.00'*/
      $s15 = "CreateBMutex" fullword ascii /* score: '15.00'*/
      $s16 = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Masum\\Who" fullword wide /* score: '10.00'*/
      $s17 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Microzoft_Ofiz" fullword wide /* score: '10.00'*/
      $s18 = "./3>>?????>=C" fullword ascii /* score: '9.00'*/ /* hex encoded string '<' */
      $s19 = "GetSpecialFolder" fullword wide /* score: '9.00'*/
      $s20 = "RegWrite" fullword wide /* PEStudio Blacklist: strings */ /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

