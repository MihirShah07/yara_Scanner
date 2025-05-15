/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpxib153og
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpxib153og_Mari {
   meta:
      description = "tmpxib153og - file Mari.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "efb67be90882ded2d3e53e463ae175a4b4b5229ca6929b835fa7dd4687801144"
   strings:
      $s1 = "C:\\Windows\\SYSTEM32.exe" fullword wide /* score: '29.00'*/
      $s2 = "C:\\Winnt\\SYSTEM32.exe" fullword wide /* score: '29.00'*/
      $s3 = "WINDOWS\\SYSTEM32.exe" fullword wide /* score: '23.00'*/
      $s4 = "Winnt\\SYSTEM32.exe" fullword wide /* score: '23.00'*/
      $s5 = "rundll32.exe url.dll,FileProtocolHandler " fullword wide /* score: '22.00'*/
      $s6 = "info.exe" fullword wide /* score: '22.00'*/
      $s7 = "http://my.marijuana.com" fullword wide /* score: '21.00'*/
      $s8 = "@*\\AC:\\marijuana\\marijuana\\Marijuana.vbp" fullword wide /* score: '17.00'*/
      $s9 = "The Marijuana Virus!!!" fullword ascii /* score: '13.00'*/
      $s10 = "check this out!!!" fullword wide /* score: '13.00'*/
      $s11 = "LEGALIZE IT!!!" fullword wide /* score: '13.00'*/
      $s12 = "IMPORTANT: PLEASE READ" fullword wide /* score: '10.00'*/
      $s13 = "GetNameSpace" fullword wide /* score: '9.00'*/
      $s14 = "Im A Pot Head!" fullword wide /* score: '9.00'*/
      $s15 = "Marijuana Explorer (LEGALIZE IT!!!)" fullword wide /* score: '9.00'*/
      $s16 = "Its 4:20, Time to toke up :)" fullword wide /* score: '8.00'*/
      $s17 = "cmdOutlook" fullword ascii /* score: '7.00'*/
      $s18 = "cmdCopyWinDir" fullword ascii /* score: '7.00'*/
      $s19 = "cmdRegEdit" fullword ascii /* score: '7.00'*/
      $s20 = "AddressLists" fullword wide /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

