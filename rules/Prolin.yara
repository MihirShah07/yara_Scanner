/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpabai9sz0
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpabai9sz0_Prolin {
   meta:
      description = "tmpabai9sz0 - file Prolin.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "db0c7e3029fb2a048e7a3e74c9cbf3e8bcec06288b5eafac5aae678d8663bffc"
   strings:
      $x1 = "Hi, guess you have got the message.  I have kept a list of files that I have infected under this.  If you are smart enough just " wide /* score: '31.00'*/
      $s2 = "c:\\creative.exe" fullword wide /* score: '24.00'*/
      $s3 = "creative.exe" fullword wide /* score: '22.00'*/
      $s4 = "C:\\WINDOWS\\Start Menu\\Programs\\StartUp\\creative.exe" fullword wide /* score: '21.00'*/
      $s5 = "c:\\messageforu.txt" fullword wide /* score: '20.00'*/
      $s6 = "z14xym432@yahoo.com" fullword wide /* score: '18.00'*/
      $s7 = "@*\\AF:\\virus\\vir\\curr\\Project1.vbp" fullword wide /* score: '17.00'*/
      $s8 = "infectfiles" fullword ascii /* score: '13.00'*/
      $s9 = "folderspec" fullword ascii /* score: '8.00'*/
      $s10 = "creative" fullword wide /* score: '8.00'*/
      $s11 = "AddressLists" fullword wide /* score: '7.00'*/
      $s12 = "AddressEntries" fullword wide /* score: '7.00'*/
      $s13 = "Job complete" fullword wide /* score: '7.00'*/
      $s14 = "folderlist1" fullword ascii /* score: '5.00'*/
      $s15 = "'/?OPPG0PG0" fullword ascii /* score: '4.00'*/
      $s16 = "-C000-Creative" fullword ascii /* score: '4.00'*/
      $s17 = "046}#2.Flash Player 4.0 R7" fullword ascii /* score: '4.00'*/
      $s18 = "@ pOPP (/_OP" fullword ascii /* score: '4.00'*/
      $s19 = "Flash Player 4.0 R7" fullword ascii /* score: '4.00'*/
      $s20 = "A great Shockwave flash movie" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      1 of ($x*) and 4 of them
}

