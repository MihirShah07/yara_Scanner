/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpaznat90r
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpaznat90r_Pikachu {
   meta:
      description = "tmpaznat90r - file Pikachu.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "e1dfc005d5403fb2f356276f0abe19df68249ce10e5035450926d56c2f8d3652"
   strings:
      $s1 = "C:\\AUTOEXEC.BAT" fullword wide /* score: '28.00'*/
      $s2 = "PikachuPokemon.exe" fullword wide /* score: '22.00'*/
      $s3 = "Visit us at http://www.pikachu.com" fullword ascii /* score: '21.00'*/
      $s4 = "Visit Pikachu at http://www.pikachu.com" fullword wide /* score: '21.00'*/
      $s5 = "Scripting.FileSystemObject" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s6 = "@*\\AC:\\Projetos\\Pikachu\\PikachuPokemon.vbp" fullword wide /* score: '17.00'*/
      $s7 = "C:\\Arquivos de programas\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii /* score: '16.00'*/
      $s8 = "\\PikachuPokemon.exe" fullword wide /* score: '16.00'*/
      $s9 = "Between millions of people around the world i found you. Don't forget to remember this day every time MY FRIEND!" fullword ascii /* score: '9.00'*/
      $s10 = "GetNameSpace" fullword wide /* score: '9.00'*/
      $s11 = "GetSpecialFolder" fullword wide /* score: '9.00'*/
      $s12 = "AddressLists" fullword wide /* score: '7.00'*/
      $s13 = "AddressEntries" fullword wide /* score: '7.00'*/
      $s14 = "!!!RRR" fullword ascii /* score: '6.00'*/
      $s15 = "rfrmMain" fullword ascii /* score: '4.00'*/
      $s16 = "s{sRskJcZ1JB!sc!" fullword ascii /* score: '4.00'*/
      $s17 = "ZccB{{RssJZZ9" fullword ascii /* score: '4.00'*/
      $s18 = "frmMain" fullword ascii /* score: '4.00'*/
      $s19 = "modMain" fullword ascii /* score: '4.00'*/
      $s20 = "PikachuPokemon" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

