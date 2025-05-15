/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpwvl7whkb
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule SpySheriff {
   meta:
      description = "tmpwvl7whkb - file SpySheriff.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "4f5f0d9a2b6ef077402a17136ff066dda4c8175ceb6086877aaa3570cabb638f"
   strings:
      $s1 = "By clicking \"Install SpySheriff Spyware remover\" you agree to SpySheriff EULA stated at http://www.spy-sheriff.com/eula.php" fullword wide /* score: '22.00'*/
      $s2 = "GET /trial.php?rest=%u&ver=%u&a=00000000 HTTP/1.0" fullword ascii /* score: '19.00'*/
      $s3 = "C:\\Program Files\\SpySheriff\\SpySheriff.dvm" fullword ascii /* score: '18.00'*/
      $s4 = "C:\\Program Files\\SpySheriff\\%s" fullword ascii /* score: '17.50'*/
      $s5 = "<description>SpySheriff Spyware scanner and remover.</description>" fullword ascii /* score: '16.00'*/
      $s6 = "C:\\Program Files\\%s\\%s" fullword ascii /* score: '15.50'*/
      $s7 = "C:\\Program Files\\SpySheriff" fullword ascii /* score: '15.00'*/
      $s8 = "This will install SpySheriff (Trial Ver.) Spyware remover on your computer." fullword wide /* score: '12.00'*/
      $s9 = "%s\\Install.dat" fullword ascii /* score: '11.00'*/
      $s10 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s11 = "        processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s12 = "Download progress:" fullword wide /* score: '10.00'*/
      $s13 = "Spy Sheriff Online Installer" fullword ascii /* score: '9.00'*/
      $s14 = "SpySheriff Online Installer" fullword wide /* score: '9.00'*/
      $s15 = "Install SpySheriff Spyware remover" fullword wide /* score: '9.00'*/
      $s16 = "qwxxxxw" fullword ascii /* score: '8.00'*/
      $s17 = "wwrtwwwwy" fullword ascii /* score: '8.00'*/
      $s18 = "        publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s19 = "wwtwwwwx" fullword ascii /* score: '8.00'*/
      $s20 = "zyyyy}z" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

