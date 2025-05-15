/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpyqvlptcp
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule WannaCrypt0r {
   meta:
      description = "tmpyqvlptcp - file WannaCrypt0r.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
   strings:
      $x1 = "cmd.exe /c \"%s\"" fullword ascii /* score: '36.00'*/
      $s2 = "tasksche.exe" fullword ascii /* score: '22.00'*/
      $s3 = "taskdl.exe" fullword ascii /* score: '22.00'*/
      $s4 = "taskse.exe" fullword ascii /* score: '22.00'*/
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" />" fullword ascii /* score: '15.00'*/
      $s6 = "       <!-- Windows Vista -->" fullword ascii /* score: '12.00'*/
      $s7 = "       <!-- Windows 8 -->" fullword ascii /* score: '12.00'*/
      $s8 = "       <!-- Windows 10 --> " fullword ascii /* score: '12.00'*/
      $s9 = "       <!-- Windows 8.1 -->" fullword ascii /* score: '12.00'*/
      $s10 = "       <!-- Windows 7 -->" fullword ascii /* score: '12.00'*/
      $s11 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii /* score: '11.00'*/
      $s12 = "taskse.exed*" fullword ascii /* score: '11.00'*/
      $s13 = "            processorArchitecture=\"*\"" fullword ascii /* score: '10.00'*/
      $s14 = "Inx%k:\\" fullword ascii /* score: '9.50'*/
      $s15 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii /* score: '9.00'*/
      $s16 = "Iw* -cv" fullword ascii /* score: '9.00'*/
      $s17 = "IKFJ- =" fullword ascii /* score: '8.00'*/
      $s18 = "QrRUl* " fullword ascii /* score: '8.00'*/
      $s19 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s20 = "  </compatibility>" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      1 of ($x*) and 4 of them
}

