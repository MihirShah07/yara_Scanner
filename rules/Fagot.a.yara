/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpr78palw1
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpr78palw1_Fagot_a {
   meta:
      description = "tmpr78palw1 - file Fagot.a.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "1517527c1d705a6ebc6ec9194aa95459e875ac3902a9f4aab3bf24b6a6f8407f"
   strings:
      $x1 = "C:\\windows\\system32\\dumprep.exe" fullword ascii /* score: '42.00'*/
      $x2 = "C:\\Windows\\system32\\dllhost32.exe" fullword ascii /* score: '39.00'*/
      $x3 = "C:\\windows\\cmd.exe" fullword ascii /* score: '38.00'*/
      $x4 = "C:\\windows\\system32\\wowexec.exe" fullword ascii /* score: '37.00'*/
      $x5 = "C:\\windows\\system32\\logon.exe" fullword ascii /* score: '35.00'*/
      $x6 = "C:\\windows\\system32\\services.exe" fullword ascii /* score: '35.00'*/
      $x7 = "C:\\windows\\system32\\alg.exe" fullword ascii /* score: '32.00'*/
      $x8 = "C:\\windows\\system32\\shutdown.exe" fullword ascii /* score: '32.00'*/
      $x9 = "C:\\windows\\system32\\imapi.exe" fullword ascii /* score: '32.00'*/
      $x10 = "C:\\windows\\system32\\progman.exe" fullword ascii /* score: '32.00'*/
      $x11 = "C:\\windows\\system32\\wuauclt.exe" fullword ascii /* score: '32.00'*/
      $x12 = "C:\\windows\\system32\\autochk.exe" fullword ascii /* score: '32.00'*/
      $x13 = "C:\\windows\\system32\\chcp.exe" fullword ascii /* score: '32.00'*/
      $x14 = "C:\\windows\\system32\\win.exe" fullword ascii /* score: '32.00'*/
      $x15 = "C:\\Windows\\system32\\userinit32.exe" fullword ascii /* score: '32.00'*/
      $x16 = "C:\\windows\\system32\\ntoskrnl.exe" fullword ascii /* score: '32.00'*/
      $x17 = "C:\\windows\\system32\\taskman.exe" fullword ascii /* score: '32.00'*/
      $x18 = "C:\\windows\\system32\\regsvr32.exe" fullword ascii /* score: '32.00'*/
      $x19 = "C:\\WINDOWS\\system32\\userinit.exe" fullword ascii /* score: '32.00'*/
      $x20 = "C:\\windows\\system32\\ntkrnlpa.exe" fullword ascii /* score: '32.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*)
}

