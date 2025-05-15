/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpm1r0cl_0
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpm1r0cl_0_UIWIX {
   meta:
      description = "tmpm1r0cl_0 - file UIWIX.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "146581f0b3fbe00026ee3ebe68797b0e57f39d1d8aecc99fdc3290e9cfadc4fc"
   strings:
      $s1 = "wpespy.dll" fullword ascii /* score: '28.00'*/
      $s2 = "cmdvrt32.dll" fullword ascii /* score: '26.00'*/
      $s3 = "C:\\Users\\" fullword wide /* score: '24.00'*/
      $s4 = "SxIn.dll" fullword ascii /* score: '23.00'*/
      $s5 = "vmcheck.dll" fullword ascii /* score: '23.00'*/
      $s6 = "snxhk.dll" fullword ascii /* score: '23.00'*/
      $s7 = "msvcrtd.dll" fullword ascii /* score: '23.00'*/
      $s8 = "api_log.dll" fullword ascii /* score: '22.00'*/
      $s9 = "C:\\Documents and Settings\\" fullword wide /* score: '21.00'*/
      $s10 = "https://netcologne.dl.sourceforge.net/project/cyqlite/3.8.5/sqlite-dll-win32-x86-3080500.zip" fullword ascii /* score: '20.00'*/
      $s11 = "dir_watch.dll" fullword ascii /* score: '20.00'*/
      $s12 = "\\\\\\\\.\\\\pipe\\\\cuckoo" fullword wide /* score: '19.00'*/
      $s13 = "\\\\\\\\.\\\\pipe\\\\VBoxMiniRdDN" fullword wide /* score: '19.00'*/
      $s14 = "\\\\\\\\.\\\\pipe\\\\VBoxTrayIPC" fullword wide /* score: '19.00'*/
      $s15 = "xProcess" fullword ascii /* score: '15.00'*/
      $s16 = "http://sqlite.org/2014/sqlite-dll-win32-x86-3080500.zip" fullword ascii /* score: '15.00'*/
      $s17 = "passwordRC4" fullword ascii /* score: '13.00'*/
      $s18 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii /* score: '12.00'*/
      $s19 = "passwordAES" fullword ascii /* score: '12.00'*/
      $s20 = "cryptkey" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

