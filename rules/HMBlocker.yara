/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmph20kkw3j
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule HMBlocker {
   meta:
      description = "tmph20kkw3j - file HMBlocker.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "2d047b0a46be4da59d375f71cfbd578ce1fbf77955d0bb149f6be5b9e4552180"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s2 = "3333333332**(*" fullword ascii /* score: '9.00'*/ /* hex encoded string '33332' */
      $s3 = "un /v l" fullword ascii /* score: '9.00'*/
      $s4 = "GetModulzNam~" fullword ascii /* score: '9.00'*/
      $s5 = "N%userprofi" fullword ascii /* score: '7.00'*/
      $s6 = "_USER\\SOFTWA\\MicZs\\" fullword ascii /* score: '7.00'*/
      $s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s8 = "DD HKEY_CUR" fullword ascii /* score: '7.00'*/
      $s9 = "LookupPriv" fullword ascii /* score: '7.00'*/
      $s10 = " Complo" fullword ascii /* score: '6.00'*/
      $s11 = "Decembe" fullword ascii /* score: '6.00'*/
      $s12 = "PPMMNQQQVVVW^" fullword ascii /* score: '4.00'*/
      $s13 = "FWxSQG5&&&&&'6BYfef" fullword ascii /* score: '4.00'*/
      $s14 = "MPMMIMQSTW__WWWb___^^" fullword ascii /* score: '4.00'*/
      $s15 = "allsigA" fullword ascii /* score: '4.00'*/
      $s16 = "August|" fullword ascii /* score: '4.00'*/
      $s17 = "JGJJFFJIJMMQ[" fullword ascii /* score: '4.00'*/
      $s18 = "fTrrTPPPPQWfvxvsxs" fullword ascii /* score: '4.00'*/
      $s19 = "t\\Windows\\CurIntVtsion\\R" fullword ascii /* score: '4.00'*/
      $s20 = "VGShlELcuL;," fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

