/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpt55e94jk
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpt55e94jk_Petya_A {
   meta:
      description = "tmpt55e94jk - file Petya.A.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "26b4699a7b9eeb16e76305d843d4ab05e94d43f3201436927e13b3ebafa90739"
   strings:
      $s1 = "The process crashed near a code sequence containing a Jump->Call->Pop sequence commonly used by shellcode to find the address of" ascii /* score: '28.00'*/
      $s2 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '17.00'*/
      $s3 = "  processorArchitecture=\"*\"" fullword ascii /* score: '15.00'*/
      $s4 = "X-HTTP-Attempts" fullword wide /* score: '14.00'*/
      $s5 = "tdownloaded" fullword wide /* score: '14.00'*/
      $s6 = "[Failed to add pipe security DACL][%#x]" fullword wide /* score: '13.00'*/
      $s7 = "  version=\"1.0.0.0\"" fullword ascii /* score: '12.00'*/
      $s8 = "@CommandLineMode" fullword wide /* score: '12.00'*/
      $s9 = "      <requestedExecutionLevel level=\"requireAdministrator\"            " fullword ascii /* score: '11.00'*/
      $s10 = "@APPDATA" fullword wide /* score: '11.00'*/
      $s11 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s12 = "      processorArchitecture=\"*\"" fullword ascii /* score: '10.00'*/
      $s13 = "BX-Proxy-Manual-Auth" fullword wide /* score: '10.00'*/
      $s14 = "CSoftware\\Google\\%ws\\UsageStats\\Daily" fullword wide /* score: '9.00'*/
      $s15 = "vpiiijwttttrq" fullword ascii /* score: '8.00'*/
      $s16 = "vpiiiggjwtttqqq" fullword ascii /* score: '8.00'*/
      $s17 = "iiiiiiiiiiiiigggjwtkqqqq" fullword ascii /* score: '8.00'*/
      $s18 = "bbbbbbbbbbba" ascii /* score: '8.00'*/
      $s19 = "ccccccccccccccccccccccccccccccccccccccccccc" ascii /* score: '8.00'*/
      $s20 = "      publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

