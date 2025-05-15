/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmphcmvdfp_
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule rickroll {
   meta:
      description = "tmphcmvdfp_ - file rickroll.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "48b08ea78124ca010784d9f0faae751fc4a0c72c0e7149ded81fc03819f5d723"
   strings:
      $s1 = "https://www.youtube.com/watch?v=dQw4w9WgXcQ" fullword ascii /* score: '17.00'*/
      $s2 = "._FindPESectionExec" fullword ascii /* score: '16.00'*/
      $s3 = "processthreadsapi.h" fullword ascii /* score: '15.00'*/
      $s4 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s5 = "C:\\crossdev\\gccmaster\\build-tdm64\\gcc\\x86_64-w64-mingw32\\libgcc" fullword ascii /* score: '13.00'*/
      $s6 = "9lpszCommandLine" fullword ascii /* score: '12.00'*/
      $s7 = "__imp_GetAsyncKeyState" fullword ascii /* score: '12.00'*/
      $s8 = "GNU C 4.9.2 -mtune=generic -march=x86-64 -g -O2 -O2 -O2 -fbuilding-libgcc -fno-stack-protector" fullword ascii /* score: '12.00'*/
      $s9 = ";__mingw_GetSectionForAddress" fullword ascii /* score: '12.00'*/
      $s10 = "GNU C 4.9.2 -m64 -mtune=generic -march=x86-64 -g -O2 -std=gnu99" fullword ascii /* score: '12.00'*/
      $s11 = "__mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s12 = "J__mingw_winmain_lpCmdLine" fullword ascii /* score: '12.00'*/
      $s13 = "%Target" fullword ascii /* score: '11.00'*/
      $s14 = "rickroll.cpp" fullword ascii /* score: '10.00'*/
      $s15 = "#__security_cookie_complement" fullword ascii /* score: '10.00'*/
      $s16 = "pTarget" fullword ascii /* score: '10.00'*/
      $s17 = "X86_TUNE_MISALIGNED_MOVE_STRING_PRO_EPILOGUES" fullword ascii /* score: '9.00'*/
      $s18 = "C:/crossdev/gccmaster/host-toolchain-tdm64/x86_64-w64-mingw32/include/psdk_inc" fullword ascii /* score: '9.00'*/
      $s19 = "mingw_get_invalid_parameter_handler" fullword ascii /* score: '9.00'*/
      $s20 = "C:/crossdev/gccmaster/host-toolchain-tdm64/x86_64-w64-mingw32/include" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

