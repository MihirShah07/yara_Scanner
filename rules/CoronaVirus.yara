/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp1si1zmko
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule CoronaVirus {
   meta:
      description = "tmp1si1zmko - file CoronaVirus.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "dddf7894b2e6aafa1903384759d68455c3a4a8348a7e2da3bd272555eba9bec0"
   strings:
      $s1 = "On a per-widget basis we are occasionally clipping text CPU-side if it won't fit in its frame. Otherwise we are doing coarser cl" ascii /* score: '26.00'*/
      $s2 = "ipping + passing a scissor rectangle to the renderer. The system is designed to try minimizing both execution and CPU/GPU render" ascii /* score: '22.00'*/
      $s3 = "DragDrop: %d, SourceId = 0x%08X, Payload \"%s\" (%d bytes)" fullword ascii /* score: '20.50'*/
      $s4 = "- Read FAQ and docs/FONTS.txt for more details." fullword ascii /* score: '18.00'*/
      $s5 = "SetNextItemWidth/PushItemWidth(GetContentRegionAvail().x * 0.5f)" fullword ascii /* score: '18.00'*/
      $s6 = "We don't have a getter to avoid encouraging you to persistently save values that aren't forward-compatible." fullword ascii /* score: '17.00'*/
      $s7 = "NavWindowingTarget: '%s'" fullword ascii /* score: '17.00'*/
      $s8 = "CSPing.Document+Version %s_VERSION% (Build %s_BUILDNUMBER%)" fullword wide /* score: '17.00'*/
      $s9 = "HSV encoded colors" fullword ascii /* score: '16.00'*/
      $s10 = "imgui_log.txt" fullword ascii /* score: '16.00'*/
      $s11 = "DragDropTarget" fullword ascii /* score: '16.00'*/
      $s12 = "Hjjjjjjjj" fullword wide /* reversed goodware string 'jjjjjjjjH' */ /* score: '16.00'*/
      $s13 = " processors (all in the P5 microarchitecture)." fullword ascii /* score: '15.00'*/
      $s14 = "Unknown command: '%s'" fullword ascii /* score: '15.00'*/
      $s15 = "WARNING - Display string token not recognized:  %s" fullword ascii /* score: '15.00'*/
      $s16 = "Hello.cpp" fullword ascii /* score: '15.00'*/
      $s17 = "<BBBBBBB" fullword ascii /* reversed goodware string 'BBBBBBB<' */ /* score: '14.00'*/
      $s18 = "Read FAQ and docs/FONTS.txt for details on font loading." fullword ascii /* score: '14.00'*/
      $s19 = "invalid framebuffer operation" fullword ascii /* score: '14.00'*/
      $s20 = "Keys mods: %s%s%s%s" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

