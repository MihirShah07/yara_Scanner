/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp1k5tcoiq
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule AxInterop_ShockwaveFlashObjects {
   meta:
      description = "tmp1k5tcoiq - file AxInterop.ShockwaveFlashObjects.dll"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "0d57a706d4e10cca3aed49b341a651f29046f5ef1328878d616be93c3b4cbce9"
   strings:
      $s1 = "AxInterop.ShockwaveFlashObjects.dll" fullword wide /* score: '23.00'*/
      $s2 = "get_AllowScriptAccess" fullword ascii /* score: '15.00'*/
      $s3 = "remove_FSCommand" fullword ascii /* score: '12.00'*/
      $s4 = "get_SeamlessTabbing" fullword ascii /* score: '12.00'*/
      $s5 = "add_FSCommand" fullword ascii /* score: '12.00'*/
      $s6 = "get_ProfilePort" fullword ascii /* score: '12.00'*/
      $s7 = "RaiseOnFSCommand" fullword ascii /* score: '12.00'*/
      $s8 = "_IShockwaveFlashEvents_FSCommandEventHandler" fullword ascii /* score: '12.00'*/
      $s9 = "get_FrameNum" fullword ascii /* score: '12.00'*/
      $s10 = "get_TotalFrames" fullword ascii /* score: '12.00'*/
      $s11 = "FSCommand" fullword ascii /* score: '12.00'*/
      $s12 = "get_ProfileAddress" fullword ascii /* score: '12.00'*/
      $s13 = "get_SWRemote" fullword ascii /* score: '12.00'*/
      $s14 = "_IShockwaveFlashEvents_FSCommandEvent" fullword ascii /* score: '12.00'*/
      $s15 = "set_AllowScriptAccess" fullword ascii /* score: '10.00'*/
      $s16 = "AllowScriptAccess" fullword ascii /* score: '10.00'*/
      $s17 = "get_MovieData" fullword ascii /* score: '9.00'*/
      $s18 = "get_AllowFullScreen" fullword ascii /* score: '9.00'*/
      $s19 = "TGetProperty" fullword ascii /* score: '9.00'*/
      $s20 = "get_EmbedMovie" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      8 of them
}

