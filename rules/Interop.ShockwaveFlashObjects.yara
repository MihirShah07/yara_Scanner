/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpmnutr0jh
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Interop_ShockwaveFlashObjects {
   meta:
      description = "tmpmnutr0jh - file Interop.ShockwaveFlashObjects.dll"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "63af704211a03f6ff6530ebfca095b6c97636ab66e5a6de80d167b19c3c30c66"
   strings:
      $s1 = "ShockwaveFlashObjects.dll" fullword ascii /* score: '23.00'*/
      $s2 = "Interop.ShockwaveFlashObjects.dll" fullword wide /* score: '23.00'*/
      $s3 = "get_AllowScriptAccess" fullword ascii /* score: '15.00'*/
      $s4 = "m_FSCommandDelegate" fullword ascii /* score: '12.00'*/
      $s5 = "get_TotalFrames" fullword ascii /* score: '12.00'*/
      $s6 = "FSCommand" fullword ascii /* score: '12.00'*/
      $s7 = "remove_FSCommand" fullword ascii /* score: '12.00'*/
      $s8 = "get_SeamlessTabbing" fullword ascii /* score: '12.00'*/
      $s9 = "get_FrameNum" fullword ascii /* score: '12.00'*/
      $s10 = "add_FSCommand" fullword ascii /* score: '12.00'*/
      $s11 = "_IShockwaveFlashEvents_FSCommandEventHandler" fullword ascii /* score: '12.00'*/
      $s12 = "get_ProfileAddress" fullword ascii /* score: '12.00'*/
      $s13 = "get_SWRemote" fullword ascii /* score: '12.00'*/
      $s14 = "get_ProfilePort" fullword ascii /* score: '12.00'*/
      $s15 = "RemoteInvokeEx" fullword ascii /* score: '11.00'*/
      $s16 = "AllowScriptAccess" fullword ascii /* score: '10.00'*/
      $s17 = "set_AllowScriptAccess" fullword ascii /* score: '10.00'*/
      $s18 = "get_FlashVars" fullword ascii /* score: '9.00'*/
      $s19 = "get_AlignMode" fullword ascii /* score: '9.00'*/
      $s20 = "get_InlineData" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      8 of them
}

