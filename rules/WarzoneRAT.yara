/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpues_p6hh
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule WarzoneRAT {
   meta:
      description = "tmpues_p6hh - file WarzoneRAT.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "61e6a93f43049712b5f2d949fd233fa8015fe4bef01b9e1285d3d87b12f894f2"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADh4W" fullword ascii /* score: '27.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD^V" fullword ascii /* score: '27.00'*/
      $s4 = "trtljApcZp.exe" fullword wide /* score: '22.00'*/
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s6 = "logoPictureBox.Image" fullword wide /* score: '12.00'*/
      $s7 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s8 = "get_AssemblyDescription" fullword ascii /* score: '11.00'*/
      $s9 = "GetNormal" fullword ascii /* score: '9.00'*/
      $s10 = "GetIntersectVector" fullword ascii /* score: '9.00'*/
      $s11 = "get_PlayGround" fullword ascii /* score: '9.00'*/
      $s12 = "get_rrrrrrrrrrrrrrrr5" fullword ascii /* score: '9.00'*/
      $s13 = "get_Backbuffer" fullword ascii /* score: '9.00'*/
      $s14 = "GetBounceVector" fullword ascii /* score: '9.00'*/
      $s15 = "get_Resizing" fullword ascii /* score: '9.00'*/
      $s16 = "get_AssemblyCompany" fullword ascii /* score: '8.00'*/
      $s17 = "deathadder" fullword wide /* score: '8.00'*/
      $s18 = "ctlBreakout_KeyDown" fullword ascii /* score: '7.00'*/
      $s19 = "ctlBreakout_PreviewKeyDown" fullword ascii /* score: '7.00'*/
      $s20 = "labelCompanyName" fullword wide /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

