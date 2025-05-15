/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmph2dkbad4
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmph2dkbad4_Bezilom {
   meta:
      description = "tmph2dkbad4 - file Bezilom.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "94d2b1da2c4ce7db94ee9603bc2f81386032687e7c664aff6460ba0f5dac0022"
   strings:
      $s1 = "Scripting.FileSystemObject" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s2 = "Set oTemplate = NormalTemplate.VBProject.VBComponents.Item(1)" fullword wide /* score: '15.00'*/
      $s3 = "CopyFiles.txt" fullword wide /* score: '14.00'*/
      $s4 = "*\\AA:\\bez outlooka\\Zimmer.vbp" fullword wide /* score: '13.00'*/
      $s5 = "DisplayAsIcon:=False, Left:=ActiveDocument.PageSetup.LeftMargin + 115, Top:=ActiveDocument.PageSetup.TopMargin -11, Width:=37, H" wide /* score: '12.00'*/
      $s6 = "ilom bez outlooka\\z\\Zimmer.vbp" fullword wide /* score: '11.00'*/
      $s7 = "Set oDocument = ActiveDocument.VBProject.VBComponents.Item(1)" fullword wide /* score: '11.00'*/
      $s8 = "iTempCountOfLines = oTemplate.CodeModule.CountOfLines" fullword wide /* score: '11.00'*/
      $s9 = "If iTempCountOfLines <> 41 Then" fullword wide /* score: '11.00'*/
      $s10 = "  oTemplate.CodeModule.DeleteLines 1, iTempCountOfLines" fullword wide /* score: '11.00'*/
      $s11 = "  oTemplate.CodeModule.AddFromString " fullword wide /* score: '11.00'*/
      $s12 = "  Do While oTemplate.CodeModule.Lines(iLines, 1) <> \"" fullword wide /* score: '11.00'*/
      $s13 = "Maria.doc" fullword wide /* score: '10.00'*/
      $s14 = "modInfectWord" fullword ascii /* score: '9.00'*/
      $s15 = "GetFolder" fullword wide /* score: '9.00'*/
      $s16 = "Private Sub Document_Open()" fullword wide /* score: '7.00'*/
      $s17 = "On Error Resume Next" fullword wide /* score: '7.00'*/
      $s18 = "\"Private Sub Document_Close()\"" fullword wide /* score: '7.00'*/
      $s19 = "\"Private Sub Document_Open()\"" fullword wide /* score: '7.00'*/
      $s20 = "Selection.ShapeRange.WrapFormat.AllowOverlap = True" fullword wide /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      8 of them
}

