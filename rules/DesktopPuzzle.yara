/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpp3n9ouzt
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule DesktopPuzzle {
   meta:
      description = "tmpp3n9ouzt - file DesktopPuzzle.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "1f5a26f24a2bfdd301008f0cc51a6c3762f41b926f974c814f1ecaa4cb28e5e6"
   strings:
      $s1 = "e-mail : andy_feys@hotmail.com" fullword ascii /* score: '18.00'*/
      $s2 = "0http://www.fortunecity.com/skyscraper/binary/44/" fullword ascii /* score: '17.00'*/
      $s3 = "0M0Y0b0h0" fullword ascii /* base64 encoded string '3F4oHt' */ /* score: '11.00'*/
      $s4 = "EComponentError@" fullword ascii /* score: '10.00'*/
      $s5 = "Bits index out of range/Menu '%s' is already being used by another form" fullword wide /* score: '10.00'*/
      $s6 = "=)=5=;=F=" fullword ascii /* score: '9.00'*/ /* hex encoded string '_' */
      $s7 = "funmain" fullword ascii /* score: '8.00'*/
      $s8 = ":&:*:<:H:L:X:\\:d:h:l:p:t:x:|:" fullword ascii /* score: '7.00'*/
      $s9 = "EWriteErrord" fullword ascii /* score: '7.00'*/
      $s10 = "ver it is you're doing ! Use the cursor keys to move the pieces (black piece is the empty one)." fullword ascii /* score: '7.00'*/
      $s11 = "ShareImages(" fullword ascii /* score: '7.00'*/
      $s12 = "OnDragDrop," fullword ascii /* score: '6.00'*/
      $s13 = "frmFunStuff2" fullword ascii /* score: '5.00'*/
      $s14 = "TStringList0" fullword ascii /* score: '5.00'*/
      $s15 = "TButton4" fullword ascii /* score: '5.00'*/
      $s16 = "FocusControl8" fullword ascii /* score: '5.00'*/
      $s17 = "TfrmFunStuff2" fullword ascii /* score: '5.00'*/
      $s18 = "THintWindow8" fullword ascii /* score: '5.00'*/
      $s19 = "77$7,767" fullword ascii /* score: '5.00'*/ /* hex encoded string 'wwg' */
      $s20 = "CopyMode8" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

