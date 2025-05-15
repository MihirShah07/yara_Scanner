/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpdvtkesy3
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpdvtkesy3_Nostart {
   meta:
      description = "tmpdvtkesy3 - file Nostart.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "2f10f1384f3513f573a88e1771c740a973a5a304387e23aa4bf310794532fa8e"
   strings:
      $s1 = "wwwpwwwwwwwwwwwwwwww" fullword ascii /* reversed goodware string 'wwwwwwwwwwwwwwwwpwww' */ /* score: '18.00'*/
      $s2 = "List count out of bounds (%d)+Operation not allowed on sorted string list%String list does not allow duplicates#A component name" wide /* score: '14.00'*/
      $s3 = "Please reset your machine with the reset button - NOT Ctrl-Alt-Delete - as this will cause a fatal error which can only be recti" ascii /* score: '11.00'*/
      $s4 = "Please reset your machine with the reset button - NOT Ctrl-Alt-Delete - as this will cause a fatal error which can only be recti" ascii /* score: '11.00'*/
      $s5 = "Windows System Failure" fullword ascii /* score: '10.00'*/
      $s6 = "Windows has raised an exception error &&07564aaabH.  You MUST restart the system now." fullword ascii /* score: '10.00'*/
      $s7 = "Bits index out of range/Menu '%s' is already being used by another form" fullword wide /* score: '10.00'*/
      $s8 = "Invalid ImageList Index)Failed to read ImageList data from stream$Error creating window device context" fullword wide /* score: '10.00'*/
      $s9 = "<2<,=4=?=" fullword ascii /* score: '9.00'*/ /* hex encoded string '$' */
      $s10 = "94:@:D:P:T:\\:`:d:h:l:p:t:x:|:" fullword ascii /* score: '7.00'*/
      $s11 = "TurnSysKeysBackOn" fullword ascii /* score: '7.00'*/
      $s12 = "TThreadList\\" fullword ascii /* score: '7.00'*/
      $s13 = "EFOpenError\\" fullword ascii /* score: '7.00'*/
      $s14 = "TurnSysKeysOff" fullword ascii /* score: '7.00'*/
      $s15 = "ShareImages(" fullword ascii /* score: '7.00'*/
      $s16 = "OnKeyPress|" fullword ascii /* score: '7.00'*/
      $s17 = "Booleanp" fullword ascii /* score: '6.00'*/
      $s18 = "TImageList8" fullword ascii /* score: '5.00'*/
      $s19 = "$''%s'' is not a valid component nameA class named %s already exists" fullword wide /* score: '5.00'*/
      $s20 = "TControlScrollBar|3B" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

