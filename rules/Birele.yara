/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmphf9vjfa_
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmphf9vjfa__Birele {
   meta:
      description = "tmphf9vjfa_ - file Birele.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "b2dcfdf9e7b09f2aa5004668370e77982963ace820e7285b2e264a294441da23"
   strings:
      $s1 = "Try.exe" fullword wide /* score: '19.00'*/
      $s2 = "iViRCvSJeRSn2" fullword ascii /* score: '10.00'*/
      $s3 = "5Bxyp:\"M" fullword ascii /* score: '10.00'*/
      $s4 = "GetStdHandleCreat" fullword ascii /* score: '9.00'*/
      $s5 = "gxmS47H56" fullword ascii /* score: '8.00'*/
      $s6 = "DrsCommLineTRvd" fullword ascii /* score: '7.00'*/
      $s7 = "7JkPeOn7RWQhdyCLofc8218hOI1UfRUn" fullword ascii /* score: '7.00'*/
      $s8 = "QUpigEJQ5.ndjN" fullword ascii /* score: '7.00'*/
      $s9 = "jw3BiNJABP4gBC88kOod,jrfbxVX2" fullword ascii /* score: '7.00'*/
      $s10 = "Pinnacle Systems" fullword wide /* score: '7.00'*/
      $s11 = "BWDCSQNH" fullword ascii /* score: '6.50'*/
      $s12 = "YVLfqXB0" fullword ascii /* score: '5.00'*/
      $s13 = "yRAXN48" fullword ascii /* score: '5.00'*/
      $s14 = "ccKpcTIE5" fullword ascii /* score: '5.00'*/
      $s15 = "oBtlhI3" fullword ascii /* score: '5.00'*/
      $s16 = "XELIynY8" fullword ascii /* score: '5.00'*/
      $s17 = "nkKHrISuzuDVP4" fullword ascii /* score: '5.00'*/
      $s18 = "IBgGpOl4" fullword ascii /* score: '5.00'*/
      $s19 = "FfHBFDV1" fullword ascii /* score: '5.00'*/
      $s20 = "GiGmBqN1" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

