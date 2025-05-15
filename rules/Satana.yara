/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpsub3ci2z
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpsub3ci2z_Satana {
   meta:
      description = "tmpsub3ci2z - file Satana.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96"
   strings:
      $s1 = "5rhQJGe:aT6waT1WbQFkhsIwagVQHWtRFP3UHRdQkQFgZ0JQ21Mw1TPdWMVQa@DdWGhEAA7QWQ3eBdleGBBQWR7NBtN@DV3QGtkMK{dGWRRQB33sJi6MBBHQ@RkGZDAm" ascii /* score: '28.00'*/
      $s2 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii /* score: '23.00'*/
      $s3 = "d:\\lbetwmwy\\uijeuqplfwub.pdb" fullword ascii /* score: '17.00'*/
      $s4 = "re xmlns:ms_windowsSettings=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\" xmlns=\"http://schemas.microsoft.com/SMI/2" ascii /* score: '17.00'*/
      $s5 = "FQ7QKkFfFQ7QKkKvKkFfFQ7QKkFfFQ7QKkFfFf7fFQ7QKkFfFQ7QKkFfFQ7Q4k7QKkFfFQ7QKkFfFQ7QKkKvKkFfFQ7QKkFfFQ7QKkFfFf7fFQ7QKkFfFQ7QKkFfFQ7Q" ascii /* score: '11.00'*/
      $s6 = "Ftp2rndRFn{vFAUyOB@QKrwlMsFPaMYuFIFV7A2uQs[mf{Kmq3mwn4U0qQKms1(hP[Yes6EesTOaqL[2hBZQ6TEbOjupon3QaD2wFapzNyZQqrDqbNUPOD1{Grwl,s;Q" ascii /* score: '9.00'*/
      $s7 = "4$4*4B4_4" fullword ascii /* score: '9.00'*/ /* hex encoded string 'DKD' */
      $s8 = "FRkMGdJZB{hJFQ:MVF2J@T2wF371FWhEKtdJWQF:ARtf@F3sBkNGDlMAWW7YGA;QDV35GAhLAPhIBdswFQF6sztABQJYPAFrIWlhHUgMEVdfFEYeWVBYAQUMKkALaVdh" ascii /* score: '9.00'*/
      $s9 = "NiLI[r31@U0dUo0p7UZ[WBFE7Ua:,e3:hkFZkWV2kny:SRKnHJV2`3gjy,3Unr:kFT;YTtwjDVUlGREY,Y:jeyEdeg3waTFQfKVtZQFOZiPoJQD:,QFOZrv,aBwjuUD;" ascii /* score: '9.00'*/
      $s10 = "1ntO6D,vVb{u4r:u@4EVdi3KNQJPpR[YFn4vqQEuDWqnufGZ;USP;AQm@(QihQWvF5u{EHRZdo5h@{eh`Ak{Fi;EmftpNqEN3AZ:AeDQKvGdUeKz3[nPfAoWDKoD;Q[{" ascii /* score: '9.00'*/
      $s11 = "ogF`FRw7FduAKL;ZFtplhABOhD0swuARDq6j1((RDMVH[klRoGR7ho;4aE;7hYMeLIGoLIRPKrzU@55N@:F7FUGQIa2K@sG[ITOaHIIeqIBo;YGoHIemoE6DK77OBqBE" ascii /* score: '9.00'*/
      $s12 = "SkhNK{hZBLMEHG;,dWpvSzdQOGhlWPVlOG3UWFziE@RfLdJbVUwYSQ;@GlF4agEwAddeBtikTHBRet[RA0Fpt2dGJ@VjOzFkBd7NBfNsZhlF@bERPBoOZBUdFQ6BjhzQ" ascii /* score: '9.00'*/
      $s13 = "hazmlbt" fullword ascii /* score: '8.00'*/
      $s14 = "wemzgrdwugjw" fullword ascii /* score: '8.00'*/
      $s15 = "tydqcgfwwka" fullword ascii /* score: '8.00'*/
      $s16 = "kaxkytpp" fullword ascii /* score: '8.00'*/
      $s17 = "blfmaqhzknqdixy" fullword ascii /* score: '8.00'*/
      $s18 = "fxpusugcfbhgdacizktsh" fullword ascii /* score: '8.00'*/
      $s19 = "hcqzqdnqhvfbsrryd" fullword ascii /* score: '8.00'*/
      $s20 = "hedbzlnpahqxkz" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

