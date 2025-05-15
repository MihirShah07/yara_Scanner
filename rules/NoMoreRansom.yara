/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpgmm9mq_9
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule NoMoreRansom {
   meta:
      description = "tmpgmm9mq_9 - file NoMoreRansom.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "2aab13d49b60001de3aa47fb8f7251a973faa7f3c53a3840cdf5fd0b26e9a09f"
   strings:
      $x1 = ".The specified target is unknown or unreachable0The Local Security Authority cannot be contacted-The requested security package " wide /* score: '39.00'*/
      $x2 = "RichEdit line insertion error %s is already associated with %sE%d is an invalid PageIndex value.  PageIndex must be between 0 an" wide /* score: '36.00'*/
      $x3 = "The credentials supplied were not complete, and could not be verified. Additional information can be returned from the context.4" wide /* score: '35.00'*/
      $s4 = "An attempt was made by this server to make a Kerberos constrained delegation request for a target outside of the server\\'s real" wide /* score: '23.00'*/
      $s5 = "The logon attempt failed;The credentials supplied to the package were not recognized4No credentials are available in the securit" wide /* score: '23.00'*/
      $s6 = "-Smartcard logon is required and was not used.!A system shutdown is in progress.'An invalid request was sent to the KDC.DThe KDC" wide /* score: '22.00'*/
      $s7 = "acPlayerConfigExecute" fullword ascii /* score: '21.00'*/
      $s8 = "EThe function completed successfully, but CompleteToken must be calledtThe function completed successfully, but both CompleteTok" wide /* score: '21.00'*/
      $s9 = "Error getting SSL method.%Error setting File Descriptor for SSL!Error binding data to SSL socket.+EOF was observed that violates" wide /* score: '21.00'*/
      $s10 = "Invalid UTF7 Input is not an valid %s format.)Hash function have to many bits processed" fullword wide /* score: '21.00'*/
      $s11 = "&(c) Copyright 2016 StationPlaylist.com" fullword ascii /* score: '20.00'*/
      $s12 = "The security context could not be established due to a failure in the requested quality of service (e.g. mutual authentication o" wide /* score: '20.00'*/
      $s13 = "acGainScanExecute" fullword ascii /* score: '19.00'*/
      $s14 = "acScanFilesExecute" fullword ascii /* score: '19.00'*/
      $s15 = "acSetSegueExecute" fullword ascii /* score: '18.00'*/
      $s16 = "acTestHookLenExecute" fullword ascii /* score: '18.00'*/
      $s17 = "acSetOverlapExecute" fullword ascii /* score: '18.00'*/
      $s18 = "acOpenContainingExecute" fullword ascii /* score: '18.00'*/
      $s19 = "acJumpStartExecute" fullword ascii /* score: '18.00'*/
      $s20 = "acTestOverlapExecute" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

