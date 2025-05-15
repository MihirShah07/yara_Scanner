/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmprnw41lwq
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmprnw41lwq_Floxif {
   meta:
      description = "tmprnw41lwq - file Floxif.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "812af0ec9e1dfd8f48b47fd148bafe6eecb42d0a304bc0e4539750dd23820a7f"
   strings:
      $s1 = "d:\\PinyinDev_R_6_7_0\\Bin\\SogouPdb\\SogouInput\\SGDownload.pdb" fullword ascii /* score: '28.00'*/
      $s2 = "SGDownload.exe" fullword wide /* score: '28.00'*/
      $s3 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x8" ascii /* score: '27.00'*/
      $s4 = "http://ping.pinyin.sogou.com/sgdownload.gif?h=%s&r=%s&v=%s&s=%u&d=%d&u=%S&t=%d&dz=%d" fullword ascii /* score: '26.00'*/
      $s5 = "http://p3p.sogou.com/bandwidth/Dllimit?hid=%s&status=begin&speed=0&sig=%u&url=%s" fullword ascii /* score: '25.00'*/
      $s6 = "http://p3p.sogou.com/bandwidth/Dllimit?hid=%s&sig=%u&status=end&url=%s" fullword ascii /* score: '25.00'*/
      $s7 = "\\\\.\\pipe\\sgdownloadpipenew2" fullword wide /* score: '25.00'*/
      $s8 = "ziplib.dll" fullword wide /* score: '23.00'*/
      $s9 = "crashrpt.exe" fullword wide /* score: '22.00'*/
      $s10 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x8" ascii /* score: '21.00'*/
      $s11 = ".?AVt_ipcServerExecuterHttpUpload@@" fullword ascii /* score: '21.00'*/
      $s12 = ".?AVt_ipcServerExecuterHttp@@" fullword ascii /* score: '21.00'*/
      $s13 = "p3p.sogou.com" fullword ascii /* score: '21.00'*/
      $s14 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.00; Windows 98; SoDA)" fullword ascii /* score: '20.00'*/
      $s15 = "B\\HWSignature.dll" fullword wide /* score: '20.00'*/
      $s16 = ".?AVt_ipcServerExecuterBase@@" fullword ascii /* score: '18.00'*/
      $s17 = ".?AVt_ipcServerTaskExecuteTaskInWaitQueue@@" fullword ascii /* score: '18.00'*/
      $s18 = "you@youraddr.com" fullword ascii /* score: '18.00'*/
      $s19 = ".?AVt_ipcServerExecuterSoDA@@" fullword ascii /* score: '18.00'*/
      $s20 = ".?AVt_ipcServerTaskQuitExecuterSerial@@" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

