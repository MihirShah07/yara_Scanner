/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp5_s_2qc3
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule NETFramework {
   meta:
      description = "tmp5_s_2qc3 - file NETFramework.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "65a7cb8fd1c7c529c40345b4746818f8947be736aa105007dfcc57b05897ed62"
   strings:
      $s1 = "C:\\NetFXDev1\\binaries\\x86ret\\bin\\i386\\VSSetup\\Utils\\boxstub.pdb" fullword ascii /* score: '25.00'*/
      $s2 = " <assemblyIdentity name=\"BoxStub\" version=\"1.0.0.0\" processorArchitecture=\"x86\" type=\"win32\"/>" fullword ascii /* score: '19.00'*/
      $s3 = "NDP471-KB4033344-Web.exe" fullword wide /* score: '16.00'*/
      $s4 = "Failed to set access for Users group" fullword ascii /* score: '15.00'*/
      $s5 = "%_SFX_CAB_EXE_PATH%\\Setup.exe %_SFX_CAB_EXE_PARAMETERS% /x86 /x64 /web" fullword wide /* score: '15.00'*/
      $s6 = "http://microsoft.com0/" fullword ascii /* score: '14.00'*/
      $s7 = "Failed to set security descriptor owner" fullword ascii /* score: '13.00'*/
      $s8 = "CreateProcess failed with 0x%x.  Retrying..." fullword ascii /* score: '13.00'*/
      $s9 = "Failed to set security descriptor DACL" fullword ascii /* score: '13.00'*/
      $s10 = "Failed to initialize security descriptor" fullword ascii /* score: '13.00'*/
      $s11 = "      <!-- Windows Vista -->" fullword ascii /* score: '12.00'*/
      $s12 = "      <!-- Windows 8.1 -->" fullword ascii /* score: '12.00'*/
      $s13 = "      <!-- Windows 8 -->" fullword ascii /* score: '12.00'*/
      $s14 = "      <!-- Windows 10 -->" fullword ascii /* score: '12.00'*/
      $s15 = "      <!-- Windows 7 -->" fullword ascii /* score: '12.00'*/
      $s16 = "       <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>" fullword ascii /* score: '11.00'*/
      $s17 = "Failed to allocate space for commandline." fullword ascii /* score: '11.00'*/
      $s18 = " <description>Box Stub</description>" fullword ascii /* score: '10.00'*/
      $s19 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s20 = "       processorArchitecture=\"X86\" " fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

