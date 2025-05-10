rule Backdoor_ssh {
meta:
author = "Kaspersky"
reference = "https://securelist.com/energetic-bear-crouching-yeti/85345/"
actor = "Energetic Bear/Crouching Yeti"
strings:
$a1 = "OpenSSH"
$a2 = "usage: ssh"
$a3 = "HISTFILE"
condition:
all of ($a*)
}
