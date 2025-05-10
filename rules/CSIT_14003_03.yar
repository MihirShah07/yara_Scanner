
rule CSIT_14003_03 : installer RAT
{ 
    meta:
        Description = "Flying Kitten Installer"
        Reference   = "http://blog.crowdstrike.com/cat-scratch-fever-crowdstrike-tracks-newly-reported-iranian-actor-flying-kitten"

    strings:
        $exename = "IntelRapidStart.exe"
        $confname = "IntelRapidStart.exe.config"
        $cabhdr = { 4d 53 43 46 00 00 00 00 } 

    condition:
        all of them
}
