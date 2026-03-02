rule SME_RedLine_Stealer_Generic {
    meta:
        description = "RedLine Stealer - Generic Pattern for Packed Samples"
        cape_type = "RedLine Payload"
        family = "RedLine"
        severity = 3

    strings:
        $path1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii wide
        $path2 = "\\Freebl3.dll" ascii wide
        $path3 = "\\mozglue.dll" ascii wide
        
        $xml1 = "ArrayOfanyType" ascii wide
        $xml2 = "rootElement" ascii wide
        
        $key1 = "Grabber" ascii wide
        $key2 = "Entity" ascii wide

    condition:
        2 of them
}
