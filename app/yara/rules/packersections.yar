/*
__G__ = "(G)bd249ce4"
*/

rule Aspack_packer_Detecton_1
{
meta:
    description = "Aspack packer"
strings:
    $1 = ".aspack"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Aspack_packer_Armadillo_packer_Detecton_1
{
meta:
    description = "Aspack packer/Armadillo packer"
strings:
    $1 = ".adata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Aspack_packer_Detecton_2
{
meta:
    description = "Aspack packer"
strings:
    $1 = "ASPack"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule ASPAck_Protector_Detecton_1
{
meta:
    description = "ASPAck Protector"
strings:
    $1 = ".ASPack"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule CCG_Packer_Chinese_Packer__Detecton_1
{
meta:
    description = "CCG Packer (Chinese Packer)"
strings:
    $1 = ".ccg"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Crunch_2_0_Packer_Detecton_1
{
meta:
    description = "Crunch 2.0 Packer"
strings:
    $1 = "BitArts"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule DAStub_Dragon_Armor_protector_Detecton_1
{
meta:
    description = "DAStub Dragon Armor protector"
strings:
    $1 = "DAStub"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Epack_packer_Detecton_1
{
meta:
    description = "Epack packer"
strings:
    $1 = "!EPack"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule FSG_packer_Detecton_1
{
meta:
    description = "FSG packer"
strings:
    $1 = "FSG!"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule kkrunchy_Packer_Detecton_1
{
meta:
    description = "kkrunchy Packer"
strings:
    $1 = "kkrunchy"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule ImpRec_created_section_Detecton_1
{
meta:
    description = "ImpRec-created section"
strings:
    $1 = ".mackt"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule MaskPE_Packer_Detecton_1
{
meta:
    description = "MaskPE Packer"
strings:
    $1 = ".MaskPE"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule MEW_packer_Detecton_1
{
meta:
    description = "MEW packer"
strings:
    $1 = "MEW"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Mpress_Packer_Detecton_1
{
meta:
    description = "Mpress Packer"
strings:
    $1 = ".MPRESS1"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Mpress_Packer_Detecton_2
{
meta:
    description = "Mpress Packer"
strings:
    $1 = ".MPRESS2"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Neolite_Packer_Detecton_1
{
meta:
    description = "Neolite Packer"
strings:
    $1 = ".neolite"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Neolite_Packer_Detecton_2
{
meta:
    description = "Neolite Packer"
strings:
    $1 = ".neolit"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule NsPack_packer_Detecton_1
{
meta:
    description = "NsPack packer"
strings:
    $1 = ".nsp1"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule NsPack_packer_Detecton_2
{
meta:
    description = "NsPack packer"
strings:
    $1 = ".nsp0"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule NsPack_packer_Detecton_3
{
meta:
    description = "NsPack packer"
strings:
    $1 = ".nsp2"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule NsPack_packer_Detecton_4
{
meta:
    description = "NsPack packer"
strings:
    $1 = "nsp1"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule NsPack_packer_Detecton_5
{
meta:
    description = "NsPack packer"
strings:
    $1 = "nsp0"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule NsPack_packer_Detecton_6
{
meta:
    description = "NsPack packer"
strings:
    $1 = "nsp2"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule PEBundle_Packer_Detecton_1
{
meta:
    description = "PEBundle Packer"
strings:
    $1 = "pebundle"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule PEBundle_Packer_Detecton_2
{
meta:
    description = "PEBundle Packer"
strings:
    $1 = "PEBundle"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule PECompact_packer_Detecton_1
{
meta:
    description = "PECompact packer"
strings:
    $1 = "PEC2TO"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule PECompact_packer_Detecton_2
{
meta:
    description = "PECompact packer"
strings:
    $1 = "PECompact2"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule PECompact_packer_Detecton_3
{
meta:
    description = "PECompact packer"
strings:
    $1 = "PEC2"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule PECompact_packer_Detecton_4
{
meta:
    description = "PECompact packer"
strings:
    $1 = "pec1"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule PECompact_packer_Detecton_5
{
meta:
    description = "PECompact packer"
strings:
    $1 = "pec2"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule PECompact_packer_Detecton_6
{
meta:
    description = "PECompact packer"
strings:
    $1 = "PEC2MO"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule PELock_Protector_Detecton_1
{
meta:
    description = "PELock Protector"
strings:
    $1 = "PELOCKnt"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Perplex_PE_Protector_Detecton_1
{
meta:
    description = "Perplex PE-Protector"
strings:
    $1 = ".perplex"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule PEShield_Packer_Detecton_1
{
meta:
    description = "PEShield Packer"
strings:
    $1 = "PESHiELD"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Petite_Packer_Detecton_1
{
meta:
    description = "Petite Packer"
strings:
    $1 = ".petite"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule ProCrypt_Packer_Detecton_1
{
meta:
    description = "ProCrypt Packer"
strings:
    $1 = "ProCrypt"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule RLPack_Packer_Detecton_1
{
meta:
    description = "RLPack Packer"
strings:
    $1 = ".RLPack"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule RPCrypt_Packer_Detecton_1
{
meta:
    description = "RPCrypt Packer"
strings:
    $1 = "RCryptor"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule RPCrypt_Packer_Detecton_2
{
meta:
    description = "RPCrypt Packer"
strings:
    $1 = ".RPCrypt"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule StarForce_Protection_Detecton_1
{
meta:
    description = "StarForce Protection"
strings:
    $1 = ".sforce3"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Simple_Pack_Detecton_1
{
meta:
    description = "Simple Pack"
strings:
    $1 = ".spack"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule SVKP_packer_Detecton_1
{
meta:
    description = "SVKP packer"
strings:
    $1 = ".svkp"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Themida_Packer_Detecton_1
{
meta:
    description = "Themida Packer"
strings:
    $1 = "Themida"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Themida_Packer_Detecton_2
{
meta:
    description = "Themida Packer"
strings:
    $1 = ".Themida"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Unknown_Packer_Detecton_1
{
meta:
    description = "Unknown Packer"
strings:
    $1 = ".packed"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Upack_packer_Detecton_1
{
meta:
    description = "Upack packer"
strings:
    $1 = ".Upack"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Upack_Packer_Detecton_1
{
meta:
    description = "Upack Packer"
strings:
    $1 = ".ByDwing"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule UPX_packer_Detecton_1
{
meta:
    description = "UPX packer"
strings:
    $1 = "UPX0"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule UPX_packer_Detecton_2
{
meta:
    description = "UPX packer"
strings:
    $1 = "UPX1"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule UPX_packer_Detecton_3
{
meta:
    description = "UPX packer"
strings:
    $1 = "UPX2"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule UPX_packer_Detecton_4
{
meta:
    description = "UPX packer"
strings:
    $1 = "UPX!"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule UPX_Packer_Detecton_1
{
meta:
    description = "UPX Packer"
strings:
    $1 = ".UPX0"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule UPX_Packer_Detecton_2
{
meta:
    description = "UPX Packer"
strings:
    $1 = ".UPX1"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule UPX_Packer_Detecton_3
{
meta:
    description = "UPX Packer"
strings:
    $1 = ".UPX2"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule VMProtect_packer_Detecton_1
{
meta:
    description = "VMProtect packer"
strings:
    $1 = ".vmp0"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule VMProtect_packer_Detecton_2
{
meta:
    description = "VMProtect packer"
strings:
    $1 = ".vmp1"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule VMProtect_packer_Detecton_3
{
meta:
    description = "VMProtect packer"
strings:
    $1 = ".vmp2"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Vprotect_Packer_Detecton_1
{
meta:
    description = "Vprotect Packer"
strings:
    $1 = "VProtect"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule WinLicense_Themida_Protector_Detecton_1
{
meta:
    description = "WinLicense (Themida) Protector"
strings:
    $1 = "WinLicen"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule WWPACK_Packer_Detecton_1
{
meta:
    description = "WWPACK Packer"
strings:
    $1 = ".WWPACK"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Y0da_Protector_Detecton_1
{
meta:
    description = "Y0da Protector"
strings:
    $1 = ".yP"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Y0da_Protector_Detecton_2
{
meta:
    description = "Y0da Protector"
strings:
    $1 = ".y0da"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}
