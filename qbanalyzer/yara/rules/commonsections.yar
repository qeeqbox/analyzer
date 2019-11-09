rule Control_Flow_Guard_Detecton_1
{
meta:
    description = "Control Flow Guard"
strings:
    $ = ".00cfg"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule a_section_present_inside_the_apisetschema_dll_Detecton_1
{
meta:
    description = "a section present inside the apisetschema.dll"
strings:
    $ = ".apiset"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Alpha_architecture_section_Detecton_1
{
meta:
    description = "Alpha-architecture section"
strings:
    $ = ".arch"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule cygwin_gcc_Detecton_1
{
meta:
    description = "cygwin/gcc"
strings:
    $ = ".autoload_text"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule LUA_Binary_data_Detecton_1
{
meta:
    description = "LUA Binary data"
strings:
    $ = ".bindat"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule palette_entries_Detecton_1
{
meta:
    description = "palette entries"
strings:
    $ = ".bootdat"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Uninitialized_Data_Section_Detecton_1
{
meta:
    description = "Uninitialized Data Section"
strings:
    $ = ".bss"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Uninitialized_Data_Section_Detecton_2
{
meta:
    description = "Uninitialized Data Section"
strings:
    $ = ".BSS"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule gcc_cygwin_debug_information_Detecton_1
{
meta:
    description = "gcc/cygwin debug information"
strings:
    $ = ".buildid"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule CLR_Unhandled_Exception_Handler_section_Detecton_1
{
meta:
    description = ".CLR Unhandled Exception Handler section"
strings:
    $ = ".CLR_UEF"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Code_Section_Detecton_1
{
meta:
    description = "Code Section"
strings:
    $ = ".code"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule CLR_Metadata_Section_Detecton_1
{
meta:
    description = ".CLR Metadata Section"
strings:
    $ = ".cormeta"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule compiled_LUA_Detecton_1
{
meta:
    description = "compiled LUA"
strings:
    $ = ".complua"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Initialized_Data_Section_C_RunTime__Detecton_1
{
meta:
    description = "Initialized Data Section  (C RunTime)"
strings:
    $ = ".CRT"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule cygwin_section_Detecton_1
{
meta:
    description = "cygwin section"
strings:
    $ = ".cygwin_dll_common"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Data_Section_Detecton_1
{
meta:
    description = "Data Section"
strings:
    $ = ".data"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Data_Section_Detecton_2
{
meta:
    description = "Data Section"
strings:
    $ = ".DATA"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Data_Section_Detecton_3
{
meta:
    description = "Data Section"
strings:
    $ = ".data1"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Data_Section_Detecton_4
{
meta:
    description = "Data Section"
strings:
    $ = ".data2"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Data_Section_Detecton_5
{
meta:
    description = "Data Section"
strings:
    $ = ".data3"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Debug_info_Section_Detecton_1
{
meta:
    description = "Debug info Section"
strings:
    $ = ".debug"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Debug_info_Section_Visual_C_version_7_0__Detecton_1
{
meta:
    description = "Debug info Section (Visual C++ version <7.0)"
strings:
    $ = ".debug$F"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule directive_section_temporary__Detecton_1
{
meta:
    description = "directive section (temporary)"
strings:
    $ = ".drectve "
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Delay_Import_Section_Detecton_1
{
meta:
    description = "Delay Import Section"
strings:
    $ = ".didat"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Delay_Import_Section_Detecton_2
{
meta:
    description = "Delay Import Section"
strings:
    $ = ".didata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Export_Data_Section_Detecton_1
{
meta:
    description = "Export Data Section"
strings:
    $ = ".edata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule gcc_cygwin_Exception_Handler_Frame_section_Detecton_1
{
meta:
    description = "gcc/cygwin; Exception Handler Frame section"
strings:
    $ = ".eh_fram"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Alternative_Export_Data_Section_Detecton_1
{
meta:
    description = "Alternative Export Data Section"
strings:
    $ = ".export"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule FASM_flat_Section_Detecton_1
{
meta:
    description = "FASM flat Section"
strings:
    $ = ".fasm"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule FASM_flat_Section_Detecton_2
{
meta:
    description = "FASM flat Section"
strings:
    $ = ".flat"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule section_added_by_new_Visual_Studio_14_0__Detecton_1
{
meta:
    description = "section added by new Visual Studio (14.0)"
strings:
    $ = ".gfids"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule section_added_by_new_Visual_Studio_14_0__Detecton_2
{
meta:
    description = "section added by new Visual Studio (14.0)"
strings:
    $ = ".giats"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule section_added_by_new_Visual_Studio_14_0__Detecton_3
{
meta:
    description = "section added by new Visual Studio (14.0)"
strings:
    $ = ".gljmp"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule ARMv7_core_glue_functions_thumb_mode__Detecton_1
{
meta:
    description = "ARMv7 core glue functions (thumb mode)"
strings:
    $ = ".glue_7t"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule ARMv7_core_glue_functions_32_bit_ARM_mode__Detecton_1
{
meta:
    description = "ARMv7 core glue functions (32-bit ARM mode)"
strings:
    $ = ".glue_7"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Initialized_Data_Section_Borland__Detecton_1
{
meta:
    description = "Initialized Data Section  (Borland)"
strings:
    $ = ".idata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule IDL_Attributes_registered_SEH__Detecton_1
{
meta:
    description = "IDL Attributes (registered SEH)"
strings:
    $ = ".idlsym"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Alternative_Import_data_section_Detecton_1
{
meta:
    description = "Alternative Import data section"
strings:
    $ = ".impdata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Alternative_Import_data_section_Detecton_2
{
meta:
    description = "Alternative Import data section"
strings:
    $ = ".import"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Code_Section_Borland__Detecton_1
{
meta:
    description = "Code Section  (Borland)"
strings:
    $ = ".itext"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Nullsoft_Installer_section_Detecton_1
{
meta:
    description = "Nullsoft Installer section"
strings:
    $ = ".ndata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Code_section_inside_rpcrt4_dll_Detecton_1
{
meta:
    description = "Code section inside rpcrt4.dll"
strings:
    $ = ".orpc"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Exception_Handling_Functions_Section_PDATA_records__Detecton_1
{
meta:
    description = "Exception Handling Functions Section (PDATA records)"
strings:
    $ = ".pdata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Read_only_initialized_Data_Section_MS_and_Borland__Detecton_1
{
meta:
    description = "Read-only initialized Data Section  (MS and Borland)"
strings:
    $ = ".rdata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Relocations_Section_Detecton_1
{
meta:
    description = "Relocations Section"
strings:
    $ = ".reloc"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Read_only_Data_Section_Detecton_1
{
meta:
    description = "Read-only Data Section"
strings:
    $ = ".rodata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Resource_section_Detecton_1
{
meta:
    description = "Resource section"
strings:
    $ = ".rsrc"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule GP_relative_Uninitialized_Data_Section_Detecton_1
{
meta:
    description = "GP-relative Uninitialized Data Section"
strings:
    $ = ".sbss"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Section_containing_script_Detecton_1
{
meta:
    description = "Section containing script"
strings:
    $ = ".script"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Shared_section_Detecton_1
{
meta:
    description = "Shared section"
strings:
    $ = ".shared"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule GP_relative_Initialized_Data_Section_Detecton_1
{
meta:
    description = "GP-relative Initialized Data Section"
strings:
    $ = ".sdata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule GP_relative_Read_only_Data_Section_Detecton_1
{
meta:
    description = "GP-relative Read-only Data Section"
strings:
    $ = ".srdata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Created_by_Haskell_compiler_GHC__Detecton_1
{
meta:
    description = "Created by Haskell compiler (GHC)"
strings:
    $ = ".stab"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Created_by_Haskell_compiler_GHC__Detecton_2
{
meta:
    description = "Haskell compiler (GHC)"
strings:
    $ = ".stabstr"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Registered_Exception_Handlers_Section_Detecton_1
{
meta:
    description = "Registered Exception Handlers Section"
strings:
    $ = ".sxdata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Code_Section_Detecton_2
{
meta:
    description = "Code Section"
strings:
    $ = ".text"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Alternative_Code_Section_Detecton_1
{
meta:
    description = "Alternative Code Section"
strings:
    $ = ".text0"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Alternative_Code_Section_Detecton_2
{
meta:
    description = "Alternative Code Section"
strings:
    $ = ".text1"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Alternative_Code_Section_Detecton_3
{
meta:
    description = "Alternative Code Section"
strings:
    $ = ".text2"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Alternative_Code_Section_Detecton_4
{
meta:
    description = "Alternative Code Section"
strings:
    $ = ".text3"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Section_used_by_incremental_linking_Detecton_1
{
meta:
    description = "Section used by incremental linking"
strings:
    $ = ".textbss"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Thread_Local_Storage_Section_Detecton_1
{
meta:
    description = "Thread Local Storage Section"
strings:
    $ = ".tls"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Thread_Local_Storage_Section_Detecton_2
{
meta:
    description = "Thread Local Storage Section"
strings:
    $ = ".tls$"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Uninitialized_Data_Section_Detecton_3
{
meta:
    description = "Uninitialized Data Section"
strings:
    $ = ".udata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule GP_relative_Initialized_Data_Detecton_1
{
meta:
    description = "GP-relative Initialized Data"
strings:
    $ = ".vsdata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Exception_Information_Section_Detecton_1
{
meta:
    description = "Exception Information Section"
strings:
    $ = ".xdata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Wix_section_Detecton_1
{
meta:
    description = "Wix section"
strings:
    $ = ".wixburn"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule WPP_Windows_software_trace_PreProcessor__Detecton_1
{
meta:
    description = "WPP (Windows software trace PreProcessor)"
strings:
    $ = ".wpp_sf "
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Uninitialized_Data_Section_Borland__Detecton_1
{
meta:
    description = "Uninitialized Data Section  (Borland)"
strings:
    $ = "BSS"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Code_Section_Borland__Detecton_2
{
meta:
    description = "Code Section (Borland)"
strings:
    $ = "CODE"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Data_Section_Borland__Detecton_1
{
meta:
    description = "Data Section (Borland)"
strings:
    $ = "DATA"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Legacy_data_group_section_Detecton_1
{
meta:
    description = "Legacy data group section"
strings:
    $ = "DGROUP"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Export_Data_Section_Detecton_2
{
meta:
    description = "Export Data Section"
strings:
    $ = "edata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Initialized_Data_Section_C_RunTime__Detecton_2
{
meta:
    description = "Initialized Data Section  (C RunTime)"
strings:
    $ = "idata"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule INIT_section_drivers__Detecton_1
{
meta:
    description = "INIT section (drivers)"
strings:
    $ = "INIT"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule Active_Template_Library_ATL__Detecton_1
{
meta:
    description = "Active Template Library (ATL)"
strings:
    $ = "minATL"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}

rule PAGE_section_drivers__Detecton_1
{
meta:
    description = "PAGE section (drivers)"
strings:
    $ = "PAGE"
condition:
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (for any of them : ( $ in (0..1024) ))
}
