/*
_G_ = "(G)bd249ce4"
*/

rule AOL_parameter_info_files
{
meta:
    description = "AOL_parameter_info_files"
strings:
    $1 = { 41 43 53 44 }
condition:
    $1 at 0
}

rule Binary_property_list_plist
{
meta:
    description = "Binary_property_list_plist_"
strings:
    $1 = { 62 70 6C 69 73 74 }
condition:
    $1 at 0
}

rule BIOS_details_in_RAM
{
meta:
    description = "BIOS_details_in_RAM"
strings:
    $1 = { 00 14 00 00 01 02 }
condition:
    $1 at 0
}

rule cpio_archive
{
meta:
    description = "cpio_archive"
strings:
    $1 = { 30 37 30 37 30 }
condition:
    $1 at 0
}

rule ELF_executable
{
meta:
    description = "ELF_executable"
strings:
    $1 = { 7F 45 4C 46 }
condition:
    $1 at 0
}

rule Extended_tcpdump_libpcap_capture_file
{
meta:
    description = "Extended_tcpdump_libpcap_capture_file"
strings:
    $1 = { A1 B2 CD 34 }
condition:
    $1 at 0
}

rule INFO2_Windows_recycle_bin_1
{
meta:
    description = "INFO2_Windows_recycle_bin_1"
strings:
    $1 = { 04 00 00 00 }
condition:
    $1 at 0
}

rule INFO2_Windows_recycle_bin_2
{
meta:
    description = "INFO2_Windows_recycle_bin_2"
strings:
    $1 = { 05 00 00 00 }
condition:
    $1 at 0
}

rule Java_serialization_data
{
meta:
    description = "Java_serialization_data"
strings:
    $1 = { AC ED }
condition:
    $1 at 0
}

rule KWAJ_compressed_file
{
meta:
    description = "KWAJ_compressed_file"
strings:
    $1 = { 4B 57 41 4A 88 F0 27 D1 }
condition:
    $1 at 0
}

rule NAV_quarantined_virus_file
{
meta:
    description = "NAV_quarantined_virus_file"
strings:
    $1 = { CD 20 AA AA 02 00 00 00 }
condition:
    $1 at 0
}

rule QBASIC_SZDD_file
{
meta:
    description = "QBASIC_SZDD_file"
strings:
    $1 = { 53 5A 20 88 F0 27 33 D1 }
condition:
    $1 at 0
}

rule SMS_text_SIM_
{
meta:
    description = "SMS_text_SIM_"
strings:
    $1 = { 6F 3C }
condition:
    $1 at 0
}

rule SZDD_file_format
{
meta:
    description = "SZDD_file_format"
strings:
    $1 = { 53 5A 44 44 88 F0 27 33 }
condition:
    $1 at 0
}

rule tcpdump_libpcap_capture_file
{
meta:
    description = "tcpdump_libpcap_capture_file"
strings:
    $1 = { A1 B2 C3 D4 }
condition:
    $1 at 0
}

rule Tcpdump_capture_file
{
meta:
    description = "Tcpdump_capture_file"
strings:
    $1 = { 34 CD B2 A1 }
condition:
    $1 at 0
}

rule UTF8_file
{
meta:
    description = "UTF8_file"
strings:
    $1 = { EF BB BF }
condition:
    $1 at 0
}

rule UTF_16_UCS_2_file
{
meta:
    description = "UTF_16_UCS_2_file"
strings:
    $1 = { FE FF }
condition:
    $1 at 0
}

rule UTF_32_UCS_4_file
{
meta:
    description = "UTF_32_UCS_4_file"
strings:
    $1 = { FF FE 00 00 }
condition:
    $1 at 0
}

rule UUencoded_file
{
meta:
    description = "UUencoded_file"
strings:
    $1 = { 62 65 67 69 6E }
condition:
    $1 at 0
}

rule WinDump_winpcap_capture_file
{
meta:
    description = "WinDump_winpcap_capture_file"
strings:
    $1 = { D4 C3 B2 A1 }
condition:
    $1 at 0
}

rule zisofs_compressed_file
{
meta:
    description = "zisofs_compressed_file"
strings:
    $1 = { 37 E4 53 96 C9 DB D6 07 }
condition:
    $1 at 0
}

rule Lotus_1_2_3_v9_123
{
meta:
    extension = "123"
    description = "Lotus_1_2_3_v9_"
strings:
    $1 = { 00 00 1A 00 05 10 04 }
condition:
    $1 at 0
}

rule _3GPP_multimedia_files_3GP
{
meta:
    extension = "3GP"
    description = "3GPP_multimedia_files"
strings:
    $1 = { 00 00 00 14 66 74 79 70 }
condition:
    $1 at 0
}

rule _3GPP2_multimedia_files_3GP
{
meta:
    extension = "3GP"
    description = "3GPP2_multimedia_files"
strings:
    $1 = { 00 00 00 20 66 74 79 70 }
condition:
    $1 at 0
}

rule MPEG_4_video_files_3GP5
{
meta:
    extension = "3GP5"
    description = "MPEG_4_video_files"
strings:
    $1 = { 00 00 00 18 66 74 79 70 }
condition:
    $1 at 0
}

rule _4X_Movie_video_4XM
{
meta:
    extension = "4XM"
    description = "4X_Movie_video"
strings:
    $1 = { 52 49 46 46 }
condition:
    $1 at 0
}

rule _7_Zip_compressed_file_7Z
{
meta:
    extension = "7Z"
    description = "7_Zip_compressed_file"
strings:
    $1 = { 37 7A BC AF 27 1C }
condition:
    $1 at 0
}

rule Palm_Address_Book_Archive_ABA
{
meta:
    extension = "ABA"
    description = "Palm_Address_Book_Archive"
strings:
    $1 = { 00 01 42 41 }
condition:
    $1 at 0
}

rule ABD__QSD_Quicken_data_file_ABD
{
meta:
    extension = "ABD"
    description = "ABD__QSD_Quicken_data_file"
strings:
    $1 = { 51 57 20 56 65 72 2E 20 }
condition:
    $1 at 0
}

rule AOL_address_book_index_ABI
{
meta:
    extension = "ABI"
    description = "AOL_address_book_index"
strings:
    $1 = { 41 4F 4C 49 4E 44 45 58 }
condition:
    $1 at 0
}

rule AOL_config_files_ABI
{
meta:
    extension = "ABI"
    description = "AOL_config_files"
strings:
    $1 = { 41 4F 4C }
condition:
    $1 at 0
}

rule AOL_address_book_ABY
{
meta:
    extension = "ABY"
    description = "AOL_address_book"
strings:
    $1 = { 41 4F 4C 44 42 }
condition:
    $1 at 0
}

rule AOL_config_files_ABY
{
meta:
    extension = "ABY"
    description = "AOL_config_files"
strings:
    $1 = { 41 4F 4C }
condition:
    $1 at 0
}

rule Sonic_Foundry_Acid_Music_File_AC
{
meta:
    extension = "AC"
    description = "Sonic_Foundry_Acid_Music_File"
strings:
    $1 = { 72 69 66 66 }
condition:
    $1 at 0
}

rule Microsoft_Access_2007_ACCDB
{
meta:
    extension = "ACCDB"
    description = "Microsoft_Access_2007"
strings:
    $1 = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 41 43 45 20 44 42 }
condition:
    $1 at 0
}

rule MS_Agent_Character_file_ACS
{
meta:
    extension = "ACS"
    description = "MS_Agent_Character_file"
strings:
    $1 = { C3 AB CD AB }
condition:
    $1 at 0
}

rule CaseWare_Working_Papers_AC
{
meta:
    extension = "AC_"
    description = "CaseWare_Working_Papers"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule Antenna_data_file_AD
{
meta:
    extension = "AD"
    description = "Antenna_data_file"
strings:
    $1 = { 52 45 56 4E 55 4D 3A 2C }
condition:
    $1 at 0
}

rule Amiga_disk_file_ADF
{
meta:
    extension = "ADF"
    description = "Amiga_disk_file"
strings:
    $1 = { 44 4F 53 }
condition:
    $1 at 0
}

rule Access_project_file_ADP
{
meta:
    extension = "ADP"
    description = "Access_project_file"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule Approach_index_file_ADX
{
meta:
    extension = "ADX"
    description = "Approach_index_file"
strings:
    $1 = { 03 00 00 00 41 50 50 52 }
condition:
    $1 at 0
}

rule Dreamcast_audio_ADX
{
meta:
    extension = "ADX"
    description = "Dreamcast_audio"
strings:
    $1 = { 80 00 00 20 03 12 04 }
condition:
    $1 at 0
}

rule Audio_Interchange_File_AIFF
{
meta:
    extension = "AIFF"
    description = "Audio_Interchange_File"
strings:
    $1 = { 46 4F 52 4D 00 }
condition:
    $1 at 0
}

rule AIN_Compressed_Archive_AIN
{
meta:
    extension = "AIN"
    description = "AIN_Compressed_Archive"
strings:
    $1 = { 21 12 }
condition:
    $1 at 0
}

rule Adaptive_Multi_Rate_ACELP_Codec_GSM_AMR
{
meta:
    extension = "AMR"
    description = "Adaptive_Multi_Rate_ACELP_Codec_GSM_"
strings:
    $1 = { 23 21 41 4D 52 }
condition:
    $1 at 0
}

rule Windows_animated_cursor_ANI
{
meta:
    extension = "ANI"
    description = "Windows_animated_cursor"
strings:
    $1 = { 52 49 46 46 }
condition:
    $1 at 0
}

rule Lotus_IBM_Approach_97_file_APR
{
meta:
    extension = "APR"
    description = "Lotus_IBM_Approach_97_file"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule FreeArc_compressed_file_ARC
{
meta:
    extension = "ARC"
    description = "FreeArc_compressed_file"
strings:
    $1 = { 41 72 43 01 }
condition:
    $1 at 0
}

rule LH_archive_old_vers_type_1_ARC
{
meta:
    extension = "ARC"
    description = "LH_archive_old_vers_type_1_"
strings:
    $1 = { 1A 02 }
condition:
    $1 at 0
}

rule LH_archive_old_vers_type_2_ARC
{
meta:
    extension = "ARC"
    description = "LH_archive_old_vers_type_2_"
strings:
    $1 = { 1A 03 }
condition:
    $1 at 0
}

rule LH_archive_old_vers_type_3_ARC
{
meta:
    extension = "ARC"
    description = "LH_archive_old_vers_type_3_"
strings:
    $1 = { 1A 04 }
condition:
    $1 at 0
}

rule LH_archive_old_vers_type_4_ARC
{
meta:
    extension = "ARC"
    description = "LH_archive_old_vers_type_4_"
strings:
    $1 = { 1A 08 }
condition:
    $1 at 0
}

rule LH_archive_old_vers_type_5_ARC
{
meta:
    extension = "ARC"
    description = "LH_archive_old_vers_type_5_"
strings:
    $1 = { 1A 09 }
condition:
    $1 at 0
}

rule ARJ_Compressed_archive_file_ARJ
{
meta:
    extension = "ARJ"
    description = "ARJ_Compressed_archive_file"
strings:
    $1 = { 60 EA }
condition:
    $1 at 0
}

rule AOL_history_typed_URL_files_ARL
{
meta:
    extension = "ARL"
    description = "AOL_history_typed_URL_files"
strings:
    $1 = { D4 2A }
condition:
    $1 at 0
}

rule Windows_Media_Audio_Video_File_ASF
{
meta:
    extension = "ASF"
    description = "Windows_Media_Audio_Video_File"
strings:
    $1 = { 30 26 B2 75 8E 66 CF 11 }
condition:
    $1 at 0
}

rule Underground_Audio_AST
{
meta:
    extension = "AST"
    description = "Underground_Audio"
strings:
    $1 = { 53 43 48 6C }
condition:
    $1 at 0
}

rule Advanced_Stream_Redirector_ASX
{
meta:
    extension = "ASX"
    description = "Advanced_Stream_Redirector"
strings:
    $1 = { 3C }
condition:
    $1 at 0
}

rule Audacity_audio_file_AU
{
meta:
    extension = "AU"
    description = "Audacity_audio_file"
strings:
    $1 = { 64 6E 73 2E }
condition:
    $1 at 0
}

rule NeXT_Sun_Microsystems_audio_file_AU
{
meta:
    extension = "AU"
    description = "NeXT_Sun_Microsystems_audio_file"
strings:
    $1 = { 2E 73 6E 64 }
condition:
    $1 at 0
}

rule AOL_history_typed_URL_files_AUT
{
meta:
    extension = "AUT"
    description = "AOL_history_typed_URL_files"
strings:
    $1 = { D4 2A }
condition:
    $1 at 0
}

rule Resource_Interchange_File_Format_AVI
{
meta:
    extension = "AVI"
    description = "Resource_Interchange_File_Format"
strings:
    $1 = { 52 49 46 46 }
condition:
    $1 at 0
}

rule MS_Answer_Wizard_AW
{
meta:
    extension = "AW"
    description = "MS_Answer_Wizard"
strings:
    $1 = { 8A 01 09 00 00 00 E1 08 }
condition:
    $1 at 0
}

rule AOL_and_AIM_buddy_list_BAG
{
meta:
    extension = "BAG"
    description = "AOL_and_AIM_buddy_list"
strings:
    $1 = { 41 4F 4C 20 46 65 65 64 }
condition:
    $1 at 0
}

rule AOL_config_files_BAG
{
meta:
    extension = "BAG"
    description = "AOL_config_files"
strings:
    $1 = { 41 4F 4C }
condition:
    $1 at 0
}

rule MS_Publisher_BDR
{
meta:
    extension = "BDR"
    description = "MS_Publisher"
strings:
    $1 = { 58 54 }
condition:
    $1 at 0
}

rule Speedtouch_router_firmware_BIN
{
meta:
    extension = "BIN"
    description = "Speedtouch_router_firmware"
strings:
    $1 = { 42 4C 49 32 32 33 51 }
condition:
    $1 at 0
}

rule Bitmap_image_BMP
{
meta:
    extension = "BMP"
    description = "Bitmap_image"
strings:
    $1 = { 42 4D }
condition:
    $1 at 0
}

rule bzip2_compressed_archive_BZ2
{
meta:
    extension = "BZ2"
    description = "bzip2_compressed_archive"
strings:
    $1 = { 42 5A 68 }
condition:
    $1 at 0
}

rule Install_Shield_compressed_file_CAB
{
meta:
    extension = "CAB"
    description = "Install_Shield_compressed_file"
strings:
    $1 = { 49 53 63 28 }
condition:
    $1 at 0
}

rule Microsoft_cabinet_file_CAB
{
meta:
    extension = "CAB"
    description = "Microsoft_cabinet_file"
strings:
    $1 = { 4D 53 43 46 }
condition:
    $1 at 0
}

rule CALS_raster_bitmap_CAL
{
meta:
    extension = "CAL"
    description = "CALS_raster_bitmap"
strings:
    $1 = { 73 72 63 64 6F 63 69 64 }
condition:
    $1 at 0
}

rule SuperCalc_worksheet_CAL
{
meta:
    extension = "CAL"
    description = "SuperCalc_worksheet"
strings:
    $1 = { 53 75 70 65 72 43 61 6C }
condition:
    $1 at 0
}

rule Windows_calendar_CAL
{
meta:
    extension = "CAL"
    description = "Windows_calendar"
strings:
    $1 = { B5 A2 B0 B3 B3 B0 A5 B5 }
condition:
    $1 at 0
}

rule Packet_sniffer_files_CAP
{
meta:
    extension = "CAP"
    description = "Packet_sniffer_files"
strings:
    $1 = { 58 43 50 00 }
condition:
    $1 at 0
}

rule WinNT_Netmon_capture_file_CAP
{
meta:
    extension = "CAP"
    description = "WinNT_Netmon_capture_file"
strings:
    $1 = { 52 54 53 53 }
condition:
    $1 at 0
}

rule EnCase_case_file_CAS
{
meta:
    extension = "CAS"
    description = "EnCase_case_file"
strings:
    $1 = { 5F 43 41 53 45 5F }
condition:
    $1 at 0
}

rule MS_security_catalog_file_CAT
{
meta:
    extension = "CAT"
    description = "MS_security_catalog_file"
strings:
    $1 = { 30 }
condition:
    $1 at 0
}

rule WordPerfect_dictionary_CBD
{
meta:
    extension = "CBD"
    description = "WordPerfect_dictionary"
strings:
    $1 = { 43 42 46 49 4C 45 }
condition:
    $1 at 0
}

rule EnCase_case_file_CBK
{
meta:
    extension = "CBK"
    description = "EnCase_case_file"
strings:
    $1 = { 5F 43 41 53 45 5F }
condition:
    $1 at 0
}

rule Resource_Interchange_File_Format_CDA
{
meta:
    extension = "CDA"
    description = "Resource_Interchange_File_Format"
strings:
    $1 = { 52 49 46 46 }
condition:
    $1 at 0
}

rule CorelDraw_document_CDR
{
meta:
    extension = "CDR"
    description = "CorelDraw_document"
strings:
    $1 = { 52 49 46 46 }
condition:
    $1 at 0
}

rule Elite_Plus_Commander_game_file_CDR
{
meta:
    extension = "CDR"
    description = "Elite_Plus_Commander_game_file"
strings:
    $1 = { 45 4C 49 54 45 20 43 6F }
condition:
    $1 at 0
}

rule Sony_Compressed_Voice_File_CDR
{
meta:
    extension = "CDR"
    description = "Sony_Compressed_Voice_File"
strings:
    $1 = { 4D 53 5F 56 4F 49 43 45 }
condition:
    $1 at 0
}

rule Flight_Simulator_Aircraft_Configuration_CFG
{
meta:
    extension = "CFG"
    description = "Flight_Simulator_Aircraft_Configuration"
strings:
    $1 = { 5B 66 6C 74 73 69 6D 2E }
condition:
    $1 at 0
}

rule MS_Compiled_HTML_Help_File_CHI
{
meta:
    extension = "CHI"
    description = "MS_Compiled_HTML_Help_File"
strings:
    $1 = { 49 54 53 46 }
condition:
    $1 at 0
}

rule MS_Compiled_HTML_Help_File_CHM
{
meta:
    extension = "CHM"
    description = "MS_Compiled_HTML_Help_File"
strings:
    $1 = { 49 54 53 46 }
condition:
    $1 at 0
}

rule Java_bytecode_CLASS
{
meta:
    extension = "CLASS"
    description = "Java_bytecode"
strings:
    $1 = { CA FE BA BE }
condition:
    $1 at 0
}

rule COM_Catalog_CLB
{
meta:
    extension = "CLB"
    description = "COM_Catalog"
strings:
    $1 = { 43 4F 4D 2B }
condition:
    $1 at 0
}

rule Corel_Binary_metafile_CLB
{
meta:
    extension = "CLB"
    description = "Corel_Binary_metafile"
strings:
    $1 = { 43 4D 58 31 }
condition:
    $1 at 0
}

rule Corel_Presentation_Exchange_metadata_CMX
{
meta:
    extension = "CMX"
    description = "Corel_Presentation_Exchange_metadata"
strings:
    $1 = { 52 49 46 46 }
condition:
    $1 at 0
}

rule DB2_conversion_file_CNV
{
meta:
    extension = "CNV"
    description = "DB2_conversion_file"
strings:
    $1 = { 53 51 4C 4F 43 4F 4E 56 }
condition:
    $1 at 0
}

rule Agent_newsreader_character_map_COD
{
meta:
    extension = "COD"
    description = "Agent_newsreader_character_map"
strings:
    $1 = { 4E 61 6D 65 3A 20 }
condition:
    $1 at 0
}

rule Windows_executable_file_1_COM
{
meta:
    extension = "COM"
    description = "Windows_executable_file_1"
strings:
    $1 = { E8 }
condition:
    $1 at 0
}

rule Windows_executable_file_2_COM
{
meta:
    extension = "COM"
    description = "Windows_executable_file_2"
strings:
    $1 = { E9 }
condition:
    $1 at 0
}

rule Windows_executable_file_3_COM
{
meta:
    extension = "COM"
    description = "Windows_executable_file_3"
strings:
    $1 = { EB }
condition:
    $1 at 0
}

rule MS_Fax_Cover_Sheet_CPE
{
meta:
    extension = "CPE"
    description = "MS_Fax_Cover_Sheet"
strings:
    $1 = { 46 41 58 43 4F 56 45 52 }
condition:
    $1 at 0
}

rule Sietronics_CPI_XRD_document_CPI
{
meta:
    extension = "CPI"
    description = "Sietronics_CPI_XRD_document"
strings:
    $1 = { 53 49 45 54 52 4F 4E 49 }
condition:
    $1 at 0
}

rule Windows_international_code_page_CPI
{
meta:
    extension = "CPI"
    description = "Windows_international_code_page"
strings:
    $1 = { FF 46 4F 4E 54 }
condition:
    $1 at 0
}

rule Corel_color_palette_CPL
{
meta:
    extension = "CPL"
    description = "Corel_color_palette"
strings:
    $1 = { DC DC }
condition:
    $1 at 0
}

rule Corel_Photopaint_file_1_CPT
{
meta:
    extension = "CPT"
    description = "Corel_Photopaint_file_1"
strings:
    $1 = { 43 50 54 37 46 49 4C 45 }
condition:
    $1 at 0
}

rule Corel_Photopaint_file_2_CPT
{
meta:
    extension = "CPT"
    description = "Corel_Photopaint_file_2"
strings:
    $1 = { 43 50 54 46 49 4C 45 }
condition:
    $1 at 0
}

rule Microsoft_Code_Page_Translation_file_CPX
{
meta:
    extension = "CPX"
    description = "Microsoft_Code_Page_Translation_file"
strings:
    $1 = { 5B 57 69 6E 64 6F 77 73 }
condition:
    $1 at 0
}

rule Crush_compressed_archive_CRU
{
meta:
    extension = "CRU"
    description = "Crush_compressed_archive"
strings:
    $1 = { 43 52 55 53 48 20 76 }
condition:
    $1 at 0
}

rule Canon_RAW_file_CRW
{
meta:
    extension = "CRW"
    description = "Canon_RAW_file"
strings:
    $1 = { 49 49 1A 00 00 00 48 45 }
condition:
    $1 at 0
}

rule Photoshop_Custom_Shape_CSH
{
meta:
    extension = "CSH"
    description = "Photoshop_Custom_Shape"
strings:
    $1 = { 63 75 73 68 00 00 00 02 }
condition:
    $1 at 0
}

rule WhereIsIt_Catalog_CTF
{
meta:
    extension = "CTF"
    description = "WhereIsIt_Catalog"
strings:
    $1 = { 43 61 74 61 6C 6F 67 20 }
condition:
    $1 at 0
}

rule Visual_Basic_User_defined_Control_file_CTL
{
meta:
    extension = "CTL"
    description = "Visual_Basic_User_defined_Control_file"
strings:
    $1 = { 56 45 52 53 49 4F 4E 20 }
condition:
    $1 at 0
}

rule Customization_files_CUIX
{
meta:
    extension = "CUIX"
    description = "Customization_files"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule Windows_cursor_CUR
{
meta:
    extension = "CUR"
    description = "Windows_cursor"
strings:
    $1 = { 00 00 02 00 }
condition:
    $1 at 0
}

rule Video_CD_MPEG_movie_DAT
{
meta:
    extension = "DAT"
    description = "Video_CD_MPEG_movie"
strings:
    $1 = { 52 49 46 46 }
condition:
    $1 at 0
}

rule Access_Data_FTK_evidence_DAT
{
meta:
    extension = "DAT"
    description = "Access_Data_FTK_evidence"
strings:
    $1 = { A9 0D 00 00 00 00 00 00 }
condition:
    $1 at 0
}

rule Allegro_Generic_Packfile_compressed_DAT
{
meta:
    extension = "DAT"
    description = "Allegro_Generic_Packfile_compressed_"
strings:
    $1 = { 73 6C 68 21 }
condition:
    $1 at 0
}

rule Allegro_Generic_Packfile_uncompressed_DAT
{
meta:
    extension = "DAT"
    description = "Allegro_Generic_Packfile_uncompressed_"
strings:
    $1 = { 73 6C 68 2E }
condition:
    $1 at 0
}

rule AVG6_Integrity_database_DAT
{
meta:
    extension = "DAT"
    description = "AVG6_Integrity_database"
strings:
    $1 = { 41 56 47 36 5F 49 6E 74 }
condition:
    $1 at 0
}

rule MapInfo_Native_Data_Format_DAT
{
meta:
    extension = "DAT"
    description = "MapInfo_Native_Data_Format"
strings:
    $1 = { 03 }
condition:
    $1 at 0
}

rule EasyRecovery_Saved_State_file_DAT
{
meta:
    extension = "DAT"
    description = "EasyRecovery_Saved_State_file"
strings:
    $1 = { 45 52 46 53 53 41 56 45 }
condition:
    $1 at 0
}

rule IE_History_file_DAT
{
meta:
    extension = "DAT"
    description = "IE_History_file"
strings:
    $1 = { 43 6C 69 65 6E 74 20 55 }
condition:
    $1 at 0
}

rule Inno_Setup_Uninstall_Log_DAT
{
meta:
    extension = "DAT"
    description = "Inno_Setup_Uninstall_Log"
strings:
    $1 = { 49 6E 6E 6F 20 53 65 74 }
condition:
    $1 at 0
}

rule Norton_Disk_Doctor_undo_file_DAT
{
meta:
    extension = "DAT"
    description = "Norton_Disk_Doctor_undo_file"
strings:
    $1 = { 50 4E 43 49 55 4E 44 4F }
condition:
    $1 at 0
}

rule PestPatrol_data_scan_strings_DAT
{
meta:
    extension = "DAT"
    description = "PestPatrol_data_scan_strings"
strings:
    $1 = { 50 45 53 54 }
condition:
    $1 at 0
}

rule Runtime_Software_disk_image_DAT
{
meta:
    extension = "DAT"
    description = "Runtime_Software_disk_image"
strings:
    $1 = { 1A 52 54 53 20 43 4F 4D }
condition:
    $1 at 0
}

rule Shareaza_P2P_thumbnail_DAT
{
meta:
    extension = "DAT"
    description = "Shareaza_P2P_thumbnail"
strings:
    $1 = { 52 41 5A 41 54 44 42 31 }
condition:
    $1 at 0
}

rule TomTom_traffic_data_DAT
{
meta:
    extension = "DAT"
    description = "TomTom_traffic_data"
strings:
    $1 = { 4E 41 56 54 52 41 46 46 }
condition:
    $1 at 0
}

rule UFO_Capture_map_file_DAT
{
meta:
    extension = "DAT"
    description = "UFO_Capture_map_file"
strings:
    $1 = { 55 46 4F 4F 72 62 69 74 }
condition:
    $1 at 0
}

rule Walkman_MP3_file_DAT
{
meta:
    extension = "DAT"
    description = "Walkman_MP3_file"
strings:
    $1 = { 57 4D 4D 50 }
condition:
    $1 at 0
}

rule Win9x_registry_hive_DAT
{
meta:
    extension = "DAT"
    description = "Win9x_registry_hive"
strings:
    $1 = { 43 52 45 47 }
condition:
    $1 at 0
}

rule WinNT_registry_file_DAT
{
meta:
    extension = "DAT"
    description = "WinNT_registry_file"
strings:
    $1 = { 72 65 67 66 }
condition:
    $1 at 0
}

rule MSWorks_database_file_DB
{
meta:
    extension = "DB"
    description = "MSWorks_database_file"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule dBASE_IV_or_dBFast_configuration_file_DB
{
meta:
    extension = "DB"
    description = "dBASE_IV_or_dBFast_configuration_file"
strings:
    $1 = { 08 }
condition:
    $1 at 0
}

rule Netscape_Navigator_v4_database_DB
{
meta:
    extension = "DB"
    description = "Netscape_Navigator_v4_database"
strings:
    $1 = { 00 06 15 61 00 00 00 02 00 00 04 D2 00 00 10 00 }
condition:
    $1 at 0
}

rule Palm_Zire_photo_database_DB
{
meta:
    extension = "DB"
    description = "Palm_Zire_photo_database"
strings:
    $1 = { 44 42 46 48 }
condition:
    $1 at 0
}

rule SQLite_database_file_DB
{
meta:
    extension = "DB"
    description = "SQLite_database_file"
strings:
    $1 = { 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00 }
condition:
    $1 at 0
}

rule Thumbs_db_subheader_DB
{
meta:
    extension = "DB"
    description = "Thumbs_db_subheader"
strings:
    $1 = { FD FF FF FF }
condition:
    $1 at 0
}

rule dBASE_III_file_DB3
{
meta:
    extension = "DB3"
    description = "dBASE_III_file"
strings:
    $1 = { 03 }
condition:
    $1 at 0
}

rule dBASE_IV_file_DB4
{
meta:
    extension = "DB4"
    description = "dBASE_IV_file"
strings:
    $1 = { 04 }
condition:
    $1 at 0
}

rule Palm_DateBook_Archive_DBA
{
meta:
    extension = "DBA"
    description = "Palm_DateBook_Archive"
strings:
    $1 = { 00 01 42 44 }
condition:
    $1 at 0
}

rule Skype_user_data_file_DBB
{
meta:
    extension = "DBB"
    description = "Skype_user_data_file"
strings:
    $1 = { 6C 33 33 6C }
condition:
    $1 at 0
}

rule Psion_Series_3_Database_DBF
{
meta:
    extension = "DBF"
    description = "Psion_Series_3_Database"
strings:
    $1 = { 4F 50 4C 44 61 74 61 62 }
condition:
    $1 at 0
}

rule Outlook_Express_e_mail_folder_DBX
{
meta:
    extension = "DBX"
    description = "Outlook_Express_e_mail_folder"
strings:
    $1 = { CF AD 12 FE }
condition:
    $1 at 0
}

rule AOL_HTML_mail_DCI
{
meta:
    extension = "DCI"
    description = "AOL_HTML_mail"
strings:
    $1 = { 3C 21 64 6F 63 74 79 70 }
condition:
    $1 at 0
}

rule PCX_bitmap_DCX
{
meta:
    extension = "DCX"
    description = "PCX_bitmap"
strings:
    $1 = { B1 68 DE 3A }
condition:
    $1 at 0
}

rule Dalvik_Android_executable_file_dex
{
meta:
    extension = "dex"
    description = "Dalvik_Android_executable_file"
strings:
    $1 = { 64 65 78 0A 30 30 39 00 }
condition:
    $1 at 0
}

rule Bitmap_image_DIB
{
meta:
    extension = "DIB"
    description = "Bitmap_image"
strings:
    $1 = { 42 4D }
condition:
    $1 at 0
}

rule MacOS_X_image_file_DMG
{
meta:
    extension = "DMG"
    description = "MacOS_X_image_file"
strings:
    $1 = { 78 }
condition:
    $1 at 0
}

rule Windows_dump_file_DMP
{
meta:
    extension = "DMP"
    description = "Windows_dump_file"
strings:
    $1 = { 4D 44 4D 50 93 A7 }
condition:
    $1 at 0
}

rule Windows_memory_dump_DMP
{
meta:
    extension = "DMP"
    description = "Windows_memory_dump"
strings:
    $1 = { 50 41 47 45 44 55 }
condition:
    $1 at 0
}

rule Amiga_DiskMasher_compressed_archive_DMS
{
meta:
    extension = "DMS"
    description = "Amiga_DiskMasher_compressed_archive"
strings:
    $1 = { 44 4D 53 21 }
condition:
    $1 at 0
}

rule Microsoft_Office_document_DOC
{
meta:
    extension = "DOC"
    description = "Microsoft_Office_document"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule DeskMate_Document_DOC
{
meta:
    extension = "DOC"
    description = "DeskMate_Document"
strings:
    $1 = { 0D 44 4F 43 }
condition:
    $1 at 0
}

rule Perfect_Office_document_DOC
{
meta:
    extension = "DOC"
    description = "Perfect_Office_document"
strings:
    $1 = { CF 11 E0 A1 B1 1A E1 00 }
condition:
    $1 at 0
}

rule Word_2_0_file_DOC
{
meta:
    extension = "DOC"
    description = "Word_2_0_file"
strings:
    $1 = { DB A5 2D 00 }
condition:
    $1 at 0
}

rule Word_document_subheader_DOC
{
meta:
    extension = "DOC"
    description = "Word_document_subheader"
strings:
    $1 = { EC A5 C1 00 }
condition:
    $1 at 0
}

rule MS_Office_Open_XML_Format_Document_DOCX
{
meta:
    extension = "DOCX"
    description = "MS_Office_Open_XML_Format_Document"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule MS_Office_2007_documents_DOCX
{
meta:
    extension = "DOCX"
    description = "MS_Office_2007_documents"
strings:
    $1 = { 50 4B 03 04 14 00 06 00 }
condition:
    $1 at 0
}

rule Microsoft_Office_document_DOT
{
meta:
    extension = "DOT"
    description = "Microsoft_Office_document"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule Generic_drawing_programs_DRW
{
meta:
    extension = "DRW"
    description = "Generic_drawing_programs"
strings:
    $1 = { 07 }
condition:
    $1 at 0
}

rule Micrografx_vector_graphic_file_DRW
{
meta:
    extension = "DRW"
    description = "Micrografx_vector_graphic_file"
strings:
    $1 = { 01 FF 02 04 03 02 }
condition:
    $1 at 0
}

rule Micrografx_Designer_graphic_DS4
{
meta:
    extension = "DS4"
    description = "Micrografx_Designer_graphic"
strings:
    $1 = { 52 49 46 46 }
condition:
    $1 at 0
}

rule CD_Stomper_Pro_label_file_DSN
{
meta:
    extension = "DSN"
    description = "CD_Stomper_Pro_label_file"
strings:
    $1 = { 4D 56 }
condition:
    $1 at 0
}

rule MS_Developer_Studio_project_file_DSP
{
meta:
    extension = "DSP"
    description = "MS_Developer_Studio_project_file"
strings:
    $1 = { 23 20 4D 69 63 72 6F 73 }
condition:
    $1 at 0
}

rule Digital_Speech_Standard_file_DSS
{
meta:
    extension = "DSS"
    description = "Digital_Speech_Standard_file"
strings:
    $1 = { 02 64 73 73 }
condition:
    $1 at 0
}

rule MS_Visual_Studio_workspace_file_DSW
{
meta:
    extension = "DSW"
    description = "MS_Visual_Studio_workspace_file"
strings:
    $1 = { 64 73 77 66 69 6C 65 }
condition:
    $1 at 0
}

rule DesignTools_2D_Design_file_DTD
{
meta:
    extension = "DTD"
    description = "DesignTools_2D_Design_file"
strings:
    $1 = { 07 64 74 32 64 64 74 64 }
condition:
    $1 at 0
}

rule Dial_up_networking_file_DUN
{
meta:
    extension = "DUN"
    description = "Dial_up_networking_file"
strings:
    $1 = { 5B 50 68 6F 6E 65 5D }
condition:
    $1 at 0
}

rule Sony_Compressed_Voice_File_DVF
{
meta:
    extension = "DVF"
    description = "Sony_Compressed_Voice_File"
strings:
    $1 = { 4D 53 5F 56 4F 49 43 45 }
condition:
    $1 at 0
}

rule DVR_Studio_stream_file_DVR
{
meta:
    extension = "DVR"
    description = "DVR_Studio_stream_file"
strings:
    $1 = { 44 56 44 }
condition:
    $1 at 0
}

rule Visio_DisplayWrite_4_text_file_DW4
{
meta:
    extension = "DW4"
    description = "Visio_DisplayWrite_4_text_file"
strings:
    $1 = { 4F 7B }
condition:
    $1 at 0
}

rule Generic_AutoCAD_drawing_DWG
{
meta:
    extension = "DWG"
    description = "Generic_AutoCAD_drawing"
strings:
    $1 = { 41 43 31 30 }
condition:
    $1 at 0
}

rule Expert_Witness_Compression_Format_E01
{
meta:
    extension = "E01"
    description = "Expert_Witness_Compression_Format"
strings:
    $1 = { 45 56 46 09 0D 0A FF 00 }
condition:
    $1 at 0
}

rule Logical_File_Evidence_Format_E01
{
meta:
    extension = "E01"
    description = "Logical_File_Evidence_Format"
strings:
    $1 = { 4C 56 46 09 0D 0A FF 00 }
condition:
    $1 at 0
}

rule MS_Exchange_configuration_file_ECF
{
meta:
    extension = "ECF"
    description = "MS_Exchange_configuration_file"
strings:
    $1 = { 5B 47 65 6E 65 72 61 6C }
condition:
    $1 at 0
}

rule eFax_file_EFX
{
meta:
    extension = "EFX"
    description = "eFax_file"
strings:
    $1 = { DC FE }
condition:
    $1 at 0
}

rule Exchange_e_mail_EML
{
meta:
    extension = "EML"
    description = "Exchange_e_mail"
strings:
    $1 = { 58 2D }
condition:
    $1 at 0
}

rule Generic_e_mail_1_EML
{
meta:
    extension = "EML"
    description = "Generic_e_mail_1"
strings:
    $1 = { 52 65 74 75 72 6E 2D 50 }
condition:
    $1 at 0
}

rule Generic_e_mail_2_EML
{
meta:
    extension = "EML"
    description = "Generic_e_mail_2"
strings:
    $1 = { 46 72 6F 6D }
condition:
    $1 at 0
}

rule EndNote_Library_File_ENL
{
meta:
    extension = "ENL"
    description = "EndNote_Library_File"
strings:
    $1 = { 40 40 40 20 00 00 40 40 40 40 }
condition:
    $1 at 0
}

rule Adobe_encapsulated_PostScript_EPS
{
meta:
    extension = "EPS"
    description = "Adobe_encapsulated_PostScript"
strings:
    $1 = { C5 D0 D3 C6 }
condition:
    $1 at 0
}

rule Encapsulated_PostScript_file_EPS
{
meta:
    extension = "EPS"
    description = "Encapsulated_PostScript_file"
strings:
    $1 = { 25 21 50 53 2D 41 64 6F }
condition:
    $1 at 0
}

rule WinPharoah_capture_file_ETH
{
meta:
    extension = "ETH"
    description = "WinPharoah_capture_file"
strings:
    $1 = { 1A 35 01 00 }
condition:
    $1 at 0
}

rule Windows_Event_Viewer_file_EVT
{
meta:
    extension = "EVT"
    description = "Windows_Event_Viewer_file"
strings:
    $1 = { 30 00 00 00 4C 66 4C 65 }
condition:
    $1 at 0
}

rule Windows_Vista_event_log_EVTX
{
meta:
    extension = "EVTX"
    description = "Windows_Vista_event_log"
strings:
    $1 = { 45 6C 66 46 69 6C 65 00 }
condition:
    $1 at 0
}

rule Windows_DOS_executable_file_EXE
{
meta:
    extension = "EXE"
    description = "Windows_DOS_executable_file"
strings:
    $1 = { 4D 5A }
condition:
    $1 at 0
}

rule PDF_file_FDF
{
meta:
    extension = "FDF"
    description = "PDF_file"
strings:
    $1 = { 25 50 44 46 }
condition:
    $1 at 0
}

rule Free_Lossless_Audio_Codec_file_FLAC
{
meta:
    extension = "FLAC"
    description = "Free_Lossless_Audio_Codec_file"
strings:
    $1 = { 66 4C 61 43 00 00 00 22 }
condition:
    $1 at 0
}

rule FLIC_animation_FLI
{
meta:
    extension = "FLI"
    description = "FLIC_animation"
strings:
    $1 = { 00 11 }
condition:
    $1 at 0
}

rule Qimage_filter_FLT
{
meta:
    extension = "FLT"
    description = "Qimage_filter"
strings:
    $1 = { 76 32 30 30 33 2E 31 30 }
condition:
    $1 at 0
}

rule Flash_video_file_FLV
{
meta:
    extension = "FLV"
    description = "Flash_video_file"
strings:
    $1 = { 46 4C 56 }
condition:
    $1 at 0
}

rule Adobe_FrameMaker_FM
{
meta:
    extension = "FM"
    description = "Adobe_FrameMaker"
strings:
    $1 = { 3C 4D 61 6B 65 72 46 69 }
condition:
    $1 at 0
}

rule WinPharoah_filter_file_FTR
{
meta:
    extension = "FTR"
    description = "WinPharoah_filter_file"
strings:
    $1 = { D2 0A 00 00 }
condition:
    $1 at 0
}

rule Symantex_Ghost_image_file_GHO
{
meta:
    extension = "GHO"
    description = "Symantex_Ghost_image_file"
strings:
    $1 = { FE EF }
condition:
    $1 at 0
}

rule Symantex_Ghost_image_file_GHS
{
meta:
    extension = "GHS"
    description = "Symantex_Ghost_image_file"
strings:
    $1 = { FE EF }
condition:
    $1 at 0
}

rule Windows_Help_file_2_GID
{
meta:
    extension = "GID"
    description = "Windows_Help_file_2"
strings:
    $1 = { 3F 5F 03 00 }
condition:
    $1 at 0
}

rule Windows_help_file_3_GID
{
meta:
    extension = "GID"
    description = "Windows_help_file_3"
strings:
    $1 = { 4C 4E 02 00 }
condition:
    $1 at 0
}

rule GIF_file_GIF
{
meta:
    extension = "GIF"
    description = "GIF_file"
strings:
    $1 = { 47 49 46 38 }
condition:
    $1 at 0
}

rule GPG_public_keyring_GPG
{
meta:
    extension = "GPG"
    description = "GPG_public_keyring"
strings:
    $1 = { 99 }
condition:
    $1 at 0
}

rule Windows_Program_Manager_group_file_GRP
{
meta:
    extension = "GRP"
    description = "Windows_Program_Manager_group_file"
strings:
    $1 = { 50 4D 43 43 }
condition:
    $1 at 0
}

rule Show_Partner_graphics_file_GX2
{
meta:
    extension = "GX2"
    description = "Show_Partner_graphics_file"
strings:
    $1 = { 47 58 32 }
condition:
    $1 at 0
}

rule GZIP_archive_file_GZ
{
meta:
    extension = "GZ"
    description = "GZIP_archive_file"
strings:
    $1 = { 1F 8B 08 }
condition:
    $1 at 0
}

rule Hamarsoft_compressed_archive_HAP
{
meta:
    extension = "HAP"
    description = "Hamarsoft_compressed_archive"
strings:
    $1 = { 91 33 48 46 }
condition:
    $1 at 0
}

rule Windows_dump_file_HDMP
{
meta:
    extension = "HDMP"
    description = "Windows_dump_file"
strings:
    $1 = { 4D 44 4D 50 93 A7 }
condition:
    $1 at 0
}

rule Install_Shield_compressed_file_HDR
{
meta:
    extension = "HDR"
    description = "Install_Shield_compressed_file"
strings:
    $1 = { 49 53 63 28 }
condition:
    $1 at 0
}

rule Radiance_High_Dynamic_Range_image_file_HDR
{
meta:
    extension = "HDR"
    description = "Radiance_High_Dynamic_Range_image_file"
strings:
    $1 = { 23 3F 52 41 44 49 41 4E }
condition:
    $1 at 0
}

rule Houdini_image_file_Three_dimensional_modeling_and_animation_hip
{
meta:
    extension = "hip"
    description = "Houdini_image_file_Three_dimensional_modeling_and_animation"
strings:
    $1 = { 48 69 50 21 }
condition:
    $1 at 0
}

rule Windows_Help_file_1_HLP
{
meta:
    extension = "HLP"
    description = "Windows_Help_file_1"
strings:
    $1 = { 00 00 FF FF FF FF }
condition:
    $1 at 0
}

rule Windows_Help_file_2_HLP
{
meta:
    extension = "HLP"
    description = "Windows_Help_file_2"
strings:
    $1 = { 3F 5F 03 00 }
condition:
    $1 at 0
}

rule Windows_help_file_3_HLP
{
meta:
    extension = "HLP"
    description = "Windows_help_file_3"
strings:
    $1 = { 4C 4E 02 00 }
condition:
    $1 at 0
}

rule BinHex_4_Compressed_Archive_HQX
{
meta:
    extension = "HQX"
    description = "BinHex_4_Compressed_Archive"
strings:
    $1 = { 28 54 68 69 73 20 66 69 }
condition:
    $1 at 0
}

rule Windows_icon_printer_spool_file_ICO
{
meta:
    extension = "ICO"
    description = "Windows_icon_printer_spool_file"
strings:
    $1 = { 00 00 01 00 }
condition:
    $1 at 0
}

rule AOL_user_configuration_IDX
{
meta:
    extension = "IDX"
    description = "AOL_user_configuration"
strings:
    $1 = { 41 4F 4C 44 42 }
condition:
    $1 at 0
}

rule AOL_config_files_IDX
{
meta:
    extension = "IDX"
    description = "AOL_config_files"
strings:
    $1 = { 41 4F 4C }
condition:
    $1 at 0
}

rule Quicken_QuickFinder_Information_File_IDX
{
meta:
    extension = "IDX"
    description = "Quicken_QuickFinder_Information_File"
strings:
    $1 = { 50 00 00 00 20 00 00 00 }
condition:
    $1 at 0
}

rule DVD_info_file_IFO
{
meta:
    extension = "IFO"
    description = "DVD_info_file"
strings:
    $1 = { 44 56 44 }
condition:
    $1 at 0
}

rule ChromaGraph_Graphics_Card_Bitmap_IMG
{
meta:
    extension = "IMG"
    description = "ChromaGraph_Graphics_Card_Bitmap"
strings:
    $1 = { 50 49 43 54 00 08 }
condition:
    $1 at 0
}

rule GEM_Raster_file_IMG
{
meta:
    extension = "IMG"
    description = "GEM_Raster_file"
strings:
    $1 = { EB 3C 90 2A }
condition:
    $1 at 0
}

rule Img_Software_Bitmap_IMG
{
meta:
    extension = "IMG"
    description = "Img_Software_Bitmap"
strings:
    $1 = { 53 43 4D 49 }
condition:
    $1 at 0
}

rule AOL_client_preferences_settings_file_IND
{
meta:
    extension = "IND"
    description = "AOL_client_preferences_settings_file"
strings:
    $1 = { 41 4F 4C 49 44 58 }
condition:
    $1 at 0
}

rule AOL_config_files_IND
{
meta:
    extension = "IND"
    description = "AOL_config_files"
strings:
    $1 = { 41 4F 4C }
condition:
    $1 at 0
}

rule Amiga_icon_INFO
{
meta:
    extension = "INFO"
    description = "Amiga_icon"
strings:
    $1 = { E3 10 00 01 00 00 00 00 }
condition:
    $1 at 0
}

rule GNU_Info_Reader_file_INFO
{
meta:
    extension = "INFO"
    description = "GNU_Info_Reader_file"
strings:
    $1 = { 54 68 69 73 20 69 73 20 }
condition:
    $1 at 0
}

rule ZoomBrowser_Image_Index_INFO
{
meta:
    extension = "INFO"
    description = "ZoomBrowser_Image_Index"
strings:
    $1 = { 7A 62 65 78 }
condition:
    $1 at 0
}

rule ISO_9660_CD_Disc_Image_ISO
{
meta:
    extension = "ISO"
    description = "ISO_9660_CD_Disc_Image"
strings:
    $1 = { 43 44 30 30 31 }
condition:
    $1 at 0
}

rule RealPlayer_video_file_V11__IVR
{
meta:
    extension = "IVR"
    description = "RealPlayer_video_file_V11_"
strings:
    $1 = { 2E 52 45 43 }
condition:
    $1 at 0
}

rule Java_archive_1_JAR
{
meta:
    extension = "JAR"
    description = "Java_archive_1"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule Jar_archive_JAR
{
meta:
    extension = "JAR"
    description = "Jar_archive"
strings:
    $1 = { 5F 27 A8 89 }
condition:
    $1 at 0
}

rule JARCS_compressed_archive_JAR
{
meta:
    extension = "JAR"
    description = "JARCS_compressed_archive"
strings:
    $1 = { 4A 41 52 43 53 00 }
condition:
    $1 at 0
}

rule Java_archive_2_JAR
{
meta:
    extension = "JAR"
    description = "Java_archive_2"
strings:
    $1 = { 50 4B 03 04 14 00 08 00 }
condition:
    $1 at 0
}

rule JPEG_IMAGE_JFIF
{
meta:
    extension = "JFIF"
    description = "JPEG_IMAGE"
strings:
    $1 = { FF D8 FF E0 }
condition:
    $1 at 0
}

rule JFIF_IMAGE_FILE__jpeg_JFIF
{
meta:
    extension = "JFIF"
    description = "JFIF_IMAGE_FILE__jpeg"
strings:
    $1 = { FF D8 FF E0 }
condition:
    $1 at 0
}

rule AOL_ART_file_1_JG
{
meta:
    extension = "JG"
    description = "AOL_ART_file_1"
strings:
    $1 = { 4A 47 03 0E }
condition:
    $1 at 0
}

rule AOL_ART_file_2_JG
{
meta:
    extension = "JG"
    description = "AOL_ART_file_2"
strings:
    $1 = { 4A 47 04 0E }
condition:
    $1 at 0
}

rule MS_Windows_journal_JNT
{
meta:
    extension = "JNT"
    description = "MS_Windows_journal"
strings:
    $1 = { 4E 42 2A 00 }
condition:
    $1 at 0
}

rule JPEG2000_image_files_JP2
{
meta:
    extension = "JP2"
    description = "JPEG2000_image_files"
strings:
    $1 = { 00 00 00 0C 6A 50 20 20 }
condition:
    $1 at 0
}

rule JPEG_IMAGE_JPE
{
meta:
    extension = "JPE"
    description = "JPEG_IMAGE"
strings:
    $1 = { FF D8 FF E0 }
condition:
    $1 at 0
}

rule JPE_IMAGE_FILE__jpeg_JPE
{
meta:
    extension = "JPE"
    description = "JPE_IMAGE_FILE__jpeg"
strings:
    $1 = { FF D8 FF E0 }
condition:
    $1 at 0
}

rule JPEG_IMAGE_JPEG
{
meta:
    extension = "JPEG"
    description = "JPEG_IMAGE"
strings:
    $1 = { FF D8 FF E0 }
condition:
    $1 at 0
}

rule CANNON_EOS_JPEG_FILE_JPEG
{
meta:
    extension = "JPEG"
    description = "CANNON_EOS_JPEG_FILE"
strings:
    $1 = { FF D8 FF E2 }
condition:
    $1 at 0
}

rule SAMSUNG_D500_JPEG_FILE_JPEG
{
meta:
    extension = "JPEG"
    description = "SAMSUNG_D500_JPEG_FILE"
strings:
    $1 = { FF D8 FF E3 }
condition:
    $1 at 0
}

rule JPEG_IMAGE_JPG
{
meta:
    extension = "JPG"
    description = "JPEG_IMAGE"
strings:
    $1 = { FF D8 FF E0 }
condition:
    $1 at 0
}

rule Digital_camera_JPG_using_Exchangeable_Image_File_Format_EXIF_JPG
{
meta:
    extension = "JPG"
    description = "Digital_camera_JPG_using_Exchangeable_Image_File_Format_EXIF_"
strings:
    $1 = { FF D8 FF E1 }
condition:
    $1 at 0
}

rule Still_Picture_Interchange_File_Format_SPIFF_JPG
{
meta:
    extension = "JPG"
    description = "Still_Picture_Interchange_File_Format_SPIFF_"
strings:
    $1 = { FF D8 FF E8 }
condition:
    $1 at 0
}

rule MS_Windows_journal_JTP
{
meta:
    extension = "JTP"
    description = "MS_Windows_journal"
strings:
    $1 = { 4E 42 2A 00 }
condition:
    $1 at 0
}

rule KGB_archive_KGB
{
meta:
    extension = "KGB"
    description = "KGB_archive"
strings:
    $1 = { 4B 47 42 5F 61 72 63 68 }
condition:
    $1 at 0
}

rule Sprint_Music_Store_audio_KOZ
{
meta:
    extension = "KOZ"
    description = "Sprint_Music_Store_audio"
strings:
    $1 = { 49 44 33 03 00 00 00 }
condition:
    $1 at 0
}

rule KWord_document_KWD
{
meta:
    extension = "KWD"
    description = "KWord_document"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule Jeppesen_FliteLog_file_LBK
{
meta:
    extension = "LBK"
    description = "Jeppesen_FliteLog_file"
strings:
    $1 = { C8 00 79 00 }
condition:
    $1 at 0
}

rule Windows_application_log_LGC
{
meta:
    extension = "LGC"
    description = "Windows_application_log"
strings:
    $1 = { 7B 0D 0A 6F 20 }
condition:
    $1 at 0
}

rule Windows_application_log_LGD
{
meta:
    extension = "LGD"
    description = "Windows_application_log"
strings:
    $1 = { 7B 0D 0A 6F 20 }
condition:
    $1 at 0
}

rule Compressed_archive_LHA
{
meta:
    extension = "LHA"
    description = "Compressed_archive"
strings:
    $1 = { 2D 6C 68 }
condition:
    $1 at 0
}

rule Unix_archiver_ar_MS_Program_Library_Common_Object_File_Format_COFF_LIB
{
meta:
    extension = "LIB"
    description = "Unix_archiver_ar_MS_Program_Library_Common_Object_File_Format_COFF_"
strings:
    $1 = { 21 3C 61 72 63 68 3E 0A }
condition:
    $1 at 0
}

rule MS_Reader_eBook_LIT
{
meta:
    extension = "LIT"
    description = "MS_Reader_eBook"
strings:
    $1 = { 49 54 4F 4C 49 54 4C 53 }
condition:
    $1 at 0
}

rule Windows_shortcut_file_LNK
{
meta:
    extension = "LNK"
    description = "Windows_shortcut_file"
strings:
    $1 = { 4C 00 00 00 01 14 02 00 }
condition:
    $1 at 0
}

rule Symantec_Wise_Installer_log_LOG
{
meta:
    extension = "LOG"
    description = "Symantec_Wise_Installer_log"
strings:
    $1 = { 2A 2A 2A 20 20 49 6E 73 }
condition:
    $1 at 0
}

rule Lotus_WordPro_file_LWP
{
meta:
    extension = "LWP"
    description = "Lotus_WordPro_file"
strings:
    $1 = { 57 6F 72 64 50 72 6F }
condition:
    $1 at 0
}

rule Compressed_archive_LZH
{
meta:
    extension = "LZH"
    description = "Compressed_archive"
strings:
    $1 = { 2D 6C 68 }
condition:
    $1 at 0
}

rule Apple_audio_and_video_files_M4A
{
meta:
    extension = "M4A"
    description = "Apple_audio_and_video_files"
strings:
    $1 = { 00 00 00 20 66 74 79 70 4D 34 41 }
condition:
    $1 at 0
}

rule Windows_Visual_Stylesheet_MANIFEST
{
meta:
    extension = "MANIFEST"
    description = "Windows_Visual_Stylesheet"
strings:
    $1 = { 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D }
condition:
    $1 at 0
}

rule MAr_compressed_archive_MAR
{
meta:
    extension = "MAR"
    description = "MAr_compressed_archive"
strings:
    $1 = { 4D 41 72 30 00 }
condition:
    $1 at 0
}

rule Microsoft_MSN_MARC_archive_MAR
{
meta:
    extension = "MAR"
    description = "Microsoft_MSN_MARC_archive"
strings:
    $1 = { 4D 41 52 43 }
condition:
    $1 at 0
}

rule Mozilla_archive_MAR
{
meta:
    extension = "MAR"
    description = "Mozilla_archive"
strings:
    $1 = { 4D 41 52 31 00 }
condition:
    $1 at 0
}

rule Microsoft_Access_MDB
{
meta:
    extension = "MDB"
    description = "Microsoft_Access"
strings:
    $1 = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 }
condition:
    $1 at 0
}

rule SQL_Data_Base_MDF
{
meta:
    extension = "MDF"
    description = "SQL_Data_Base"
strings:
    $1 = { 01 0F 00 00 }
condition:
    $1 at 0
}

rule MS_Document_Imaging_file_MDI
{
meta:
    extension = "MDI"
    description = "MS_Document_Imaging_file"
strings:
    $1 = { 45 50 }
condition:
    $1 at 0
}

rule MIDI_sound_file_MID
{
meta:
    extension = "MID"
    description = "MIDI_sound_file"
strings:
    $1 = { 4D 54 68 64 }
condition:
    $1 at 0
}

rule MIDI_sound_file_MIDI
{
meta:
    extension = "MIDI"
    description = "MIDI_sound_file"
strings:
    $1 = { 4D 54 68 64 }
condition:
    $1 at 0
}

rule Adobe_FrameMaker_MIF
{
meta:
    extension = "MIF"
    description = "Adobe_FrameMaker"
strings:
    $1 = { 3C 4D 61 6B 65 72 46 69 }
condition:
    $1 at 0
}

rule MapInfo_Interchange_Format_file_MIF
{
meta:
    extension = "MIF"
    description = "MapInfo_Interchange_Format_file"
strings:
    $1 = { 56 65 72 73 69 6F 6E 20 }
condition:
    $1 at 0
}

rule Matroska_stream_file_MKV
{
meta:
    extension = "MKV"
    description = "Matroska_stream_file"
strings:
    $1 = { 1A 45 DF A3 93 42 82 88 }
condition:
    $1 at 0
}

rule Milestones_project_management_file_MLS
{
meta:
    extension = "MLS"
    description = "Milestones_project_management_file"
strings:
    $1 = { 4D 49 4C 45 53 }
condition:
    $1 at 0
}

rule Milestones_project_management_file_1_MLS
{
meta:
    extension = "MLS"
    description = "Milestones_project_management_file_1"
strings:
    $1 = { 4D 56 32 31 34 }
condition:
    $1 at 0
}

rule Milestones_project_management_file_2_MLS
{
meta:
    extension = "MLS"
    description = "Milestones_project_management_file_2"
strings:
    $1 = { 4D 56 32 43 }
condition:
    $1 at 0
}

rule Skype_localization_data_file_MLS
{
meta:
    extension = "MLS"
    description = "Skype_localization_data_file"
strings:
    $1 = { 4D 4C 53 57 }
condition:
    $1 at 0
}

rule Yamaha_Synthetic_music_Mobile_Application_Format_MMF
{
meta:
    extension = "MMF"
    description = "Yamaha_Synthetic_music_Mobile_Application_Format"
strings:
    $1 = { 4D 4D 4D 44 00 00 }
condition:
    $1 at 0
}

rule Microsoft_Money_file_MNY
{
meta:
    extension = "MNY"
    description = "Microsoft_Money_file"
strings:
    $1 = { 00 01 00 00 4D 53 49 53 41 4D 20 44 61 74 61 62 61 73 65 }
condition:
    $1 at 0
}

rule MSinfo_file_MOF
{
meta:
    extension = "MOF"
    description = "MSinfo_file"
strings:
    $1 = { FF FE 23 00 6C 00 69 00 }
condition:
    $1 at 0
}

rule QuickTime_movie_1_MOV
{
meta:
    extension = "MOV"
    description = "QuickTime_movie_1"
strings:
    $1 = { 6D 6F 6F 76 }
condition:
    $1 at 0
}

rule QuickTime_movie_2_MOV
{
meta:
    extension = "MOV"
    description = "QuickTime_movie_2"
strings:
    $1 = { 66 72 65 65 }
condition:
    $1 at 0
}

rule QuickTime_movie_3_MOV
{
meta:
    extension = "MOV"
    description = "QuickTime_movie_3"
strings:
    $1 = { 6D 64 61 74 }
condition:
    $1 at 0
}

rule QuickTime_movie_4_MOV
{
meta:
    extension = "MOV"
    description = "QuickTime_movie_4"
strings:
    $1 = { 77 69 64 65 }
condition:
    $1 at 0
}

rule QuickTime_movie_5_MOV
{
meta:
    extension = "MOV"
    description = "QuickTime_movie_5"
strings:
    $1 = { 70 6E 6F 74 }
condition:
    $1 at 0
}

rule QuickTime_movie_6_MOV
{
meta:
    extension = "MOV"
    description = "QuickTime_movie_6"
strings:
    $1 = { 73 6B 69 70 }
condition:
    $1 at 0
}

rule Monochrome_Picture_TIFF_bitmap_MP
{
meta:
    extension = "MP"
    description = "Monochrome_Picture_TIFF_bitmap"
strings:
    $1 = { 0C ED }
condition:
    $1 at 0
}

rule MP3_audio_file_MP3
{
meta:
    extension = "MP3"
    description = "MP3_audio_file"
strings:
    $1 = { 49 44 33 }
condition:
    $1 at 0
}

rule DVD_video_file_MPG
{
meta:
    extension = "MPG"
    description = "DVD_video_file"
strings:
    $1 = { 00 00 01 BA }
condition:
    $1 at 0
}

rule MPEG_video_file_MPG
{
meta:
    extension = "MPG"
    description = "MPEG_video_file"
strings:
    $1 = { 00 00 01 B3 }
condition:
    $1 at 0
}

rule Microsoft_Common_Console_Document_MSC
{
meta:
    extension = "MSC"
    description = "Microsoft_Common_Console_Document"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule MMC_Snap_in_Control_file_MSC
{
meta:
    extension = "MSC"
    description = "MMC_Snap_in_Control_file"
strings:
    $1 = { 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 3F 3E 0D 0A 3C 4D 4D 43 5F 43 6F 6E 73 6F 6C 65 46 69 6C 65 20 43 6F 6E 73 6F 6C 65 56 65 72 }
condition:
    $1 at 0
}

rule Microsoft_Installer_package_MSI
{
meta:
    extension = "MSI"
    description = "Microsoft_Installer_package"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule Cerius2_file_MSI
{
meta:
    extension = "MSI"
    description = "Cerius2_file"
strings:
    $1 = { 23 20 }
condition:
    $1 at 0
}

rule Sony_Compressed_Voice_File_MSV
{
meta:
    extension = "MSV"
    description = "Sony_Compressed_Voice_File"
strings:
    $1 = { 4D 53 5F 56 4F 49 43 45 }
condition:
    $1 at 0
}

rule Minitab_data_file_MTW
{
meta:
    extension = "MTW"
    description = "Minitab_data_file"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule Nero_CD_compilation_NRI
{
meta:
    extension = "NRI"
    description = "Nero_CD_compilation"
strings:
    $1 = { 0E 4E 65 72 6F 49 53 4F }
condition:
    $1 at 0
}

rule Lotus_Notes_database_NSF
{
meta:
    extension = "NSF"
    description = "Lotus_Notes_database"
strings:
    $1 = { 1A 00 00 04 00 00 }
condition:
    $1 at 0
}

rule NES_Sound_file_NSF
{
meta:
    extension = "NSF"
    description = "NES_Sound_file"
strings:
    $1 = { 4E 45 53 4D 1A 01 }
condition:
    $1 at 0
}

rule Lotus_Notes_database_template_NTF
{
meta:
    extension = "NTF"
    description = "Lotus_Notes_database_template"
strings:
    $1 = { 1A 00 00 }
condition:
    $1 at 0
}

rule National_Imagery_Transmission_Format_file_NTF
{
meta:
    extension = "NTF"
    description = "National_Imagery_Transmission_Format_file"
strings:
    $1 = { 4E 49 54 46 30 }
condition:
    $1 at 0
}

rule National_Transfer_Format_Map_NTF
{
meta:
    extension = "NTF"
    description = "National_Transfer_Format_Map"
strings:
    $1 = { 30 31 4F 52 44 4E 41 4E }
condition:
    $1 at 0
}

rule VMware_BIOS_state_file_NVRAM
{
meta:
    extension = "NVRAM"
    description = "VMware_BIOS_state_file"
strings:
    $1 = { 4D 52 56 4E }
condition:
    $1 at 0
}

rule MS_COFF_relocatable_object_code_OBJ
{
meta:
    extension = "OBJ"
    description = "MS_COFF_relocatable_object_code"
strings:
    $1 = { 4C 01 }
condition:
    $1 at 0
}

rule Relocatable_object_code_OBJ
{
meta:
    extension = "OBJ"
    description = "Relocatable_object_code"
strings:
    $1 = { 80 }
condition:
    $1 at 0
}

rule OpenDocument_template_ODP
{
meta:
    extension = "ODP"
    description = "OpenDocument_template"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule OpenDocument_template_ODT
{
meta:
    extension = "ODT"
    description = "OpenDocument_template"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule Ogg_Vorbis_Codec_compressed_file_OGA
{
meta:
    extension = "OGA"
    description = "Ogg_Vorbis_Codec_compressed_file"
strings:
    $1 = { 4F 67 67 53 00 02 00 00 }
condition:
    $1 at 0
}

rule Ogg_Vorbis_Codec_compressed_file_OGG
{
meta:
    extension = "OGG"
    description = "Ogg_Vorbis_Codec_compressed_file"
strings:
    $1 = { 4F 67 67 53 00 02 00 00 }
condition:
    $1 at 0
}

rule Ogg_Vorbis_Codec_compressed_file_OGV
{
meta:
    extension = "OGV"
    description = "Ogg_Vorbis_Codec_compressed_file"
strings:
    $1 = { 4F 67 67 53 00 02 00 00 }
condition:
    $1 at 0
}

rule Ogg_Vorbis_Codec_compressed_file_OGX
{
meta:
    extension = "OGX"
    description = "Ogg_Vorbis_Codec_compressed_file"
strings:
    $1 = { 4F 67 67 53 00 02 00 00 }
condition:
    $1 at 0
}

rule MS_OneNote_note_ONE
{
meta:
    extension = "ONE"
    description = "MS_OneNote_note"
strings:
    $1 = { E4 52 5C 7B 8C D8 A7 4D }
condition:
    $1 at 0
}

rule Developer_Studio_File_Options_file_OPT
{
meta:
    extension = "OPT"
    description = "Developer_Studio_File_Options_file"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule Developer_Studio_subheader_OPT
{
meta:
    extension = "OPT"
    description = "Developer_Studio_subheader"
strings:
    $1 = { FD FF FF FF 20 }
condition:
    $1 at 0
}

rule AOL_personal_file_cabinet_ORG
{
meta:
    extension = "ORG"
    description = "AOL_personal_file_cabinet"
strings:
    $1 = { 41 4F 4C 56 4D 31 30 30 }
condition:
    $1 at 0
}

rule OpenDocument_template_OTT
{
meta:
    extension = "OTT"
    description = "OpenDocument_template"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule Intel_PROset_Wireless_Profile_P10
{
meta:
    extension = "P10"
    description = "Intel_PROset_Wireless_Profile"
strings:
    $1 = { 64 00 00 00 }
condition:
    $1 at 0
}

rule PAK_Compressed_archive_file_PAK
{
meta:
    extension = "PAK"
    description = "PAK_Compressed_archive_file"
strings:
    $1 = { 1A 0B }
condition:
    $1 at 0
}

rule Quake_archive_file_PAK
{
meta:
    extension = "PAK"
    description = "Quake_archive_file"
strings:
    $1 = { 50 41 43 4B }
condition:
    $1 at 0
}

rule GIMP_pattern_file_PAT
{
meta:
    extension = "PAT"
    description = "GIMP_pattern_file"
strings:
    $1 = { 47 50 41 54 }
condition:
    $1 at 0
}

rule PAX_password_protected_bitmap_PAX
{
meta:
    extension = "PAX"
    description = "PAX_password_protected_bitmap"
strings:
    $1 = { 50 41 58 }
condition:
    $1 at 0
}

rule Visual_C_PreCompiled_header_PCH
{
meta:
    extension = "PCH"
    description = "Visual_C_PreCompiled_header"
strings:
    $1 = { 56 43 50 43 48 30 }
condition:
    $1 at 0
}

rule ZSOFT_Paintbrush_file_3_PCX
{
meta:
    extension = "PCX"
    description = "ZSOFT_Paintbrush_file_3"
strings:
    $1 = { 0A 05 01 01 }
condition:
    $1 at 0
}

rule ZSOFT_Paintbrush_file_2_PCX
{
meta:
    extension = "PCX"
    description = "ZSOFT_Paintbrush_file_2"
strings:
    $1 = { 0A 03 01 01 }
condition:
    $1 at 0
}

rule ZSOFT_Paintbrush_file_1_PCX
{
meta:
    extension = "PCX"
    description = "ZSOFT_Paintbrush_file_1"
strings:
    $1 = { 0A 02 01 01 }
condition:
    $1 at 0
}

rule MS_C__debugging_symbols_file_PDB
{
meta:
    extension = "PDB"
    description = "MS_C__debugging_symbols_file"
strings:
    $1 = { 4D 69 63 72 6F 73 6F 66 74 20 43 2F 43 2B 2B 20 }
condition:
    $1 at 0
}

rule Merriam_Webster_Pocket_Dictionary_PDB
{
meta:
    extension = "PDB"
    description = "Merriam_Webster_Pocket_Dictionary"
strings:
    $1 = { 4D 2D 57 20 50 6F 63 6B }
condition:
    $1 at 0
}

rule BGBlitz_position_database_file_PDB
{
meta:
    extension = "PDB"
    description = "BGBlitz_position_database_file"
strings:
    $1 = { AC ED 00 05 73 72 00 12 }
condition:
    $1 at 0
}

rule PowerBASIC_Debugger_Symbols_PDB
{
meta:
    extension = "PDB"
    description = "PowerBASIC_Debugger_Symbols"
strings:
    $1 = { 73 7A 65 7A }
condition:
    $1 at 0
}

rule PalmOS_SuperMemo_PDB
{
meta:
    extension = "PDB"
    description = "PalmOS_SuperMemo"
strings:
    $1 = { 73 6D 5F }
condition:
    $1 at 0
}

rule PDF_file_PDF
{
meta:
    extension = "PDF"
    description = "PDF_file"
strings:
    $1 = { 25 50 44 46 }
condition:
    $1 at 0
}

rule Windows_prefetch_file_PF
{
meta:
    extension = "PF"
    description = "Windows_prefetch_file"
strings:
    $1 = { 11 00 00 00 53 43 43 41 }
condition:
    $1 at 0
}

rule AOL_config_files_PFC
{
meta:
    extension = "PFC"
    description = "AOL_config_files"
strings:
    $1 = { 41 4F 4C }
condition:
    $1 at 0
}

rule AOL_personal_file_cabinet_PFC
{
meta:
    extension = "PFC"
    description = "AOL_personal_file_cabinet"
strings:
    $1 = { 41 4F 4C 56 4D 31 30 30 }
condition:
    $1 at 0
}

rule PGP_disk_image_PGD
{
meta:
    extension = "PGD"
    description = "PGP_disk_image"
strings:
    $1 = { 50 47 50 64 4D 41 49 4E }
condition:
    $1 at 0
}

rule Portable_Graymap_Graphic_PGM
{
meta:
    extension = "PGM"
    description = "Portable_Graymap_Graphic"
strings:
    $1 = { 50 35 0A }
condition:
    $1 at 0
}

rule PGP_public_keyring_PKR
{
meta:
    extension = "PKR"
    description = "PGP_public_keyring"
strings:
    $1 = { 99 01 }
condition:
    $1 at 0
}

rule PNG_image_PNG
{
meta:
    extension = "PNG"
    description = "PNG_image"
strings:
    $1 = { 89 50 4E 47 0D 0A 1A 0A }
condition:
    $1 at 0
}

rule Microsoft_Office_document_PPS
{
meta:
    extension = "PPS"
    description = "Microsoft_Office_document"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule PowerPoint_presentation_subheader_6_PPT
{
meta:
    extension = "PPT"
    description = "PowerPoint_presentation_subheader_6"
strings:
    $1 = { FD FF FF FF 43 00 00 00 }
condition:
    $1 at 0
}

rule PowerPoint_presentation_subheader_5_PPT
{
meta:
    extension = "PPT"
    description = "PowerPoint_presentation_subheader_5"
strings:
    $1 = { FD FF FF FF 1C 00 00 00 }
condition:
    $1 at 0
}

rule Microsoft_Office_document_PPT
{
meta:
    extension = "PPT"
    description = "Microsoft_Office_document"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule PowerPoint_presentation_subheader_4_PPT
{
meta:
    extension = "PPT"
    description = "PowerPoint_presentation_subheader_4"
strings:
    $1 = { FD FF FF FF 0E 00 00 00 }
condition:
    $1 at 0
}

rule PowerPoint_presentation_subheader_3_PPT
{
meta:
    extension = "PPT"
    description = "PowerPoint_presentation_subheader_3"
strings:
    $1 = { A0 46 1D F0 }
condition:
    $1 at 0
}

rule PowerPoint_presentation_subheader_2_PPT
{
meta:
    extension = "PPT"
    description = "PowerPoint_presentation_subheader_2"
strings:
    $1 = { 0F 00 E8 03 }
condition:
    $1 at 0
}

rule PowerPoint_presentation_subheader_1_PPT
{
meta:
    extension = "PPT"
    description = "PowerPoint_presentation_subheader_1"
strings:
    $1 = { 00 6E 1E F0 }
condition:
    $1 at 0
}

rule MS_Office_Open_XML_Format_Document_PPTX
{
meta:
    extension = "PPTX"
    description = "MS_Office_Open_XML_Format_Document"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule MS_Office_2007_documents_PPTX
{
meta:
    extension = "PPTX"
    description = "MS_Office_2007_documents"
strings:
    $1 = { 50 4B 03 04 14 00 06 00 }
condition:
    $1 at 0
}

rule Powerpoint_Packaged_Presentation_PPZ
{
meta:
    extension = "PPZ"
    description = "Powerpoint_Packaged_Presentation"
strings:
    $1 = { 4D 53 43 46 }
condition:
    $1 at 0
}

rule PathWay_Map_file_PRC
{
meta:
    extension = "PRC"
    description = "PathWay_Map_file"
strings:
    $1 = { 74 42 4D 50 4B 6E 57 72 }
condition:
    $1 at 0
}

rule Palmpilot_resource_file_PRC
{
meta:
    extension = "PRC"
    description = "Palmpilot_resource_file"
strings:
    $1 = { 42 4F 4F 4B 4D 4F 42 49 }
condition:
    $1 at 0
}

rule Photoshop_image_PSD
{
meta:
    extension = "PSD"
    description = "Photoshop_image"
strings:
    $1 = { 38 42 50 53 }
condition:
    $1 at 0
}

rule Corel_Paint_Shop_Pro_image_PSP
{
meta:
    extension = "PSP"
    description = "Corel_Paint_Shop_Pro_image"
strings:
    $1 = { 7E 42 4B 00 }
condition:
    $1 at 0
}

rule MS_Publisher_file_PUB
{
meta:
    extension = "PUB"
    description = "MS_Publisher_file"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule MS_WinMobile_personal_note_PWI
{
meta:
    extension = "PWI"
    description = "MS_WinMobile_personal_note"
strings:
    $1 = { 7B 5C 70 77 69 }
condition:
    $1 at 0
}

rule Win98_password_file_PWL
{
meta:
    extension = "PWL"
    description = "Win98_password_file"
strings:
    $1 = { E3 82 85 96 }
condition:
    $1 at 0
}

rule Win95_password_file_PWL
{
meta:
    extension = "PWL"
    description = "Win95_password_file"
strings:
    $1 = { B0 4D 46 43 }
condition:
    $1 at 0
}

rule QuickBooks_backup_QBB
{
meta:
    extension = "QBB"
    description = "QuickBooks_backup"
strings:
    $1 = { 45 86 00 00 06 00 }
condition:
    $1 at 0
}

rule Resource_Interchange_File_Format_QCP
{
meta:
    extension = "QCP"
    description = "Resource_Interchange_File_Format"
strings:
    $1 = { 52 49 46 46 }
condition:
    $1 at 0
}

rule QDF_Quicken_data_QDF
{
meta:
    extension = "QDF"
    description = "QDF_Quicken_data"
strings:
    $1 = { AC 9E BD 8F 00 00 }
condition:
    $1 at 0
}

rule QDL_Quicken_data_QEL
{
meta:
    extension = "QEL"
    description = "QDL_Quicken_data"
strings:
    $1 = { 51 45 4C 20 }
condition:
    $1 at 0
}

rule Qcow_Disk_Image_QEMU
{
meta:
    extension = "QEMU"
    description = "Qcow_Disk_Image"
strings:
    $1 = { 51 46 49 }
condition:
    $1 at 0
}

rule Quicken_price_history_QPH
{
meta:
    extension = "QPH"
    description = "Quicken_price_history"
strings:
    $1 = { 03 00 00 00 }
condition:
    $1 at 0
}

rule ABD__QSD_Quicken_data_file_QSD
{
meta:
    extension = "QSD"
    description = "ABD__QSD_Quicken_data_file"
strings:
    $1 = { 51 57 20 56 65 72 2E 20 }
condition:
    $1 at 0
}

rule Quark_Express_Motorola_QXD
{
meta:
    extension = "QXD"
    description = "Quark_Express_Motorola_"
strings:
    $1 = { 00 00 4D 4D 58 50 52 }
condition:
    $1 at 0
}

rule Quark_Express_Intel_QXD
{
meta:
    extension = "QXD"
    description = "Quark_Express_Intel_"
strings:
    $1 = { 00 00 49 49 58 50 52 }
condition:
    $1 at 0
}

rule RealAudio_streaming_media_RA
{
meta:
    extension = "RA"
    description = "RealAudio_streaming_media"
strings:
    $1 = { 2E 72 61 FD 00 }
condition:
    $1 at 0
}

rule RealAudio_file_RA
{
meta:
    extension = "RA"
    description = "RealAudio_file"
strings:
    $1 = { 2E 52 4D 46 00 00 00 12 }
condition:
    $1 at 0
}

rule RealMedia_metafile_RAM
{
meta:
    extension = "RAM"
    description = "RealMedia_metafile"
strings:
    $1 = { 72 74 73 70 3A 2F 2F }
condition:
    $1 at 0
}

rule WinRAR_compressed_archive_RAR
{
meta:
    extension = "RAR"
    description = "WinRAR_compressed_archive"
strings:
    $1 = { 52 61 72 21 1A 07 00 }
condition:
    $1 at 0
}

rule WinNT_Registry_Registry_Undo_files_REG
{
meta:
    extension = "REG"
    description = "WinNT_Registry_Registry_Undo_files"
strings:
    $1 = { 52 45 47 45 44 49 54 }
condition:
    $1 at 0
}

rule Windows_Registry_file_REG
{
meta:
    extension = "REG"
    description = "Windows_Registry_file"
strings:
    $1 = { FF FE }
condition:
    $1 at 0
}

rule Silicon_Graphics_RGB_Bitmap_RGB
{
meta:
    extension = "RGB"
    description = "Silicon_Graphics_RGB_Bitmap"
strings:
    $1 = { 01 DA 01 01 00 03 }
condition:
    $1 at 0
}

rule RealMedia_streaming_media_RM
{
meta:
    extension = "RM"
    description = "RealMedia_streaming_media"
strings:
    $1 = { 2E 52 4D 46 }
condition:
    $1 at 0
}

rule Resource_Interchange_File_Format_RMI
{
meta:
    extension = "RMI"
    description = "Resource_Interchange_File_Format"
strings:
    $1 = { 52 49 46 46 }
condition:
    $1 at 0
}

rule RealMedia_streaming_media_RMVB
{
meta:
    extension = "RMVB"
    description = "RealMedia_streaming_media"
strings:
    $1 = { 2E 52 4D 46 }
condition:
    $1 at 0
}

rule RedHat_Package_Manager_RPM
{
meta:
    extension = "RPM"
    description = "RedHat_Package_Manager"
strings:
    $1 = { ED AB EE DB }
condition:
    $1 at 0
}

rule RagTime_document_RTD
{
meta:
    extension = "RTD"
    description = "RagTime_document"
strings:
    $1 = { 43 23 2B 44 A4 43 4D A5 }
condition:
    $1 at 0
}

rule RTF_file_RTF
{
meta:
    extension = "RTF"
    description = "RTF_file"
strings:
    $1 = { 7B 5C 72 74 66 31 }
condition:
    $1 at 0
}

rule Revit_Project_file_RVT
{
meta:
    extension = "RVT"
    description = "Revit_Project_file"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule Lotus_AMI_Pro_document_2_SAM
{
meta:
    extension = "SAM"
    description = "Lotus_AMI_Pro_document_2"
strings:
    $1 = { 5B 76 65 72 5D }
condition:
    $1 at 0
}

rule Lotus_AMI_Pro_document_1_SAM
{
meta:
    extension = "SAM"
    description = "Lotus_AMI_Pro_document_1"
strings:
    $1 = { 5B 56 45 52 5D }
condition:
    $1 at 0
}

rule SPSS_Data_file_SAV
{
meta:
    extension = "SAV"
    description = "SPSS_Data_file"
strings:
    $1 = { 24 46 4C 32 40 28 23 29 }
condition:
    $1 at 0
}

rule SmartDraw_Drawing_file_SDR
{
meta:
    extension = "SDR"
    description = "SmartDraw_Drawing_file"
strings:
    $1 = { 53 4D 41 52 54 44 52 57 }
condition:
    $1 at 0
}

rule Harvard_Graphics_presentation_file_SH3
{
meta:
    extension = "SH3"
    description = "Harvard_Graphics_presentation_file"
strings:
    $1 = { 48 48 47 42 31 }
condition:
    $1 at 0
}

rule Win2000_XP_printer_spool_file_SHD
{
meta:
    extension = "SHD"
    description = "Win2000_XP_printer_spool_file"
strings:
    $1 = { 67 49 00 00 }
condition:
    $1 at 0
}

rule Win9x_printer_spool_file_SHD
{
meta:
    extension = "SHD"
    description = "Win9x_printer_spool_file"
strings:
    $1 = { 4B 49 00 00 }
condition:
    $1 at 0
}

rule WinNT_printer_spool_file_SHD
{
meta:
    extension = "SHD"
    description = "WinNT_printer_spool_file"
strings:
    $1 = { 66 49 00 00 }
condition:
    $1 at 0
}

rule Win_Server_2003_printer_spool_file_SHD
{
meta:
    extension = "SHD"
    description = "Win_Server_2003_printer_spool_file"
strings:
    $1 = { 68 49 00 00 }
condition:
    $1 at 0
}

rule Harvard_Graphics_presentation_SHW
{
meta:
    extension = "SHW"
    description = "Harvard_Graphics_presentation"
strings:
    $1 = { 53 48 4F 57 }
condition:
    $1 at 0
}

rule StuffIt_compressed_archive_SIT
{
meta:
    extension = "SIT"
    description = "StuffIt_compressed_archive"
strings:
    $1 = { 53 74 75 66 66 49 74 20 }
condition:
    $1 at 0
}

rule StuffIt_archive_SIT
{
meta:
    extension = "SIT"
    description = "StuffIt_archive"
strings:
    $1 = { 53 49 54 21 00 }
condition:
    $1 at 0
}

rule SkinCrafter_skin_SKF
{
meta:
    extension = "SKF"
    description = "SkinCrafter_skin"
strings:
    $1 = { 07 53 4B 46 }
condition:
    $1 at 0
}

rule PGP_secret_keyring_2_SKR
{
meta:
    extension = "SKR"
    description = "PGP_secret_keyring_2"
strings:
    $1 = { 95 01 }
condition:
    $1 at 0
}

rule PGP_secret_keyring_1_SKR
{
meta:
    extension = "SKR"
    description = "PGP_secret_keyring_1"
strings:
    $1 = { 95 00 }
condition:
    $1 at 0
}

rule Surfplan_kite_project_file_SLE
{
meta:
    extension = "SLE"
    description = "Surfplan_kite_project_file"
strings:
    $1 = { 3A 56 45 52 53 49 4F 4E }
condition:
    $1 at 0
}

rule Steganos_virtual_secure_drive_SLE
{
meta:
    extension = "SLE"
    description = "Steganos_virtual_secure_drive"
strings:
    $1 = { 41 43 76 }
condition:
    $1 at 0
}

rule Visual_Studio_NET_file_SLN
{
meta:
    extension = "SLN"
    description = "Visual_Studio_NET_file"
strings:
    $1 = { 4D 69 63 72 6F 73 6F 66 74 20 56 69 73 75 61 6C }
condition:
    $1 at 0
}

rule Netscape_Communicator_v4_mail_folder_SNM
{
meta:
    extension = "SNM"
    description = "Netscape_Communicator_v4_mail_folder"
strings:
    $1 = { 00 1E 84 90 00 00 00 00 }
condition:
    $1 at 0
}

rule MS_Access_Snapshot_Viewer_file_SNP
{
meta:
    extension = "SNP"
    description = "MS_Access_Snapshot_Viewer_file"
strings:
    $1 = { 4D 53 43 46 }
condition:
    $1 at 0
}

rule Visual_Studio_Solution_User_Options_file_SOU
{
meta:
    extension = "SOU"
    description = "Visual_Studio_Solution_User_Options_file"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule Windows_icon_printer_spool_file_SPL
{
meta:
    extension = "SPL"
    description = "Windows_icon_printer_spool_file"
strings:
    $1 = { 00 00 01 00 }
condition:
    $1 at 0
}

rule SPSS_output_file_SPO
{
meta:
    extension = "SPO"
    description = "SPSS_output_file"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule WinNT_Registry_Registry_Undo_files_SUD
{
meta:
    extension = "SUD"
    description = "WinNT_Registry_Registry_Undo_files"
strings:
    $1 = { 52 45 47 45 44 49 54 }
condition:
    $1 at 0
}

rule Visual_Studio_Solution_subheader_SUO
{
meta:
    extension = "SUO"
    description = "Visual_Studio_Solution_subheader"
strings:
    $1 = { FD FF FF FF 04 }
condition:
    $1 at 0
}

rule Shockwave_Flash_player_SWF
{
meta:
    extension = "SWF"
    description = "Shockwave_Flash_player"
strings:
    $1 = { 46 57 53 }
condition:
    $1 at 0
}

rule Shockwave_Flash_file_SWF
{
meta:
    extension = "SWF"
    description = "Shockwave_Flash_file"
strings:
    $1 = { 43 57 53 }
condition:
    $1 at 0
}

rule StarOffice_spreadsheet_SXC
{
meta:
    extension = "SXC"
    description = "StarOffice_spreadsheet"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule OpenOffice_documents_SXD
{
meta:
    extension = "SXD"
    description = "OpenOffice_documents"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule OpenOffice_documents_SXI
{
meta:
    extension = "SXI"
    description = "OpenOffice_documents"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule OpenOffice_documents_SXW
{
meta:
    extension = "SXW"
    description = "OpenOffice_documents"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule Windows_executable_SYS
{
meta:
    extension = "SYS"
    description = "Windows_executable"
strings:
    $1 = { FF }
condition:
    $1 at 0
}

rule Windows_executable_file_3_SYS
{
meta:
    extension = "SYS"
    description = "Windows_executable_file_3"
strings:
    $1 = { EB }
condition:
    $1 at 0
}

rule Windows_executable_file_2_SYS
{
meta:
    extension = "SYS"
    description = "Windows_executable_file_2"
strings:
    $1 = { E9 }
condition:
    $1 at 0
}

rule Windows_executable_file_1_SYS
{
meta:
    extension = "SYS"
    description = "Windows_executable_file_1"
strings:
    $1 = { E8 }
condition:
    $1 at 0
}

rule Keyboard_driver_file_SYS
{
meta:
    extension = "SYS"
    description = "Keyboard_driver_file"
strings:
    $1 = { FF 4B 45 59 42 20 20 20 }
condition:
    $1 at 0
}

rule DOS_system_driver_SYS
{
meta:
    extension = "SYS"
    description = "DOS_system_driver"
strings:
    $1 = { FF FF FF FF }
condition:
    $1 at 0
}

rule Harvard_Graphics_symbol_graphic_SYW
{
meta:
    extension = "SYW"
    description = "Harvard_Graphics_symbol_graphic"
strings:
    $1 = { 41 4D 59 4F }
condition:
    $1 at 0
}

rule Tape_Archive_TAR
{
meta:
    extension = "TAR"
    description = "Tape_Archive"
strings:
    $1 = { 75 73 74 61 72 }
condition:
    $1 at 0
}

rule bzip2_compressed_archive_TAR_BZ2
{
meta:
    extension = "TAR.BZ2"
    description = "bzip2_compressed_archive"
strings:
    $1 = { 42 5A 68 }
condition:
    $1 at 0
}

rule Compressed_tape_archive_2_TAR_Z
{
meta:
    extension = "TAR.Z"
    description = "Compressed_tape_archive_2"
strings:
    $1 = { 1F A0 }
condition:
    $1 at 0
}

rule Compressed_tape_archive_1_TAR_Z
{
meta:
    extension = "TAR.Z"
    description = "Compressed_tape_archive_1"
strings:
    $1 = { 1F 9D 90 }
condition:
    $1 at 0
}

rule bzip2_compressed_archive_TB2
{
meta:
    extension = "TB2"
    description = "bzip2_compressed_archive"
strings:
    $1 = { 42 5A 68 }
condition:
    $1 at 0
}

rule bzip2_compressed_archive_TBZ2
{
meta:
    extension = "TBZ2"
    description = "bzip2_compressed_archive"
strings:
    $1 = { 42 5A 68 }
condition:
    $1 at 0
}

rule Acronis_True_Image_TIB
{
meta:
    extension = "TIB"
    description = "Acronis_True_Image"
strings:
    $1 = { B4 6E 68 44 }
condition:
    $1 at 0
}

rule TIFF_file_3_TIF
{
meta:
    extension = "TIF"
    description = "TIFF_file_3"
strings:
    $1 = { 4D 4D 00 2A }
condition:
    $1 at 0
}

rule TIFF_file_2_TIF
{
meta:
    extension = "TIF"
    description = "TIFF_file_2"
strings:
    $1 = { 49 49 2A 00 }
condition:
    $1 at 0
}

rule TIFF_file_1_TIF
{
meta:
    extension = "TIF"
    description = "TIFF_file_1"
strings:
    $1 = { 49 20 49 }
condition:
    $1 at 0
}

rule TIFF_file_4_TIF
{
meta:
    extension = "TIF"
    description = "TIFF_file_4"
strings:
    $1 = { 4D 4D 00 2B }
condition:
    $1 at 0
}

rule TIFF_file_2_TIFF
{
meta:
    extension = "TIFF"
    description = "TIFF_file_2"
strings:
    $1 = { 49 49 2A 00 }
condition:
    $1 at 0
}

rule TIFF_file_1_TIFF
{
meta:
    extension = "TIFF"
    description = "TIFF_file_1"
strings:
    $1 = { 49 20 49 }
condition:
    $1 at 0
}

rule TIFF_file_4_TIFF
{
meta:
    extension = "TIFF"
    description = "TIFF_file_4"
strings:
    $1 = { 4D 4D 00 2B }
condition:
    $1 at 0
}

rule TIFF_file_3_TIFF
{
meta:
    extension = "TIFF"
    description = "TIFF_file_3"
strings:
    $1 = { 4D 4D 00 2A }
condition:
    $1 at 0
}

rule OLE_SPSS_Visual_C__library_file_TLB
{
meta:
    extension = "TLB"
    description = "OLE_SPSS_Visual_C__library_file"
strings:
    $1 = { 4D 53 46 54 02 00 01 00 }
condition:
    $1 at 0
}

rule Novell_LANalyzer_capture_file_TR1
{
meta:
    extension = "TR1"
    description = "Novell_LANalyzer_capture_file"
strings:
    $1 = { 01 10 }
condition:
    $1 at 0
}

rule Unicode_extensions_UCE
{
meta:
    extension = "UCE"
    description = "Unicode_extensions"
strings:
    $1 = { 55 43 45 58 }
condition:
    $1 at 0
}

rule UFA_compressed_archive_UFA
{
meta:
    extension = "UFA"
    description = "UFA_compressed_archive"
strings:
    $1 = { 55 46 41 C6 D2 C1 }
condition:
    $1 at 0
}

rule VideoVCD_VCDImager_file_VCD
{
meta:
    extension = "VCD"
    description = "VideoVCD_VCDImager_file"
strings:
    $1 = { 45 4E 54 52 59 56 43 44 }
condition:
    $1 at 0
}

rule vCard_VCF
{
meta:
    extension = "VCF"
    description = "vCard"
strings:
    $1 = { 42 45 47 49 4E 3A 56 43 }
condition:
    $1 at 0
}

rule Visual_C__Workbench_Info_File_VCW
{
meta:
    extension = "VCW"
    description = "Visual_C__Workbench_Info_File"
strings:
    $1 = { 5B 4D 53 56 43 }
condition:
    $1 at 0
}

rule Virtual_PC_HD_image_VHD
{
meta:
    extension = "VHD"
    description = "Virtual_PC_HD_image"
strings:
    $1 = { 63 6F 6E 65 63 74 69 78 }
condition:
    $1 at 0
}

rule VMware_4_Virtual_Disk_VMDK
{
meta:
    extension = "VMDK"
    description = "VMware_4_Virtual_Disk"
strings:
    $1 = { 4B 44 4D }
condition:
    $1 at 0
}

rule VMware_4_Virtual_Disk_description_VMDK
{
meta:
    extension = "VMDK"
    description = "VMware_4_Virtual_Disk_description"
strings:
    $1 = { 23 20 44 69 73 6B 20 44 }
condition:
    $1 at 0
}

rule VMware_3_Virtual_Disk_VMDK
{
meta:
    extension = "VMDK"
    description = "VMware_3_Virtual_Disk"
strings:
    $1 = { 43 4F 57 44 }
condition:
    $1 at 0
}

rule DVD_video_file_VOB
{
meta:
    extension = "VOB"
    description = "DVD_video_file"
strings:
    $1 = { 00 00 01 BA }
condition:
    $1 at 0
}

rule Visio_file_VSD
{
meta:
    extension = "VSD"
    description = "Visio_file"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule Outlook_Express_address_book_Win95_WAB
{
meta:
    extension = "WAB"
    description = "Outlook_Express_address_book_Win95_"
strings:
    $1 = { 81 32 84 C1 85 05 D0 11 }
condition:
    $1 at 0
}

rule Outlook_address_file_WAB
{
meta:
    extension = "WAB"
    description = "Outlook_address_file"
strings:
    $1 = { 9C CB CB 8D 13 75 D2 11 }
condition:
    $1 at 0
}

rule Resource_Interchange_File_Format_WAV
{
meta:
    extension = "WAV"
    description = "Resource_Interchange_File_Format"
strings:
    $1 = { 52 49 46 46 }
condition:
    $1 at 0
}

rule QuattroPro_spreadsheet_WB2
{
meta:
    extension = "WB2"
    description = "QuattroPro_spreadsheet"
strings:
    $1 = { 00 00 02 00 }
condition:
    $1 at 0
}

rule Quatro_Pro_for_Windows_7_0_WB3
{
meta:
    extension = "WB3"
    description = "Quatro_Pro_for_Windows_7_0"
strings:
    $1 = { 3E 00 03 00 FE FF 09 00 06 }
condition:
    $1 at 0
}

rule Microsoft_Office_document_WIZ
{
meta:
    extension = "WIZ"
    description = "Microsoft_Office_document"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule Lotus_1_2_3_v1_WK1
{
meta:
    extension = "WK1"
    description = "Lotus_1_2_3_v1_"
strings:
    $1 = { 00 00 02 00 06 04 06 00 }
condition:
    $1 at 0
}

rule Lotus_1_2_3_v3_WK3
{
meta:
    extension = "WK3"
    description = "Lotus_1_2_3_v3_"
strings:
    $1 = { 00 00 1A 00 00 10 04 00 }
condition:
    $1 at 0
}

rule Lotus_1_2_3_v4_v5_WK4
{
meta:
    extension = "WK4"
    description = "Lotus_1_2_3_v4_v5_"
strings:
    $1 = { 00 00 1A 00 02 10 04 00 }
condition:
    $1 at 0
}

rule Lotus_1_2_3_v4_v5_WK5
{
meta:
    extension = "WK5"
    description = "Lotus_1_2_3_v4_v5_"
strings:
    $1 = { 00 00 1A 00 02 10 04 00 }
condition:
    $1 at 0
}

rule DeskMate_Worksheet_WKS
{
meta:
    extension = "WKS"
    description = "DeskMate_Worksheet"
strings:
    $1 = { 0E 57 4B 53 }
condition:
    $1 at 0
}

rule Works_for_Windows_spreadsheet_WKS
{
meta:
    extension = "WKS"
    description = "Works_for_Windows_spreadsheet"
strings:
    $1 = { FF 00 02 00 04 04 05 54 }
condition:
    $1 at 0
}

rule Windows_Media_Audio_Video_File_WMA
{
meta:
    extension = "WMA"
    description = "Windows_Media_Audio_Video_File"
strings:
    $1 = { 30 26 B2 75 8E 66 CF 11 }
condition:
    $1 at 0
}

rule Windows_graphics_metafile_WMF
{
meta:
    extension = "WMF"
    description = "Windows_graphics_metafile"
strings:
    $1 = { D7 CD C6 9A }
condition:
    $1 at 0
}

rule Windows_Media_Audio_Video_File_WMV
{
meta:
    extension = "WMV"
    description = "Windows_Media_Audio_Video_File"
strings:
    $1 = { 30 26 B2 75 8E 66 CF 11 }
condition:
    $1 at 0
}

rule Windows_Media_compressed_skin_file_WMZ
{
meta:
    extension = "WMZ"
    description = "Windows_Media_compressed_skin_file"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule WordPerfect_text_and_graphics_WP
{
meta:
    extension = "WP"
    description = "WordPerfect_text_and_graphics"
strings:
    $1 = { FF 57 50 43 }
condition:
    $1 at 0
}

rule WordPerfect_text_and_graphics_WP5
{
meta:
    extension = "WP5"
    description = "WordPerfect_text_and_graphics"
strings:
    $1 = { FF 57 50 43 }
condition:
    $1 at 0
}

rule WordPerfect_text_and_graphics_WP6
{
meta:
    extension = "WP6"
    description = "WordPerfect_text_and_graphics"
strings:
    $1 = { FF 57 50 43 }
condition:
    $1 at 0
}

rule WordPerfect_text_and_graphics_WPD
{
meta:
    extension = "WPD"
    description = "WordPerfect_text_and_graphics"
strings:
    $1 = { FF 57 50 43 }
condition:
    $1 at 0
}

rule WordPerfect_text_WPF
{
meta:
    extension = "WPF"
    description = "WordPerfect_text"
strings:
    $1 = { 81 CD AB }
condition:
    $1 at 0
}

rule WordPerfect_text_and_graphics_WPG
{
meta:
    extension = "WPG"
    description = "WordPerfect_text_and_graphics"
strings:
    $1 = { FF 57 50 43 }
condition:
    $1 at 0
}

rule Windows_Media_Player_playlist_WPL
{
meta:
    extension = "WPL"
    description = "Windows_Media_Player_playlist"
strings:
    $1 = { 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 4D 65 64 69 61 20 50 6C 61 79 65 72 20 2D 2D 20 }
condition:
    $1 at 0
}

rule WordPerfect_text_and_graphics_WPP
{
meta:
    extension = "WPP"
    description = "WordPerfect_text_and_graphics"
strings:
    $1 = { FF 57 50 43 }
condition:
    $1 at 0
}

rule MSWorks_text_document_WPS
{
meta:
    extension = "WPS"
    description = "MSWorks_text_document"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule MS_Write_file_3_WRI
{
meta:
    extension = "WRI"
    description = "MS_Write_file_3"
strings:
    $1 = { BE 00 00 00 AB }
condition:
    $1 at 0
}

rule MS_Write_file_2_WRI
{
meta:
    extension = "WRI"
    description = "MS_Write_file_2"
strings:
    $1 = { 32 BE }
condition:
    $1 at 0
}

rule MS_Write_file_1_WRI
{
meta:
    extension = "WRI"
    description = "MS_Write_file_1"
strings:
    $1 = { 31 BE }
condition:
    $1 at 0
}

rule WordStar_Version_5_0_6_0_document_WS
{
meta:
    extension = "WS"
    description = "WordStar_Version_5_0_6_0_document"
strings:
    $1 = { 1D 7D }
condition:
    $1 at 0
}

rule WordStar_for_Windows_file_WS2
{
meta:
    extension = "WS2"
    description = "WordStar_for_Windows_file"
strings:
    $1 = { 57 53 32 30 30 30 }
condition:
    $1 at 0
}

rule BizTalk_XML_Data_Reduced_Schema_XDR
{
meta:
    extension = "XDR"
    description = "BizTalk_XML_Data_Reduced_Schema"
strings:
    $1 = { 3C }
condition:
    $1 at 0
}

rule Microsoft_Office_document_XLA
{
meta:
    extension = "XLA"
    description = "Microsoft_Office_document"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule Excel_spreadsheet_subheader_2_XLS
{
meta:
    extension = "XLS"
    description = "Excel_spreadsheet_subheader_2"
strings:
    $1 = { FD FF FF FF 10 }
condition:
    $1 at 0
}

rule Excel_spreadsheet_subheader_1_XLS
{
meta:
    extension = "XLS"
    description = "Excel_spreadsheet_subheader_1"
strings:
    $1 = { 09 08 10 00 00 06 05 00 }
condition:
    $1 at 0
}

rule Excel_spreadsheet_subheader_7_XLS
{
meta:
    extension = "XLS"
    description = "Excel_spreadsheet_subheader_7"
strings:
    $1 = { FD FF FF FF 29 }
condition:
    $1 at 0
}

rule Excel_spreadsheet_subheader_6_XLS
{
meta:
    extension = "XLS"
    description = "Excel_spreadsheet_subheader_6"
strings:
    $1 = { FD FF FF FF 28 }
condition:
    $1 at 0
}

rule Excel_spreadsheet_subheader_5_XLS
{
meta:
    extension = "XLS"
    description = "Excel_spreadsheet_subheader_5"
strings:
    $1 = { FD FF FF FF 23 }
condition:
    $1 at 0
}

rule Microsoft_Office_document_XLS
{
meta:
    extension = "XLS"
    description = "Microsoft_Office_document"
strings:
    $1 = { D0 CF 11 E0 A1 B1 1A E1 }
condition:
    $1 at 0
}

rule Excel_spreadsheet_subheader_4_XLS
{
meta:
    extension = "XLS"
    description = "Excel_spreadsheet_subheader_4"
strings:
    $1 = { FD FF FF FF 22 }
condition:
    $1 at 0
}

rule Excel_spreadsheet_subheader_3_XLS
{
meta:
    extension = "XLS"
    description = "Excel_spreadsheet_subheader_3"
strings:
    $1 = { FD FF FF FF 1F }
condition:
    $1 at 0
}

rule MS_Office_Open_XML_Format_Document_XLSX
{
meta:
    extension = "XLSX"
    description = "MS_Office_Open_XML_Format_Document"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule MS_Office_2007_documents_XLSX
{
meta:
    extension = "XLSX"
    description = "MS_Office_2007_documents"
strings:
    $1 = { 50 4B 03 04 14 00 06 00 }
condition:
    $1 at 0
}

rule User_Interface_Language_XML
{
meta:
    extension = "XML"
    description = "User_Interface_Language"
strings:
    $1 = { 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 3F 3E }
condition:
    $1 at 0
}

rule Mozilla_Browser_Archive_XPI
{
meta:
    extension = "XPI"
    description = "Mozilla_Browser_Archive"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule XML_paper_specification_file_XPS
{
meta:
    extension = "XPS"
    description = "XML_paper_specification_file"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule eXact_Packager_Models_XPT
{
meta:
    extension = "XPT"
    description = "eXact_Packager_Models"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule XPCOM_libraries_XPT
{
meta:
    extension = "XPT"
    description = "XPCOM_libraries"
strings:
    $1 = { 58 50 43 4F 4D 0A 54 79 }
condition:
    $1 at 0
}

rule ZLock_Pro_encrypted_ZIP_ZIP
{
meta:
    extension = "ZIP"
    description = "ZLock_Pro_encrypted_ZIP"
strings:
    $1 = { 50 4B 03 04 14 00 01 00 }
condition:
    $1 at 0
}

rule PKZIP_archive_3_ZIP
{
meta:
    extension = "ZIP"
    description = "PKZIP_archive_3"
strings:
    $1 = { 50 4B 07 08 }
condition:
    $1 at 0
}

rule PKZIP_archive_2_ZIP
{
meta:
    extension = "ZIP"
    description = "PKZIP_archive_2"
strings:
    $1 = { 50 4B 05 06 }
condition:
    $1 at 0
}

rule PKZIP_archive_1_ZIP
{
meta:
    extension = "ZIP"
    description = "PKZIP_archive_1"
strings:
    $1 = { 50 4B 03 04 }
condition:
    $1 at 0
}

rule PKSFX_self_extracting_archive_ZIP
{
meta:
    extension = "ZIP"
    description = "PKSFX_self_extracting_archive"
strings:
    $1 = { 50 4B 53 70 58 }
condition:
    $1 at 0
}

rule PKLITE_archive_ZIP
{
meta:
    extension = "ZIP"
    description = "PKLITE_archive"
strings:
    $1 = { 50 4B 4C 49 54 45 }
condition:
    $1 at 0
}

rule WinZip_compressed_archive_ZIP
{
meta:
    extension = "ZIP"
    description = "WinZip_compressed_archive"
strings:
    $1 = { 57 69 6E 5A 69 70 }
condition:
    $1 at 0
}

rule ZOO_compressed_archive_ZOO
{
meta:
    extension = "ZOO"
    description = "ZOO_compressed_archive"
strings:
    $1 = { 5A 4F 4F 20 }
condition:
    $1 at 0
}
