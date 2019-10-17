/*
__G__ = "(G)bd249ce4"
*/

rule AntiVMGeneric
{
strings:
	$ = { 0f 01 0d 00 00 00 00 c3 }
	$ = { 45 C7 00 01 }
	$ = { 0f 3f 07 0b c7 45 fc ff ff ff ff }
    $ = "avghookx.dll" wide nocase ascii
    $ = "avghooka.dll" wide nocase ascii
    $ = "cmdvrt64.dll" wide nocase ascii
    $ = "cmdvrt32.dll" wide nocase ascii
    $ = "snxhk.dll" wide nocase ascii
    $ = "sbiedll.dll" wide nocase ascii
    $ = "dbghelp.dll" wide nocase ascii
    $ = "api_log.dll" wide nocase ascii
    $ = "dir_watch.dll" wide nocase ascii
    $ = "pstorec.dll" wide nocase ascii
    $ = "vmcheck.dll" wide nocase ascii
    $ = "wpespy.dll" wide nocase ascii
condition:
    any of them
}

rule VBOX_1
{
strings:
    $RegKey1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
    $Value1 = "Identifier" nocase wide ascii
    $RegKey2 = "HARDWARE\\Description\\System" nocase wide ascii
    $Value2 = "SystemBiosVersion" nocase wide ascii
    $Data = "VBOX" nocase wide ascii
condition:
    any of ($RegKey*) and any of ($Value*) and $Data
}

rule VBOX_2
{
strings:
    $RegKey = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" nocase wide ascii
    $Data = "VBOX" nocase wide ascii
condition:
    all of them
}

rule VBOX_3
{

strings:

//regkey
    $ = "HARDWARE\\ACPI\\DSDT\\VBOX_" nocase wide ascii
    $ = "HARDWARE\\ACPI\\FADT\\VBOX_" nocase wide ascii
    $ = "HARDWARE\\ACPI\\RSDT\\VBOX_" nocase wide ascii
    $ = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase wide ascii
    $ = "SYSTEM\\ControlSet001\\Services\\VBoxGuest" nocase wide ascii
    $ = "SYSTEM\\ControlSet001\\Services\\VBoxMouse" nocase wide ascii
    $ = "SYSTEM\\ControlSet001\\Services\\VBoxService" nocase wide ascii
    $ = "SYSTEM\\ControlSet001\\Services\\VBoxSF" nocase wide ascii
    $ = "SYSTEM\\ControlSet001\\Services\\VBoxVideo" nocase wide ascii

//files
    $ = "system32\\drivers\\VBoxMouse.sys" nocase wide ascii
    $ = "system32\\drivers\\VBoxGuest.sys" nocase wide ascii
    $ = "system32\\drivers\\VBoxSF.sys" nocase wide ascii
    $ = "system32\\drivers\\VBoxVideo.sys" nocase wide ascii
    $ = "system32\\vboxdisp.dll" nocase wide ascii
    $ = "system32\\vboxhook.dll" nocase wide ascii
    $ = "system32\\vboxmrxnp.dll" nocase wide ascii
    $ = "system32\\vboxogl.dll" nocase wide ascii
    $ = "system32\\vboxoglarrayspu.dll" nocase wide ascii
    $ = "system32\\vboxoglcrutil.dll" nocase wide ascii
    $ = "system32\\vboxoglerrorspu.dll" nocase wide ascii
    $ = "system32\\vboxoglfeedbackspu.dll" nocase wide ascii
    $ = "system32\\vboxoglpackspu.dll" nocase wide ascii
    $ = "system32\\vboxoglpassthroughspu.dll" nocase wide ascii
    $ = "system32\\vboxservice.exe" nocase wide ascii
    $ = "system32\\vboxtray.exe" nocase wide ascii
    $ = "system32\\VBoxControl.exe" nocase wide ascii

condition:
    any of them
}

rule VBOX_MAC_Address_CouldBeFP
{
strings:

//may cause false positive
    $ = { 08 00 27 }
    $ = "08:00:27"
    $ = "08-00-27"

condition:
    any of them
}

rule VMWare_1
{
strings:
    $RegKey = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" nocase wide ascii
    $Data = "WMWARE" nocase wide ascii
condition:
    all of them
}

rule VMWare_2
{
strings:

    $ = "SOFTWARE\\VMware, Inc.\\VMware Tools" nocase wide ascii

//files
    $ = "system32\\drivers\\vmhgfs.sys" nocase wide ascii
    $ = "system32\\drivers\\vm3dmp.sys" nocase wide ascii
    $ = "system32\\drivers\\vmci.sys" nocase wide ascii
    $ = "system32\\drivers\\vmmemctl.sys" nocase wide ascii
    $ = "system32\\drivers\\vmrawdsk.sys" nocase wide ascii
    $ = "system32\\drivers\\vmusbmouse.sys" nocase wide ascii
    $ = "System32\\Drivers\\Vmmouse.sys" nocase wide ascii
    $ = "system32\\drivers\\vmsrvc.sys" nocase wide ascii
    $ = "system32\\drivers\\vmx86.sys" nocase wide ascii
    $ = "System32\\Drivers\\vmnet.sys" nocase wide ascii
    $ = "System32\\Drivers\\vm3dgl.dll" nocase wide ascii
    $ = "System32\\Drivers\\vmdum.dll" nocase wide ascii
    $ = "System32\\Drivers\\vm3dver.dll" nocase wide ascii
    $ = "System32\\Drivers\\vmtray.dll" nocase wide ascii
    $ = "System32\\Drivers\\VMToolsHook.dll" nocase wide ascii
    $ = "System32\\Drivers\\vmmousever.dll" nocase wide ascii
    $ = "System32\\Drivers\\vmGuestLib.dll" nocase wide ascii
    $ = "System32\\Drivers\\VmGuestLibJava.dll" nocase wide ascii
    $ = "System32\\Drivers\\vmhgfs.dll" nocase wide ascii

//Processes
    $ = "vmware2" nocase wide ascii
    $ = "vmount2" nocase wide ascii
    $ = "vmusrvc" nocase wide ascii
    $ = "vmsrvc" nocase wide ascii

//Strings
    $ = "Ven_VMware_" nocase wide ascii
    $ = "Prod_VMware_Virtual_" nocase wide ascii
    $ = "vmhgfs.sys" nocase wide ascii
    $ = "vmsrvc.sys" nocase wide ascii
    $ = "vmx86.sys" nocase wide ascii
    $ = "vmnet.sys" nocase wide ascii
    $ = "vmicheartbeat" nocase wide ascii
    $ = "vmicvss" nocase wide ascii
    $ = "vmicshutdown" nocase wide ascii
    $ = "vmicexchange" nocase wide ascii
    $ = "vmdebug" nocase wide ascii
    $ = "vmmouse" nocase wide ascii
    $ = "vmtools" nocase wide ascii
    $ = "VMMEMCTL" nocase wide ascii
    $ = "vmx86" nocase wide ascii
    $ = "vmware" nocase wide ascii
    $ = "vmount2" nocase wide ascii
    $ = "vmusrvc" nocase wide ascii
    $ = "vmsrvc" nocase wide ascii

    $ = "\\\\.\\HGFS" nocase wide ascii
    $ = "\\\\.\\vmci" nocase wide ascii
    $ = "vmtoolsd.exe" nocase wide ascii
    $ = "vmwaretray.exe" nocase wide ascii
    $ = "vmwareuser.exe" nocase wide ascii
    $ = "VGAuthService.exe" nocase wide ascii
    $ = "vmacthlp.exe" nocase wide ascii

    $ = "VBoxDrv" nocase wide ascii
    $ = "VBoxNetAdp" nocase wide ascii
    $ = "VBoxNetLwf" nocase wide ascii
    $ = "VBoxUSB" nocase wide ascii
    $ = "VBoxUSBMon" nocase wide ascii //<--- not needed (VBoxUSB is enough)

//string
    $ = "VBoxGuestAdditions" nocase wide ascii
    $ = "VBOX HARDDISK"nocase wide ascii

//process
    $ = "vboxservice" nocase wide ascii
    $ = "vboxtray" nocase wide ascii

condition:
    any of them
}

rule VMWare_3
{
strings:
    $RegKey1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
    $RegKey2 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
    $RegKey3 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
    $Value = "Identifier" nocase wide ascii
    $Data = "WMWARE" nocase wide ascii
condition:
    any of ($RegKey*) and any of ($Value*) and $Data
}

rule VMWare_4
{
strings:
    $RegKey1 = "SYSTEM\\ControlSet001\\Control\\SystemInformation" nocase wide ascii
    $Value1 = "SystemManufacturer" nocase wide ascii
    $Value2 = "SystemProductName" nocase wide ascii
    $Data = "WMWARE" nocase wide ascii
condition:
    any of ($RegKey*) and any of ($Value*) and $Data
}

rule VMWare_MAC_Address_CouldBeFP
{
strings:

//may cause false positive
    $ = { 00 05 69 }
    $ = "00:05:69"
    $ = "00-05-69"

    $ = { 00 0C 29 }
    $ = "00:0c:29"
    $ = "00-0c-29"

    $ = { 00 1C 14 }
    $ = "00:1C:14"
    $ = "00-1C-14"

    $ = { 00 50 56 }
    $ = "00:50:56"
    $ = "00-50-56"

condition:
    any of them
}

rule Qemu_1
{
strings:
    $RegKey1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
    $Value1 = "Identifier" nocase wide ascii
    $RegKey2 = "HARDWARE\\Description\\System" nocase wide ascii
    $Value2 = "SystemBiosVersion" nocase wide ascii
    $Data = "QEMU" wide nocase ascii
condition:
    any of ($RegKey*) and any of ($Value*) and $Data
}

rule Parallels_1
{
strings:
    $ = "system32\\drivers\\prleth.sys" nocase wide ascii
    $ = "system32\\drivers\\prlfs.sys" nocase wide ascii
    $ = "system32\\drivers\\prlmouse.sys" nocase wide ascii
    $ = "system32\\drivers\\prlvideo.sys" nocase wide ascii
    $ = "system32\\drivers\\prl_pv32.sys" nocase wide ascii

    $ = "prl_cc.exe" nocase wide ascii
    $ = "prl_tools.exe" nocase wide ascii

condition:
    any of them
}

rule Parallels_MAC_Address_CouldBeFP
{
strings:

    $ = { 00 1C 42 }
    $ = "00:1C:42"
    $ = "00-1C-42"

condition:
    any of them
}

rule SandboxJoe_1
{
strings:
    $ = "joeboxcontrol.exe" nocase wide ascii
    $ = "joeboxserver.exe" nocase wide ascii
condition:
    any of them
}
