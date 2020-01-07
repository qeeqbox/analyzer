/*
__G__ = "(G)bd249ce4"
*/

rule AntiAnalysisGenericBin
{
strings:
    $vpx = {0F 3F 07 0B}
    $vmware = {56 4D 58 68}
    $vmcheckdll = {45 C7 00 01}
    $redpill = {0F 01 0D 00 00 00 00 C3}
condition:
    any of them
}

rule AntiAnalysisGeneric
{
strings:
    $ = "ProcessHacker.exe" wide nocase ascii
    $ = "processmonitor.exe" wide nocase ascii
    $ = "tcpview.exe" wide nocase ascii
    $ = "autoruns.exe" wide nocase ascii
    $ = "autorunsc.exe" wide nocase ascii
    $ = "filemon.exe" wide nocase ascii
    $ = "procmon.exe" wide nocase ascii
    $ = "regmon.exe" wide nocase ascii
    $ = "procexp.exe" wide nocase ascii
    $ = "hiew32.exe" wide nocase ascii
    $ = "ollydbg.exe" wide nocase ascii
    $ = "idaq.exe" wide nocase ascii
    $ = "idaq64.exe" wide nocase ascii
    $ = "ImmunityDebugger.exe" wide nocase ascii
    $ = "dumpcap.exe" wide nocase ascii
    $ = "HookExplorer.exe" wide nocase ascii
    $ = "ImportREC.exe" wide nocase ascii
    $ = "PETools.exe" wide nocase ascii
    $ = "LordPE.exe" wide nocase ascii
    $ = "SysInspector.exe" wide nocase ascii
    $ = "proc_analyzer.exe" wide nocase ascii
    $ = "sysAnalyzer.exe" wide nocase ascii
    $ = "sniff_hit.exe" wide nocase ascii
    $ = "ILSpy.exe" wide nocase ascii
    $ = "dnSpy.exe" wide nocase ascii
    $ = "windbg.exe" wide nocase ascii
    $ = "winhex.exe" wide nocase ascii
    $ = "fiddler.exe" wide nocase ascii
    $ = "Wireshark.exe"wide nocase ascii
    $ = "\\\\.\\NTICE" wide nocase ascii
    $ = "\\\\.\\SICE" wide nocase ascii
    $ = "\\\\.\\Syser" wide nocase ascii
    $ = "\\\\.\\SyserBoot" wide nocase ascii
    $ = "\\\\.\\SyserDbgMsg" wide nocase ascii
condition:
    any of them
}
