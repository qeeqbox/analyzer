/*
__G__ = "(G)bd249ce4"
*/

rule MD2
{
meta:
    description = "MD2"
strings:
    $1 = { 30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 02 05 00 04 10 }
condition:
    $1
}

rule MD5
{
meta:
    description = "MD5"
strings:
    $1 = { 30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10 }
condition:
    $1
}

rule SHA1
{
meta:
    description = "SHA1"
strings:
    $1 = { 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 }
condition:
    $1
}

rule SHA256
{
meta:
    description = "SHA256"
strings:
    $1 = { 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 }
condition:
    $1
}

rule SHA512
{
meta:
    description = "SHA256"
strings:
    $1 = { 30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 }
condition:
    $1
}

rule RC4
{
meta:
    description = "RC4"
strings:
    $1 = { 96 30 07 77 2C 61 0E EE }
condition:
    $1
}

rule AEC
{
meta:
    description = "AEC"
strings:
    $ = { 63 7C 77 7B F2 6B 6F C5 }
    $ = { 52 09 6A D5 30 36 A5 38 }
condition:
    any of them
}
