
/*
__G__ = "(G)bd249ce4"
*/

rule BitcoinAddress_maybe_FP
{
meta:
    description = "btc:Bitcoin Address"
strings:
    $1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
condition:
    $1
}

rule BitcoinCashAddress_maybe_FP
{
meta:
    description = "bch:Bitcoin Cash Address"
strings:
    $1 = /((bitcoincash|bchreg|bchtest):)?(q|p)[a-z0-9]{41}/
condition:
    $1
}

rule EthereumAddress_maybe_FP
{
meta:
    description = "eth:Ethereum Address"
strings:
    $1 = /0x[a-fA-F0-9]{40}/
condition:
    $1
}

rule LitecoinAddress_maybe_FP
{
meta:
    description = "ltc:Litecoin Address"
strings:
    $1 = /[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}/
condition:
    $1
}

rule DogecoinAddress_maybe_FP
{
meta:
    description = "doge:Dogecoin Address"
strings:
    $1 = /D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}/
condition:
    $1
}

rule DashAddress_maybe_FP
{
meta:
    description = "dash:Dash Address"
strings:
    $1 = /X[1-9A-HJ-NP-Za-km-z]{33}/
condition:
    $1
}

rule NeoAddress_maybe_FP
{
meta:
    description = "neo:Neo Address"
strings:
    $1 = /A[0-9a-zA-Z]{33}/
condition:
    $1
}

rule RippleAddress_maybe_FP
{
meta:
    description = "xrp:Ripple Address"
strings:
    $1 = /r[0-9a-zA-Z]{33}/
condition:
    $1
}

rule MoneroAddress_maybe_FP
{
meta:
    description = "xmr:Monero Address"
strings:
    $1 = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/
condition:
    $1
}
