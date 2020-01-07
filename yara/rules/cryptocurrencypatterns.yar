
/*
__G__ = "(G)bd249ce4"
*/

rule BitcoinAddress_maybe_FP
{
meta:
    description = "btc:Bitcoin Address"
strings:
    $1 = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/
condition:
    $1
}

rule BitcoinCashAddress_maybe_FP
{
meta:
    description = "bch:Bitcoin Cash Address"
strings:
    $1 = /\b((bitcoincash|bchreg|bchtest):)?(q|p)[a-z0-9]{41}\b/
condition:
    $1
}

rule EthereumAddress_maybe_FP
{
meta:
    description = "eth:Ethereum Address"
strings:
    $1 = /\b0x[a-fA-F0-9]{40}\b/
condition:
    $1
}

rule LitecoinAddress_maybe_FP
{
meta:
    description = "ltc:Litecoin Address"
strings:
    $1 = /\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b/
condition:
    $1
}

rule DogecoinAddress_maybe_FP
{
meta:
    description = "doge:Dogecoin Address"
strings:
    $1 = /\bD{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}\b/
condition:
    $1
}

rule DashAddress_maybe_FP
{
meta:
    description = "dash:Dash Address"
strings:
    $1 = /\bX[1-9A-HJ-NP-Za-km-z]{33}\b/
condition:
    $1
}

rule NeoAddress_maybe_FP
{
meta:
    description = "neo:Neo Address"
strings:
    $1 = /\bA[0-9a-zA-Z]{33}\b/
condition:
    $1
}

rule RippleAddress_maybe_FP
{
meta:
    description = "xrp:Ripple Address"
strings:
    $1 = /\br[0-9a-zA-Z]{33}\b/
condition:
    $1
}

rule MoneroAddress_maybe_FP
{
meta:
    description = "xmr:Monero Address"
strings:
    $1 = /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/
condition:
    $1
}
