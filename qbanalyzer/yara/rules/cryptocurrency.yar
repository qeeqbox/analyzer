/*
__G__ = "(G)bd249ce4"
*/

rule BitCoin
{
strings:
    $ = "Bitcoin" nocase wide ascii
    $ = "Litecoin" nocase wide ascii
    $ = "Namecoin" nocase wide ascii
    $ = "Terracoin" nocase wide ascii
    $ = "PPcoin" nocase wide ascii
    $ = "Primecoin" nocase wide ascii
    $ = "Feathercoin" nocase wide ascii
    $ = "Novacoin" nocase wide ascii
    $ = "Freicoin" nocase wide ascii
    $ = "Devoin" nocase wide ascii
    $ = "Franko" nocase wide ascii
    $ = "Megacoin" nocase wide ascii
    $ = "Quarkcoin" nocase wide ascii
    $ = "Worldcoin" nocase wide ascii
    $ = "Infinitecoin" nocase wide ascii
    $ = "Ixcoin" nocase wide ascii
    $ = "Anoncoin" nocase wide ascii
    $ = "BBQcoin" nocase wide ascii
    $ = "Digitalcoin" nocase wide ascii
    $ = "Mincoin" nocase wide ascii
    $ = "Goldcoin" nocase wide ascii
    $ = "Yacoin" nocase wide ascii
    $ = "Zetacoin" nocase wide ascii
    $ = "Fastcoin" nocase wide ascii
    $ = "I0coin" nocase wide ascii
    $ = "Tagcoin" nocase wide ascii
    $ = "Bytecoin" nocase wide ascii
    $ = "Florincoin" nocase wide ascii
    $ = "Phoenixcoin" nocase wide ascii
    $ = "Luckycoin" nocase wide ascii
    $ = "Craftcoin" nocase wide ascii
    $ = "Junkcoin" nocase wide ascii
condition:
    	any of them
}
