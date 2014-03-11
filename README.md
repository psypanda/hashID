hashID
======

Identify the different types of hashes used to encrypt data and especially passwords.

This tool replaces [hash-identifier](http://code.google.com/p/hash-identifier/), which is outdated!

hashID supports the identification of over 155 unique hash types using regular expressions.           
It is able to identify a single hash or parse a file and identify the hashes within it.    
There is also a php version of hashID available which is easily set up to provide online hash identification.    


Usage
------
```
$ python hashid.py (-i HASH | -f FILE) [-o OUTFILE] [--help] [--version]
```


Screenshot
------
```
$ python hashid.py -i 827ccb0eea8a706c4c34a16891f84e7b
Analysing '827ccb0eea8a706c4c34a16891f84e7b'
[+] MD5
[+] MD4
[+] MD2
[+] NTLM
[+] LM
[+] RAdmin v2.x
[+] RIPEMD-128
[+] Haval-128
[+] Tiger-128
[+] Snefru-128
[+] MD5(ZipMonster)
[+] Skein-256(128)
[+] Skein-512(128)

$ python hashid.py -f hashes.txt
Analysing 'home/psypanda/hashes.txt'
Hashes analysed: 259
Hashes found: 231
Output written: '/home/psypanda/hashid_output.txt'
```

Contribute
------
Contributing to this project can be done in various ways:
* Supply new regular expressions (please take a look at hashinfo.xlsx first)
* Change existing regular expression (please provide a resource why the current regex might be wrong)
* Work on the "hashid.xlsx" spreadsheet by providing example hashes or reading resources
* Fix anything noted in the "Known issues" section

Known issues
------
* The alignment of the help menu is messed up (--help)
* NetNTLMv1-VANILLA / NetNTLMv1+ESS and NetNTLMv2 regex not working in php version

Credits
------
* Thanks to [sigkill](https://github.com/sigkill-rcode) who helped me numerous times fixing and optimizing the code

Resources
------
* http://pythonhosted.org/passlib/index.html
* http://wiki.insidepro.com/index.php/Algorithms
* http://openwall.info/wiki/john
* http://hashcat.net/wiki/doku.php?id=example_hashes