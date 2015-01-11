hashID
======

Identify the different types of hashes used to encrypt data and especially passwords.

This tool replaces [hash-identifier](http://code.google.com/p/hash-identifier/ "hash-identifier"), which is outdated!
 
hashID is a tool written in Python 3.x which supports the identification of over 205 unique hash types using regular expressions.
A detailed list of supported hashes can be found [here](doc/hashinfo.xlsx).    
It is able to identify a single hash, parse a file or read multiple files in a directory and identify the hashes within them.    
hashID is also capable of including the corresponding [hashcat](https://hashcat.net/oclhashcat/ "hashcat") mode and/or [JohnTheRipper](http://www.openwall.com/john/) format in its output.    
Altough hashID is written in Python 3.x it should also work using Python 2.7. 

*Note: When identifying a hash on *nix operating systems use single quotes to prevent interpolation*

Install
------
```console
$ sudo apt-get install python3 git
$ git clone https://github.com/psypanda/hashid.git
$ cd hashid
$ sudo install -g 0 -o 0 -m 0644 man/hashid.7 /usr/share/man/man7/
$ sudo gzip /usr/share/man/man7/hashid.7
```

Usage
------
```console
$ ./hashid.py [-a] [-m] [-j] [--help] [--version] INPUT
```

| Parameter                      | Description                                         |
| :----------------------------- | :-------------------------------------------------- |
| input                          | string or filename to analyze                       |
| -a, --all                      | list all hash algorithms including salted passwords |
| -m, --mode                     | include corresponding hashcat mode in output        |
| -j, --john                     | include corresponding JohnTheRipper format in output|
| --help                         | show this help message and exit                     |
| --version                      | show program's version number and exit              |


Screenshot
------
```console
$ ./hashid.py $P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1
Analyzing '$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1'
[+] Wordpress ≥ v2.6.2
[+] Joomla ≥ v2.5.18
[+] PHPass' Portable Hash

$ ./hashid.py -m ecf076ce9d6ed3624a9332112b1cd67b236fdd11:17782686
Analyzing 'ecf076ce9d6ed3624a9332112b1cd67b236fdd11:17782686'
[+] Redmine Project Management Web App [Hashcat Mode: 7600]
[+] SMF ≥ v1.1 [Hashcat Mode: 121]

$ ./hashid.py hashes.txt
--File 'hashes.txt'--
Analyzing '*85ADE5DDF71E348162894C71D73324C043838751'
[+] MySQL5.x
[+] MySQL4.1
Analyzing '$2a$08$VPzNKPAY60FsAbnq.c.h5.XTCZtC1z.j3hnlDFGImN9FcpfR1QnLq'
[+] Blowfish(OpenBSD)
[+] Woltlab Burning Board 4.x
[+] BCrypt
--End of file 'hashes.txt'--

$ ./hashid.py folder/*.txt
--File 'hashes.txt'--
Analyzing '*85ADE5DDF71E348162894C71D73324C043838751'
[+] MySQL5.x
[+] MySQL4.1
Analyzing '$2a$08$VPzNKPAY60FsAbnq.c.h5.XTCZtC1z.j3hnlDFGImN9FcpfR1QnLq'
[+] Blowfish(OpenBSD)
[+] Woltlab Burning Board 4.x
[+] BCrypt
--End of file 'hashes.txt'--
--File 'hashes.txt'--
Analyzing '{smd5}01234567$yOImZPvBC8dg1HjGYfH7j.'
[+] AIX(smd5)
Analyzing 'crypt1:fnd+8xl+U1E=:Wc30H8MPgAc='
[+] Clavister Secure Gateway
--End of file 'hashes.txt'--
```

Contribute
------
Contributing to this project can be done in various ways:
* Add currently unsupported hashes
* Change/Fix/Enhance existing regular expressions
* Provide reading resources on specific hash types in [hashinfo.xlsx](doc/hashinfo.xlsx)

Credits
------
* Thanks to [sigkill](https://github.com/sigkill-rcode) who helped numerous times fixing and optimizing the code
* Thanks to [kmulvey](https://github.com/kmulvey) for supplying a [nodejs](https://github.com/psypanda/hashID/tree/js) version of hashID
* Thanks to [bburky](https://github.com/bburky) for extending hashIDs functionality and numerous ideas to improve it

Resources
------
* http://pythonhosted.org/passlib/index.html
* http://openwall.info/wiki/john
* http://openwall.info/wiki/john/sample-hashes
* http://hashcat.net/wiki/doku.php?id=example_hashes
