# crypto - Cryptography library for Racket

## Installation
Later available !!!!
The `ncrypto` package is available through Racket's package manager (https://pkgs.racket-lang.org/).
- Install via command line with `raco pkg install ncrypto`
- Or install via DrRacket (`File` > `Package Manager`).

## Documentation
Later available!!!!
Read the documentation online here: 
- crypto: https://docs.racket-lang.org/ncrypto/index.html

The idea is to have a package which can handle the same things as Crypto, sha,x509 including Cms pdf
And XML signing with all algorithms Seen as secure by NIST(USA) and ETSI(European union). 

This package should also be able to request OCSP and CRL and to handle the complete public/private key stuff. And there is a next thing: The functions which we implement schools be called by a context object which uses the algorithm id as input and selects the correct signing hashing or enc/ decr functions ( only a idea to make it easier for programming). 

Harald Glab-Plhak
