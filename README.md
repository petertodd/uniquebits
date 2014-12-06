Uniquebits
==========

Proof-of-concept developed at the Barclay's Distributed Banking Hackathon to
ensure the uniqueness of data published under a topic using
proof-of-publication and the Bitcoin blockchain. For instance, a bank could use
this technology to allow third-parties to be confident that accounting records
they were relying on were accurate and no conflicting versions of those records
existed. Or Tor could use this tool to allow Tor users to be sure the version
of Tor they were using was the same version everyone else was using and they
weren't being personally targetted with malware. Or this principle can also be
used as the basis for a certificate transparency scheme.


Usage
=====

./unibits --regtest publish 37EC7D7B0A217CDB4B4E007E7FAB114267E4FA04 hi deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbefe

./unibits -v --regtest scan --height 1 37EC7D7B0A217CDB4B4E007E7FAB114267E4FA04


WARNING: don't use this on mainnet/testnet! python-gnupg may have a remotely
exploitable bug in it; need to switch to using Isis's fork:

https://github.com/isislovecruft/python-gnupg


Requirements
============

python3-gnupg
python-bitcoinlib v0.2.1


TODO
====

* Use blockpop for anti-censorship

* Use committed encryption keys for anti-censorship. Basically publication p_i
  should commit to encryption key k_i+1, which is used to encrypt publication
  p_i+1 As miners don't know that key, they can't censor the next publication,
  however revealing that key still allows anyone to securely verify the next
  publication.

* Use Isis's python3-gnupg

* Make into library

* etc. etc.
