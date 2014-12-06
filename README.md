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


How it works
============

Uniquebits publishes hashes of data, signed by PGP signatures, on the Bitcoin
blockchain encoded into transactions. Each hash is associated with a specific
topic. By scanning the blockchain the complete set of all published hashes from
a given pubkey for a given topic can be obtained. Third-parties relying on that
data can then check their copy against the published hashes. Missing records
are immediately apparent, possibly indicating fraud. (e.g. a bank attempting to
keep two sets of books)

Note that the PGP signatures are essential! Simply publishing the hashes
themselves is not sufficient - that's timestamping rather than
proof-of-publication, and only proves that data existed prior to some time;
timestamping says nothing about whether or not *conflicting* versions of the
data exist. Unfortunately there is a tremendous amount of misinformation out
there regarding this point. Secondly it is not possible to trustlessly
outsource this publication, for example with Factom's merkle tree scheme. If
you're protocol involves a third-party in the publication that third-party can
put you in a position of being unable to prove you did not commit fraud as you
can't control what publications they make on your behalf.


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

* Provide the option of publishing via a merkle binary prefix tree to combine
  multiple publications into one.

* Use Isis's python3-gnupg

* Make into library

* etc. etc.
