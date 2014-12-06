# Copyright (C) 2014 Peter Todd <pete@petertodd.org>
#
# This file is part of uniquebits.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of uniquebits, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

UNIBITS_VERSION = '0.1.0'

import argparse
import logging
import os

import bitcoin.rpc

from bitcoin.core import *
from bitcoin.core.script import *
from bitcoin.core.scripteval import *
from bitcoin.core.serialize import *
from bitcoin.wallet import *

class Record(bitcoin.core.serialize.ImmutableSerializable):
    __slots__ = ['title', 'hash']

    def __init__(self, title, hash):
        object.__setattr__(self, 'title', title)
        object.__setattr__(self, 'hash', hash)

    @classmethod
    def stream_deserialize(cls, f):
        title = BytesSerializer.stream_deserialize(f)
        hash = ser_read(f,32)
        return cls(hash, title)

    def stream_serialize(self, f):
        BytesSerializer.stream_serialize(self.title, f)
        assert len(self.hash) == 32
        f.write(self.hash)

class SignedRecord(bitcoin.core.serialize.ImmutableSerializable):
    __slots__ = ['record', 'sig']

    def __init__(self, record, sig):
        object.__setattr__(self, 'record', record)
        object.__setattr__(self, 'sig', sig)

    @classmethod
    def stream_deserialize(cls, f):
        record = Record.stream_deserialize(f)
        sig = BytesSerializer.stream_deserialize(f)
        return cls(record, sig)

    def stream_serialize(self, f):
        Record.stream_serialize(self.record, f)
        BytesSerializer.stream_serialize(self.sig, f)

def cmd_publish(args):
    h = Hash(b'correct horse battery staple')
    seckey = CBitcoinSecret.from_secret_bytes(h)

    publisher_fingerprint = x('37EC7D7B0A217CDB4B4E007E7FAB114267E4FA04')
    bait_scriptPubKey = CScript([OP_HASH160, publisher_fingerprint, OP_EQUAL])

    signed_record = SignedRecord(Record(b"diana's thoughts", b'\x00'*32),
                                 b"PGP YO!")

    # signed record is published to the blockchain in a scriptSig; create a
    # redeemScript that can only be satisfied by it
    serialized_signed_record = signed_record.serialize()
    redeemScript = CScript([seckey.pub, OP_CHECKSIGVERIFY,
                            OP_HASH160, Hash160(serialized_signed_record), OP_EQUALVERIFY,
                            OP_DEPTH, 0, OP_EQUAL]) # stop mutability

    # create our output
    addr = P2SHBitcoinAddress.from_scriptPubKey(redeemScript.to_p2sh_scriptPubKey())
    txid = args.proxy.sendtoaddress(addr, 0.001*COIN)

    prevout = None
    tx = args.proxy.getrawtransaction(txid)
    for i, txout in enumerate(tx.vout):
        if txout.scriptPubKey == addr.to_scriptPubKey():
            prevout = COutPoint(tx.GetHash(), i)
            break
    assert prevout is not None

    # spend that output to the bait address
    tx = CTransaction([CTxIn(prevout)],
                      [CTxOut(0.00001*COIN, bait_scriptPubKey)])

    sighash = SignatureHash(redeemScript, tx, 0, SIGHASH_ALL)
    sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])
    scriptSig = CScript([serialized_signed_record, sig, redeemScript])

    signed_tx = CTransaction([CTxIn(prevout, scriptSig)],
                             [CTxOut(0.00001*COIN, bait_scriptPubKey)])

    VerifyScript(signed_tx.vin[0].scriptSig, redeemScript.to_p2sh_scriptPubKey(),
                 tx, 0, (SCRIPT_VERIFY_P2SH,))

    txid = args.proxy.sendrawtransaction(signed_tx)

    print(b2lx(txid))

def make_arg_parser():
    # Global arguments

    parser = argparse.ArgumentParser(description='Uniquebits')

    network_arg_group = parser.add_mutually_exclusive_group()
    network_arg_group.add_argument("-t","--testnet",action='store_true',
                                   help="Use testnet instead of mainnet")
    network_arg_group.add_argument("-r","--regtest",action='store_true',
                                   help="Use regtest instead of mainnet")

    parser.add_argument("-d","--datadir",
                        type=str,
                        default='~/.unibits',
                        dest='datadir',
                        help="Data directory")
    parser.add_argument("--fee-per-kb",type=float,default=0.0001,
                                 help="Fee-per-kb to use")
    parser.add_argument("--dust",type=float,default=0.0001,
                                 help="Dust threshold")
    parser.add_argument("-q","--quiet",action="count",default=0,
                                 help="Be more quiet.")
    parser.add_argument("-v","--verbose",action="count",default=0,
                                 help="Be more verbose. Both -v and -q may be used multiple times.")
    parser.add_argument('--version', action='version', version=UNIBITS_VERSION)

    subparsers = parser.add_subparsers()

    publish_parser = subparsers.add_parser('publish',
                help="Publish to a topic")
    publish_parser.set_defaults(cmd_func=cmd_publish)

    return parser


def main(argv, parser=None):
    if parser is None:
        parser = make_arg_parser()

    args = parser.parse_args()
    args.parser = parser

    # Setup logging

    args.verbosity = args.verbose - args.quiet

    if args.verbosity == 1:
        logging.root.setLevel(logging.INFO)
    elif args.verbosity >= 2:
        logging.root.setLevel(logging.DEBUG)
    elif args.verbosity == 0:
        logging.root.setLevel(logging.WARNING)
    elif args.verbosity <= -1:
        logging.root.setLevel(logging.ERROR)


    # Set Bitcoin network globally

    assert not (args.regtest and args.testnet)
    network = ''
    if args.testnet:
        logging.debug('Using testnet')
        bitcoin.SelectParams('testnet')
        network = 'testnet'

    elif args.regtest:
        logging.debug('Using regtest')
        bitcoin.SelectParams('regtest')
        network = 'regtest'


    args.fee_per_kb = int(args.fee_per_kb * bitcoin.core.COIN)
    logging.debug('Fee-per-kb: %d satoshis/KB' % args.fee_per_kb)

    args.dust = int(args.dust * bitcoin.core.COIN)
    logging.debug('Dust threshold: %d satoshis' % args.dust)

    args.datadir = os.path.expanduser(args.datadir)

    args.proxy = bitcoin.rpc.Proxy()

    if not hasattr(args, 'cmd_func'):
        parser.error('No command specified')

    args.cmd_func(args)
