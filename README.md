#### This repository is mirrored from https://git.marconi.org/marconiprotocol/marconi-stak.git

# Unified Miner for Marconi Protocol

This is a fork of [XMR-Stak](https://github.com/fireice-uk/xmr-stak)
which we've tweaked to work with [Marconi Protocol](https://marconi.org).
This miner supports CPUs as well as AMD and NVIDIA GPUs and can be
used to mine marcos on Marconi's global chain.

## Quick Start
* [HowTo Compile](doc/compile.md)
* [Usage](doc/usage.md)
* [FAQ](doc/FAQ.md)

## Features

- Supports common hardware: x86 CPU, AMD GPU, NVIDIA GPU.
- Supports common operating systems: Linux, Windows, macOS.
- Supports mining marcos on the [Marconi](https://marconi.org) global chain
- Several other useful things like TLS, stats, and monitoring

## Hash Function

This miner runs the standard CryptoNight variant 4 hash function,
sometimes also referred to as CryptoNightR. As you may remember,
this function uses a two megabyte scratch pad per thread. However,
while the hash function hasn't been changed, there's one related thing
which has: the blob of bytes that gets passed as input to the hash
function. We construct this blob slightly differently than, for
example, the way Monero constructs the hash blob. This change was for
compatibility with the block header format of Marconi's global chain,
which is much closer to Ethereum than to Monero. Hash rates are not
affected.

## You Keep All Proceeds

This miner does not donate any fraction of your earnings to anyone.
You keep everything. We only mention this because it's different from
a lot of other open source miners, which, if used with default
settings, will often donate a small percentage of your earnings to a
developer's address. In the case of this miner, you don't need to
change any code or configuration to turn off donation. It's always
off.

Remember though, it's possible that a fee will be charged by whichever
mining pool you point this client miner at. If you point at a
Marconi-hosted mining pool, there will be no fee. But other pools
might set a non-zero fee.
