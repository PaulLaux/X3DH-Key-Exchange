# The X3DH key agreement protocol

_For educational purpuses only._

Spec: https://www.signal.org/docs/specifications/x3dh/x3dh.pdf

Created using bernedogit/Amber (https://github.com/bernedogit/amber).

An implementation of the “X3DH” (or “Extended Triple Diffie-Hellman”) key agreement protocol.

X3DH establishes a shared secret key among two parties who mutually validate each other based on public keys.

X3DH provides cryptographic deniability and forward secrecy. The protocol is intended for asynchronous contexts where one user (“Bob”) is offline but has published some information to an untrusted server. Another user (“Alice”) wants to use that data to send encrypted data to Bob and establish a shared secret key for future communication.

The source for the protocol can be found in `x3dh.cpp`.

Notable changes from the spec:
 - `scrypt_blake2b` is used as the key derivation function.
 - `qDSA` is used for signatures instead of `XEdDSA`.

Both changes are for better compatibility with the cryptographic library (Amber).

## The protocol

The following diagram shows the DH calculations between keys. Note that DH1 and DH2 provide mutual authentication, while DH3 and DH4 provide forward secrecy.

For more information: https://www.signal.org/docs/specifications/x3dh/x3dh.pdf

## Usage

```bash
make && ./x3dh
```

## Tested on

Ubuntu Linux 20.04

GNU Make 4.2.1

g++ 9.3.0