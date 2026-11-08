# X3DH Key Exchange

A C++ implementation of Signal's [X3DH](https://www.signal.org/docs/specifications/x3dh/x3dh.pdf) (Extended Triple Diffie-Hellman) key agreement protocol, built on the [Amber](https://github.com/bernedogit/amber) crypto library.

> For educational purposes only.

X3DH lets Alice agree on a shared secret with an offline Bob, using keys Bob published to a server. It provides mutual authentication, forward secrecy and deniability.

## Run

```bash
make && ./x3dh
```

Needs `make` and a C++11 compiler. Tested on macOS (Apple clang 21); earlier versions were tested on Ubuntu 20.04 (g++ 9.3).

## How it works

The protocol is in [`x3dh.cpp`](x3dh.cpp); `src/` is Amber.

1. Bob uploads a prekey bundle: identity key `IK_B`, signed prekey `SPK_B` and its signature, one-time prekey `OPK_B`.
2. Alice fetches it, verifies the signature, creates an ephemeral key `EK_A`, and derives `SK` from four DH outputs.
3. Alice sends `IK_A`, `EK_A` and a first message encrypted with `SK`, with `AD = IK_A || IK_B` as associated data.
4. Bob derives the same `SK`, decrypts the message and deletes `OPK_B`.

Finally, both compare identity key fingerprints out of band.

![DH calculations between Alice's and Bob's keys](https://user-images.githubusercontent.com/3682187/115878596-5d53a080-a451-11eb-8729-17e077649357.png)

DH1 and DH2 provide mutual authentication; DH3 and DH4 provide forward secrecy.

## Primitives

| Purpose       | Primitive         |
|---------------|-------------------|
| Key agreement | X25519            |
| Signatures    | qDSA              |
| KDF           | HKDF-SHA512       |
| Encryption    | ChaCha20-Poly1305 |

## Differences from the spec

- **qDSA instead of XEdDSA**: Amber supports it with X25519 keys directly.
- **One one-time prekey**, handed out once; later bundles omit it and derive `SK` from three DH outputs, as the spec allows.
- **Single process**: Alice, Bob and the server run in one program, with hardcoded identity keys.

## License

See [LICENSE.txt](LICENSE.txt).
