/*
 * Copyright (c) 2015-2018, Pelayo Bernedo
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "group25519.hpp"
#include "misc.hpp"
#include "hasopt.hpp"
#include "keys.hpp"
#include <iostream>
#include <string.h>
#include <fstream>
#include <iomanip>
#include <assert.h>

using namespace amber;

// Vectors from https://tools.ietf.org/html/draft-irtf-cfrg-curves-05
void test_x25519() {
    std::cout << "Testing X25519 vectors.\n";
    // Alice's private key, f:
    const char asec[] = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    // Alice's public key, X25519(f, 9):
    const char apub[] = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

    // Bob's private key, g:
    const char bsec[] = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    // Bob's public key, X25519(g, 9):
    const char bpub[] = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

    // Their shared secret, K:
    const char shared[] = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    Cu25519Sec as, bs;
    Cu25519Mon ap, bp, rap, rbp;
    std::vector<uint8_t> tmp;
    const char *last;

    read_block(asec, &last, tmp);
    if (*last || tmp.size() != 32) {
        std::cout << "error reading key\n";
        return;
    }
    memcpy(as.b, &tmp[0], 32);

    read_block(bsec, &last, tmp);
    if (*last || tmp.size() != 32) {
        std::cout << "error reading key\n";
        return;
    }
    memcpy(bs.b, &tmp[0], 32);

    read_block(apub, &last, tmp);
    if (*last || tmp.size() != 32) {
        std::cout << "error reading key\n";
        return;
    }
    memcpy(rap.b, &tmp[0], 32);

    read_block(bpub, &last, tmp);
    if (*last || tmp.size() != 32) {
        std::cout << "error reading key\n";
        return;
    }
    memcpy(rbp.b, &tmp[0], 32);

    read_block(shared, &last, tmp);
    if (*last || tmp.size() != 32) {
        std::cout << "error reading key\n";
        return;
    }

    cu25519_generate(&as, &ap);
//	ap.b[31] &= 0x7F;
//	if (crypto_neq (ap.b, rap.b, 32)) {
//		std::cout << "Error in generating the public key 1\n";
//		show_block (std::cout, "scalar  ", as.b, 32);
//		show_block (std::cout, "computed", ap.b, 32);
//		show_block (std::cout, "expected", rap.b, 32);
//		return;
//	}
    cu25519_generate(&bs, &bp);
//	bp.b[31] &= 0x7F;
//	if (crypto_neq (bp.b, rbp.b, 32)) {
//		std::cout << "Error in generating the public key 2\n";
//		show_block (std::cout, "scalar  ", bs.b, 32);
//		show_block (std::cout, "computed", bp.b, 32);
//		show_block (std::cout, "expected", rbp.b, 32);
//		return;
//	}
    uint8_t sh[32];
    cu25519_shared_secret(sh, ap, bs);
    if (crypto_neq(sh, &tmp[0], 32)) {
        std::cout << "error in shared key\n";
        show_block(std::cout, "computed", sh, 32);
        show_block(std::cout, "expected", &tmp[0], 32);
        return;
    }
    cu25519_shared_secret(sh, bp, as);
    if (crypto_neq(sh, &tmp[0], 32)) {
        std::cout << "error in shared key\n";
        show_block(std::cout, "computed", sh, 32);
        show_block(std::cout, "expected", &tmp[0], 32);
        return;
    }
    std::cout << "X25519 vectors tested.\n";
}


void test_curvesig() {
    Cu25519Sec xs;
    Cu25519Mon xp;
    randombytes_buf(xs.b, 32);
    cu25519_generate(&xs, &xp);

    uint8_t sig[64];
    curvesig("Amber sig", xs.b, 32, xp.b, xs.b, sig);
    int errc = curverify("Amber sig", xs.b, 32, sig, xp.b);
    format(std::cout, "curverify returns %d\n", errc);
    errc = curverify_mont("Amber sig", xs.b, 32, sig, xp.b);
    format(std::cout, "curverify_mont returns %d\n", errc);

    uint8_t nsig[64];
    memcpy(nsig, sig, 32);
    negate_scalar(nsig + 32, sig + 32);
    errc = curverify_mont("Amber sig", xs.b, 32, nsig, xp.b);
    format(std::cout, "curverify_mont with nsig returns %d\n", errc);
    errc = curverify("Amber sig", xs.b, 32, sig, xp.b);
    format(std::cout, "curverify returns %d\n", errc);
}

void blake_test(const char *p1, size_t n1, const char *p2, size_t n2, const char *p3, size_t n3) {
    blake2b_ctx ctx;
    blake2b_init(&ctx, 64);
    blake2b_update(&ctx, p1, n1);
    blake2b_update(&ctx, p2, n2);
    blake2b_update(&ctx, p3, n3);
    char h1[64];
    blake2b_final(&ctx, h1);
    show_block(std::cout, "hash    ", h1, 64);


    const char s1[] = "foo";
    blake2b(h1, 64, s1, 0, s1, sizeof s1);
    show_block(std::cout, "hash    ", h1, 64);
}

typedef struct {
    Cu25519Mon ik_p;            // bob's identity key
    Cu25519Mon spk_p;           // bob's signed pre-key
    uint8_t    spk_p_sig[64];   // bob's signature on spk_bp using IK
    Cu25519Mon opk_p;           // bob's one time pre-key
} prekey_bundle;


void x3dh() {
    std::cout << "\nX3DH start\n";
    /*
     ** Bob publish keys:
     * Bob’s identity key IK_B
     * Bob’s signed prekey SPK_B
     * Bob’s prekey signature Sig(IK_B, Encode(SPK_B))
     * A set of Bob’s one-time prekeys (OPK_B1,OPK_B2,OPK_B3, . . . )
     */

    // Bob's identity key secret IK_B:
    const char ikb_sec[] = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";

    Cu25519Sec IK_Bs;
    Cu25519Mon IK_Bp;

    // load key into IK_Bs
    std::vector<uint8_t> tmp;
    const char *last;
    read_block(ikb_sec, &last, tmp);
    if (*last || tmp.size() != 32) {
        std::cout << "error reading key\n";
        return;
    }
    memcpy(IK_Bs.b, &tmp[0], 32);

    cu25519_generate(&IK_Bs, &IK_Bp);

    // Human readable encoding of the public key.
    //    std::string enc;
    //    encode_key(IK_Bp.b, 32, enc, true);
    //    format(std::cout, _("bob IK_B public key:    %s\n"), enc);
    show_block(std::cout, "bob IK_B public key", IK_Bp.b, 32);

    Cu25519Sec SPK_Bs;
    Cu25519Mon SPK_Bp;
    randombytes_buf(SPK_Bs.b, 32);
    cu25519_generate(&SPK_Bs, &SPK_Bp);
    show_block(std::cout, "bob SPK_B public key", SPK_Bp.b, 32);

    // sign and verify SPK_Bp_sig on SPK_Bp
    uint8_t SPK_Bp_sig[64];
    curvesig("X3DH SPK_Bp_sig", SPK_Bp.b, 32, IK_Bp.b, IK_Bs.b, SPK_Bp_sig);
    int errc = curverify("X3DH SPK_Bp_sig", SPK_Bp.b, 32, SPK_Bp_sig, IK_Bp.b);
    format(std::cout, "curverify returns %d\n", errc);
    show_block(std::cout, "bob SPK_Bp_sig public key", SPK_Bp_sig, 64);

    Cu25519Sec OPK_Bs;
    Cu25519Mon OPK_Bp;
    randombytes_buf(OPK_Bs.b, 32);
    cu25519_generate(&OPK_Bs, &OPK_Bp);

    show_block(std::cout, "bob OPK_Bp public key", OPK_Bp.b, 32);


    format(std::cout, "bundle keys: \n");
    prekey_bundle bobs_bundle;
    bobs_bundle.ik_p = IK_Bp;
    bobs_bundle.spk_p = SPK_Bp;
    memcpy(bobs_bundle.spk_p_sig, SPK_Bp_sig, 64);
    bobs_bundle.opk_p = OPK_Bp;

    show_block(std::cout, "bob ik_p public key", bobs_bundle.ik_p.b, 32);
    show_block(std::cout, "bob spk_p public key", bobs_bundle.spk_p.b, 32);
    show_block(std::cout, "bob spk_p SPK_Bp_sig public key", bobs_bundle.spk_p_sig, 64);
    show_block(std::cout, "bob opk_p public key", bobs_bundle.opk_p.b, 32);


    /*
     ** Alice verifies the prekey SPK_Bp_sig and abort if verification fails
     *  Alice then generates an ephemeral key pair with public key EK_A.
     *
     ** Alice calculates the shared key
     *  DH1 = DH(IK_A, SPK_B)
     *  DH2 = DH(EK_A, IK_B)
     *  DH3 = DH(EK_A, SPK_B)
     *  DH4 = DH(EK_A, OPK_B)
     *  SK = KDF(DH1 || DH2 || DH3 || DH4)
     *
     *
     ** Alice deletes her ephemeral private key and the DH outputs
     *
     ** Alice calculates the associated data AD that contains identity information for both parties
     *  AD = Encode(IK_A) || Encode(IK_B)
     *
     ** Alice then sends Bob an initial message containing:
     * Alice’s identity key IK_A
     * Alice’s ephemeral key EK_A
     * Identifiers stating which of Bob’s prekeys Alice used
     * An initial ciphertext encrypted with some AEAD encryption scheme using AD as associated data and using an encryption key SK
     *
     */
    // Bob's identity key secret IK_B:
    std::cout << "\nAlice start\n";
    const char ika_sec[] = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";

    Cu25519Sec IK_As;
    Cu25519Mon IK_Ap;

    // load key into IK_As
    read_block(ika_sec, &last, tmp);
    if (*last || tmp.size() != 32) {
        std::cout << "error reading key\n";
        return;
    }
    memcpy(IK_As.b, &tmp[0], 32);
    cu25519_generate(&IK_As, &IK_Ap);
    show_block(std::cout, "alice IK_A public key", IK_Ap.b, 32);

    // Alice verifies the prekey SPK_Bp_sig and abort if verification fails
    errc = curverify("X3DH SPK_Bp_sig", bobs_bundle.spk_p.b, 32, bobs_bundle.spk_p_sig, bobs_bundle.ik_p.b);
    if (errc) {
        format(std::cout, "signature check fails, Alice aborts\n");
        exit(1);
    }
    format(std::cout, "signature check successful\n");

    // Alice then generates an ephemeral key pair with public key EK_A.
    Cu25519Sec EK_As;
    Cu25519Mon EK_Ap;
    randombytes_buf(EK_As.b, 32);
    cu25519_generate(&EK_As, &EK_Ap);
    show_block(std::cout, "Alice ephemeral key EK_A public", EK_Ap.b, 32);


    /*
     * ** Alice calculates the shared key
     *  DH1 = DH(IK_A, SPK_B)
     *  DH2 = DH(EK_A, IK_B)
     *  DH3 = DH(EK_A, SPK_B)
     *  DH4 = DH(EK_A, OPK_B)
     *  SK = KDF(DH1 || DH2 || DH3 || DH4)
     */
    uint8_t dh1_a[32], dh2_a[32], dh3_a[32], dh4_a[32];
    cu25519_shared_secret(dh1_a, bobs_bundle.spk_p, IK_As);
    cu25519_shared_secret(dh2_a, bobs_bundle.ik_p, EK_As);
    cu25519_shared_secret(dh3_a, bobs_bundle.spk_p, EK_As);
    cu25519_shared_secret(dh4_a, bobs_bundle.opk_p, EK_As);

    uint8_t dh_concat_a[128];

    memcpy(dh_concat_a, dh1_a, 32);
    memcpy(dh_concat_a + 32, dh2_a, 32);
    memcpy(dh_concat_a + 64, dh3_a, 32);
    memcpy(dh_concat_a + 96, dh4_a, 32);

    uint8_t SK[32];
    const char *domain ="KDF DOMAIN";
    scrypt_blake2b (SK, sizeof SK, domain, 32, dh_concat_a, 128, 10);
    show_block(std::cout, "SK alice", SK, 32);


    // Alice deletes her ephemeral private key and the DH outputs
    randombytes_buf(EK_As.b, 32);
    randombytes_buf(dh1_a, 32);
    randombytes_buf(dh2_a, 32);
    randombytes_buf(dh3_a, 32);
    randombytes_buf(dh4_a, 32);

    // Alice calculates the associated data AD that contains identity information for both parties
    /*
     ** Bob receives the initial message
     * Upon receiving Alice’s initial message, Bob retrieves Alice’s identity key and ephemeral key from the message.
     * Bob also loads his identity private key, and the private key(s) corresponding to whichever signed prekey and one-time prekey (if any) Alice used.
     * Using these keys, Bob repeats the DH and KDF calculations from the previous section to derive SK, and then deletes the DH values.
     * Bob then constructs the AD byte sequence using IKA and IKB, as described in the previous section.
     * Finally, Bob attempts to decrypt the initial cipher text using SK and AD.
     * If the initial ciphertext fails to decrypt, then Bob aborts the protocol and deletes SK.
     * If the initial ciphertext decrypts successfully the protocol is complete for Bob.
     * Bob deletes any one-time prekey private key that was used, for forward secrecy.
     */

    /*
     * Bob and Alice should compare fingerprints via an off-band channel
     */

    uint8_t dh1_b[32], dh2_b[32], dh3_b[32], dh4_b[32];
    cu25519_shared_secret(dh1_b, IK_Ap, SPK_Bs);
    cu25519_shared_secret(dh2_b, EK_Ap, IK_Bs);
    cu25519_shared_secret(dh3_b, EK_Ap, SPK_Bs);
    cu25519_shared_secret(dh4_b, EK_Ap, OPK_Bs);

    uint8_t dh_concat_b[128];

    memcpy(dh_concat_b, dh1_b, 32);
    memcpy(dh_concat_b + 32, dh2_b, 32);
    memcpy(dh_concat_b + 64, dh3_b, 32);
    memcpy(dh_concat_b + 96, dh4_b, 32);

    uint8_t SK2[32];
    scrypt_blake2b (SK2, sizeof SK2, domain, 32, dh_concat_b, 128, 10);
    show_block(std::cout, "SK bob", SK2, 32);

//    show_block(std::cout, "dh1_a", dh1_a, 32);
//    show_block(std::cout, "dh1_b", dh1_b, 32);
//
//    show_block(std::cout, "dh2_a", dh2_a, 32);
//    show_block(std::cout, "dh2_b", dh2_b, 32);
//
//    show_block(std::cout, "dh3_a", dh3_a, 32);
//    show_block(std::cout, "dh3_b", dh3_b, 32);
//
//    show_block(std::cout, "dh4_a", dh4_a, 32);
//    show_block(std::cout, "dh4_b", dh4_b, 32);


}

int main() {
    test_curvesig();
    test_x25519();

    const char s1[] = "foo";
    const char s2[] = "bar";
    const char s3[] = "foobar";
    blake_test(s1, sizeof s1, s2, sizeof s2, s3, sizeof s3);

    x3dh();
}

