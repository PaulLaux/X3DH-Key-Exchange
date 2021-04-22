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

#include "src/group25519.hpp"
#include "src/misc.hpp"
#include "src/hasopt.hpp"

#include <iostream>
#include <string.h>

using namespace amber;

typedef struct {
    Cu25519Mon ik_p;            // Bob's identity key
    Cu25519Mon spk_p;           // Bob's signed pre-key
    uint8_t    spk_p_sig[64];   // Bob's signature on spk_bp using IK
    Cu25519Mon opk_p;           // Bob's one time pre-key
} PrekeyBundle;

typedef struct {
    Cu25519Mon ik_p;      // Alice’s identity key
    Cu25519Mon ek_p;      // Alice’s ephemeral key

    Cu25519Mon spk_p;     // Bob's signed pre-key
    Cu25519Mon opk_p;     // Bob's one time pre-key

    uint8_t ad_ct[80]; //An initial ciphertext encrypted using SK

} InitialMessage;

class Server {
public:

    // handle keys bundle
    void SetBundle(PrekeyBundle *bundle) {
        this->bundle = bundle;
    }

    PrekeyBundle* GetBundle() {
        if (!this->bundle){
            throw std::logic_error (_("Unable to get bundle"));
        }
        return bundle;
    }

    // handle message delivery
    void SendInitialMessage(InitialMessage *message){
        this->message = message;
    }
    InitialMessage* GetInitialMessage(){
        if (!this->message) {
            throw std::logic_error (_("Unable to get message"));
        }
        return message;
    }

private:
    PrekeyBundle* bundle;
    InitialMessage* message;
};

// Check equality of the given vectors
int c_equal(const unsigned char *mac1, const unsigned char *mac2, size_t n)
{
    size_t i;
    unsigned int dif = 0;
    for (i = 0; i < n; i++)
        dif |= (mac1[i] ^ mac2[i]);
    dif = (dif - 1) >> ((sizeof(unsigned int) * 8) - 1);
    return (dif & 1);
}



void x3dh_key_exchange() {
    std::cout << "\nX3DH start, only public keys will be printed to screen.\n";

    Server server;

    std::cout << "\nBob prepares the prekey bundle:\n";
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
    show_block(std::cout, "bob IK_B public key", IK_Bp.b, 32);

    Cu25519Sec SPK_Bs;
    Cu25519Mon SPK_Bp;
    randombytes_buf(SPK_Bs.b, 32);
    cu25519_generate(&SPK_Bs, &SPK_Bp);
    show_block(std::cout, "bob SPK_B public key", SPK_Bp.b, 32);

    // sign and verify SPK_Bp_sig on SPK_Bp
    uint8_t SPK_Bp_sig[64];
    curvesig("X3DH SPK_Bp_sig", SPK_Bp.b, 32, IK_Bp.b, IK_Bs.b, SPK_Bp_sig);
    show_block(std::cout, "bob SPK_Bp_sig", SPK_Bp_sig, 64);

    Cu25519Sec OPK_Bs;
    Cu25519Mon OPK_Bp;
    randombytes_buf(OPK_Bs.b, 32);
    cu25519_generate(&OPK_Bs, &OPK_Bp);

    show_block(std::cout, "bob OPK_Bp public key", OPK_Bp.b, 32);


    // create bundle message
    PrekeyBundle bobs_bundle;
    bobs_bundle.ik_p = IK_Bp;
    bobs_bundle.spk_p = SPK_Bp;
    memcpy(bobs_bundle.spk_p_sig, SPK_Bp_sig, 64);
    bobs_bundle.opk_p = OPK_Bp;


    // Bob sends the bundle to the server
    server.SetBundle(&bobs_bundle);

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

    std::cout << "\nAlice got Bob's bundle:\n";
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


    // Alice receives Bob's bundle
    PrekeyBundle *b_bundle = server.GetBundle();

    // Alice verifies the prekey SPK_Bp_sig and abort if verification fails
    int errc = curverify("X3DH SPK_Bp_sig", b_bundle->spk_p.b, 32, b_bundle->spk_p_sig, b_bundle->ik_p.b);
    if (errc) {
        format(std::cout, "signature check fails, Alice aborts\n");
        exit(1);
    }
    format(std::cout, "SPK_Bp signature verifies successfully\n");

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
    cu25519_shared_secret(dh1_a, b_bundle->spk_p, IK_As);
    cu25519_shared_secret(dh2_a, b_bundle->ik_p, EK_As);
    cu25519_shared_secret(dh3_a, b_bundle->spk_p, EK_As);
    cu25519_shared_secret(dh4_a, b_bundle->opk_p, EK_As);

    uint8_t dh_concat_a[128];

    memcpy(dh_concat_a, dh1_a, 32);
    memcpy(dh_concat_a + 32, dh2_a, 32);
    memcpy(dh_concat_a + 64, dh3_a, 32);
    memcpy(dh_concat_a + 96, dh4_a, 32);

    uint8_t SK[32];
    const char *domain ="KDF DOMAIN";
    scrypt_blake2b (SK, sizeof SK, domain, 32, dh_concat_a, sizeof dh_concat_a, 10);


    // Alice deletes her ephemeral private key and the DH outputs
    randombytes_buf(EK_As.b, 32);
    randombytes_buf(dh1_a, 32);
    randombytes_buf(dh2_a, 32);
    randombytes_buf(dh3_a, 32);
    randombytes_buf(dh4_a, 32);

    // Alice calculates the associated data AD that contains identity information for both parties
    // AD = IK_A || AK_B
    uint8_t AD[64];
    memcpy(AD, IK_Ap.b, 32);
    memcpy(AD + 32, b_bundle->ik_p.b, 32);
    show_block(std::cout, "*****Bob's identity key, as seen by Alice*****", b_bundle->ik_p.b, 32);

    // An initial ciphertext encrypted with some AEAD encryption scheme using AD as associated data and using an encryption key SK
    const uint ct_size = sizeof AD + 16;
    uint8_t cipher_text[ct_size];
    Chakey key;
    load (&key, SK);
    uint64_t nonce64;
    randombytes_buf(&nonce64, 4);
    encrypt_one (cipher_text, AD, sizeof AD, NULL, 0, key, nonce64);

    /*
     * ** Alice then sends Bob an initial message containing:
     * Alice’s identity key IK_A
     * Alice’s ephemeral key EK_A
     * Identifiers stating which of Bob’s prekeys Alice used
     * An initial ciphertext encrypted with SK
     */
    InitialMessage alices_msg;
    alices_msg.ik_p = IK_Ap;
    alices_msg.ek_p = EK_Ap;
    alices_msg.spk_p = b_bundle->spk_p;
    alices_msg.opk_p = b_bundle->opk_p;
    memcpy(alices_msg.ad_ct, cipher_text, ct_size);

    server.SendInitialMessage(&alices_msg);


    /*
     ** Bob receives the initial message
     * Upon receiving Alice’s initial message, Bob retrieves Alice’s identity key and ephemeral key from the message.
     * Bob also loads his identity private key, and the private key(s) corresponding to whichever signed prekey and one-time prekey (if any) Alice used.
     * Using these keys, Bob repeats the DH and KDF calculations from the previous section to derive SK, and then deletes the DH values.
     * Bob then constructs the AD byte sequence using IKA and IKB, as described in the previous section.
     * Finally, Bob attempts to decrypt the initial cipher_text text using SK and AD.
     * If the initial ciphertext fails to decrypt, then Bob aborts the protocol and deletes SK.
     * If the initial ciphertext decrypts successfully the protocol is complete for Bob.
     * Bob deletes any one-time prekey private key that was used, for forward secrecy.
     */

    /*
     * Bob and Alice should compare fingerprints via an off-band channel
     */

    InitialMessage *a_msg = server.GetInitialMessage();

    std::cout << "\nBob got Alice's initial message:\n";

    show_block(std::cout, "*****Alice's identity key, as seen by Bob*****", a_msg->ik_p.b, 32);

    uint8_t dh1_b[32], dh2_b[32], dh3_b[32], dh4_b[32];
    cu25519_shared_secret(dh1_b, a_msg->ik_p, SPK_Bs);
    cu25519_shared_secret(dh2_b, a_msg->ek_p, IK_Bs);
    cu25519_shared_secret(dh3_b, a_msg->ek_p, SPK_Bs);
    cu25519_shared_secret(dh4_b, a_msg->ek_p, OPK_Bs);

    uint8_t dh_concat_b[128];

    memcpy(dh_concat_b, dh1_b, 32);
    memcpy(dh_concat_b + 32, dh2_b, 32);
    memcpy(dh_concat_b + 64, dh3_b, 32);
    memcpy(dh_concat_b + 96, dh4_b, 32);

    uint8_t SK2[32];
    scrypt_blake2b (SK2, sizeof SK2, domain, 32, dh_concat_b, sizeof dh_concat_b, 10);


    Chakey key2;
    load (&key2, SK2);

    uint8_t ad_dec[64];
    errc = decrypt_one(ad_dec, cipher_text, ct_size, NULL, 0, key2, nonce64);
    if (errc) {
        std::cout << "decryption error, Bob abort";
        exit(1);
    }

    uint8_t ad_b[64];
    memcpy(ad_b, a_msg->ik_p.b, 32);
    memcpy(ad_b + 32, bobs_bundle.ik_p.b, 32);
    show_block(std::cout, "Bob successfully decrypted AD", ad_b, sizeof ad_b);


    if (c_equal(ad_b, ad_dec, 64)){
        std::cout << "\nSuccess! Secret key established\n";
        std::cout << "Parties should compare identity keys via an off-band channel to complete verification!\n";
    } else {
        std::cout << "Failure! mismatched AD message, Bob abort\n";
        exit(1);
    }

}

int main() {
    x3dh_key_exchange();
}

