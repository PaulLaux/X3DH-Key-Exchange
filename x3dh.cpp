#include "src/group25519.hpp"
#include "src/misc.hpp"
#include "src/hasopt.hpp"
#include "src/hkdf.hpp"
#include "src/sha2.hpp"

#include <iostream>
#include <stdexcept>
#include <string.h>

using namespace amber;

typedef struct {
    Cu25519Mon ik_p;            // Bob's identity key
    Cu25519Mon spk_p;           // Bob's signed pre-key
    uint8_t    spk_p_sig[64];   // Bob's signature on spk_bp using IK
    bool       has_opk;         // false once the server has handed out the one-time pre-key
    Cu25519Mon opk_p;           // Bob's one time pre-key
} PrekeyBundle;

typedef struct {
    Cu25519Mon ik_p;      // Alice’s identity key
    Cu25519Mon ek_p;      // Alice’s ephemeral key

    Cu25519Mon spk_p;     // Bob's signed pre-key
    bool       has_opk;   // whether Alice used a one-time pre-key
    Cu25519Mon opk_p;     // Bob's one time pre-key

    uint8_t ad_ct[80]; // An initial ciphertext encrypted using SK
    uint64_t nonce64;  // The nonce for the symmetric encryption
} InitialMessage;

const char *Domain ="X3DH_DOMAIN";
const char *Sig_Domain ="X3DH SPK_BP_SIG";

// parse a 32-byte hex secret key, throw on malformed input
void LoadKey(const char hex[], Cu25519Sec *key) {
    std::vector<uint8_t> tmp;
    const char *last;
    bool ok = read_block(hex, &last, tmp) >= 0 && !*last && tmp.size() == 32;
    if (ok) memcpy(key->b, tmp.data(), 32);
    crypto_bzero(tmp.data(), tmp.size());
    if (!ok) throw std::invalid_argument("error reading key");
}

// SK = HKDF-SHA512(F || DH1 || DH2 || DH3 [|| DH4]), F = 32 0xFF bytes, zero salt, info = Domain
void KDF(uint8_t sk[32], const uint8_t *dh, size_t n) {
    uint8_t F[32], salt[Sha512::hashlen] = {0};
    memset(F, 0xFF, sizeof F);
    Hkdf<Hmac<Sha512>> hkdf(salt, sizeof salt);
    hkdf.update(F, sizeof F);
    hkdf.update(dh, n);
    hkdf.final(sk, 32, Domain, strlen(Domain));
    crypto_bzero(&hkdf, sizeof hkdf);
}

class Server {
private:
    PrekeyBundle bundle;
    bool has_bundle = false;
    InitialMessage* message = nullptr;
public:

    // store keys bundle
    void SetBundle(const PrekeyBundle *b) {
        bundle = *b;
        has_bundle = true;
    }

    // retrieve keys bundle; the one-time pre-key is handed out only once
    PrekeyBundle GetBundle() {
        if (!has_bundle){
            throw std::logic_error (_("Unable to get bundle"));
        }
        PrekeyBundle out = bundle;
        bundle.has_opk = false;
        return out;
    }

    // store initial message
    void SendInitialMessage(InitialMessage *message){
        this->message = message;
    }

    // retrieve initial message
    InitialMessage* GetInitialMessage(){
        if (!this->message) {
            throw std::logic_error (_("Unable to get message"));
        }
        return message;
    }
};

class Bob {
private:
    Cu25519Sec IK_Bs;  // identity key
    Cu25519Sec SPK_Bs; // signed pre-key
    Cu25519Sec OPK_Bs; // one-time key

    uint8_t SK[32];    // The established secret key for future use

public:
    Cu25519Mon IK_Bp;  // identity key (public)
    Cu25519Mon SPK_Bp; // signed pre-key (public)
    Cu25519Mon OPK_Bp; // one-time key (public)

    PrekeyBundle bobs_bundle;

    // init bob using his private key
    explicit Bob(const char ikb_sec[]){
        LoadKey(ikb_sec, &IK_Bs);
        cu25519_generate(&IK_Bs, &IK_Bp);
    }

    // display public key
    void PrintFingerprint(){
        show_block(std::cout, "bob IK_B public key", IK_Bp.b, 32);
    }

    // generate keys bundle to be uploaded to the server (and store relevant data)
    PrekeyBundle* GenerateBundle() {

        // generate prekey SPK_B
        randombytes_buf(SPK_Bs.b, 32);
        cu25519_generate(&SPK_Bs, &SPK_Bp);
        show_block(std::cout, "bob SPK_B public key", SPK_Bp.b, 32);

        // sign and verify SPK_Bp_sig on SPK_Bp
        uint8_t SPK_Bp_sig[64];
        curvesig(Sig_Domain, SPK_Bp.b, 32, IK_Bp.b, IK_Bs.b, SPK_Bp_sig);
        show_block(std::cout, "bob SPK_Bp_sig", SPK_Bp_sig, 64);

        // generate one time key OPK_B
        randombytes_buf(OPK_Bs.b, 32);
        cu25519_generate(&OPK_Bs, &OPK_Bp);

        show_block(std::cout, "bob OPK_Bp public key", OPK_Bp.b, 32);

        // create bundle message
        bobs_bundle.ik_p = IK_Bp;
        bobs_bundle.spk_p = SPK_Bp;
        memcpy(bobs_bundle.spk_p_sig, SPK_Bp_sig, 64);
        bobs_bundle.has_opk = true;
        bobs_bundle.opk_p = OPK_Bp;

        return &bobs_bundle;
    }

    // handle initial message from alice
    void HandleInitialMessage(InitialMessage* message) {

        std::cout << "\nBob got Alice's initial message:\n";

        show_block(std::cout, "*****Alice's identity key, as seen by Bob*****", message->ik_p.b, 32);

        // Alice must have used Bob's current prekeys
        bool opk = message->has_opk;
        if (memcmp(message->spk_p.b, SPK_Bp.b, 32) || (opk && memcmp(message->opk_p.b, OPK_Bp.b, 32))) {
            std::cout << "unknown prekey, Bob aborts\n";
            exit(1);
        }

        // SK = KDF(DH1 || DH2 || DH3 [|| DH4]), then delete the DH outputs
        uint8_t dh[32 * 4];
        cu25519_shared_secret(dh,      message->ik_p, SPK_Bs);
        cu25519_shared_secret(dh + 32, message->ek_p, IK_Bs);
        cu25519_shared_secret(dh + 64, message->ek_p, SPK_Bs);
        if (opk) cu25519_shared_secret(dh + 96, message->ek_p, OPK_Bs);
        KDF(SK, dh, opk ? 128 : 96);
        crypto_bzero(dh, sizeof dh);

        Chakey chakey;
        load (&chakey, SK);
        uint8_t ad_dec[64];
        int errc = decrypt_one(ad_dec, message->ad_ct, 80, NULL, 0, chakey, message->nonce64);
        crypto_bzero(&chakey, sizeof chakey);
        if (errc) {
            std::cout << "decryption error, Bob aborts\n";
            exit(1);
        }

        uint8_t ad[64];
        memcpy(ad, message->ik_p.b, 32);
        memcpy(ad + 32, IK_Bp.b, 32);
        if (!c_equal(ad, ad_dec, 64)) {
            std::cout << "Failure! mismatched AD message, Bob aborts\n";
            exit(1);
        }
        show_block(std::cout, "Bob successfully decrypted AD", ad_dec, sizeof ad_dec);

        // delete the used one-time prekey (public part too, so a replay is rejected)
        if (opk) {
            crypto_bzero(&OPK_Bs, sizeof OPK_Bs);
            crypto_bzero(&OPK_Bp, sizeof OPK_Bp);
        }

        std::cout << "\nSuccess! Secret key established\n";
    }
};

class Alice {
private:
    Cu25519Sec IK_As; // Alice identity key

    uint8_t SK[32];   // The established secret key for future use

public:
    Cu25519Mon IK_Ap; // Alice identity key (public)

    InitialMessage msg;

    // init alice using the private key
    explicit Alice(const char ika_sec[]){
        LoadKey(ika_sec, &IK_As);
        cu25519_generate(&IK_As, &IK_Ap);
    }

    // display public key
    void PrintFingerprint(){
        show_block(std::cout, "\nAlice IK public key", IK_Ap.b, 32);
    }

    // generate the initial message based on the bundle.
    InitialMessage* GenerateInitialMessage(PrekeyBundle* bundle){
        std::cout << "Alice got Bob's bundle:\n";

        // Alice verifies the prekey SPK_Bp_sig and abort if verification fails
        int errc = curverify(Sig_Domain, bundle->spk_p.b, 32, bundle->spk_p_sig, bundle->ik_p.b);
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
         *  DH4 = DH(EK_A, OPK_B)   (only if the bundle has a one-time pre-key)
         */
        bool opk = bundle->has_opk;
        uint8_t dh[32 * 4];
        cu25519_shared_secret(dh,      bundle->spk_p, IK_As);
        cu25519_shared_secret(dh + 32, bundle->ik_p,  EK_As);
        cu25519_shared_secret(dh + 64, bundle->spk_p, EK_As);
        if (opk) cu25519_shared_secret(dh + 96, bundle->opk_p, EK_As);

        // SK = KDF(DH1 || DH2 || DH3 [|| DH4])
        KDF(SK, dh, opk ? 128 : 96);

        // Alice deletes her ephemeral private key and the DH outputs
        crypto_bzero(&EK_As, sizeof EK_As);
        crypto_bzero(dh, sizeof dh);

        // Alice calculates the associated data AD that contains identity information for both parties
        // AD = IK_A || AK_B
        uint8_t AD[64];
        memcpy(AD, IK_Ap.b, 32);
        memcpy(AD + 32, bundle->ik_p.b, 32);

        show_block(std::cout, "*****Bob's identity key, as seen by Alice*****", bundle->ik_p.b, 32);

        // An initial ciphertext encrypted with some AEAD encryption scheme using AD as associated data and using an encryption key SK
        const uint ct_size = sizeof AD + 16;
        uint8_t cipher_text[ct_size];
        Chakey key;
        load (&key, SK);
        uint64_t nonce64;
        randombytes_buf(&nonce64, sizeof nonce64);
        encrypt_one (cipher_text, AD, sizeof AD, NULL, 0, key, nonce64);
        crypto_bzero(&key, sizeof key);

        /*
         * Alice then sends Bob an initial message containing:
         * Alice’s identity key IK_A
         * Alice’s ephemeral key EK_A
         * Identifiers stating which of Bob’s prekeys Alice used
         * An initial ciphertext encrypted with SK together with the nonce
         */
        msg.ik_p = IK_Ap;
        msg.ek_p = EK_Ap;
        msg.spk_p = bundle->spk_p;
        msg.has_opk = opk;
        msg.opk_p = bundle->opk_p;
        memcpy(msg.ad_ct, cipher_text, ct_size);
        memcpy(&msg.nonce64, &nonce64, 8);

        return &msg;
    }

};

void x3dh_key_exchange() {
    std::cout << "\nX3DH start, only public keys will be printed to screen.\n";

    Server server;

    std::cout << "\nBob prepares the prekey bundle:\n";

    // Bob's identity key secret IK_B:
    const char ikb_sec[] = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";

    Bob bob = Bob(ikb_sec);
    bob.PrintFingerprint();

    /*
     ** Bob publish keys:
     * Bob’s identity key IK_B
     * Bob’s signed prekey SPK_B
     * Bob’s prekey signature Sig(IK_B, Encode(SPK_B))
     * Bob’s one-time prekey OPK_B
     */
    PrekeyBundle* bobs_bundle = bob.GenerateBundle();

    // Bob sends the bundle to the server
    server.SetBundle(bobs_bundle);


    // init Alice using the private key
    const char ika_sec[] = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    Alice alice = Alice(ika_sec);
    alice.PrintFingerprint();

    /*
     ** Alice verifies the prekey SPK_Bp_sig and abort if verification fails
     *  Alice then generates an ephemeral key pair with public key EK_A.
     *
     * Alice calculates the shared key
     * DH1 = DH(IK_A, SPK_B)
     * DH2 = DH(EK_A, IK_B)
     * DH3 = DH(EK_A, SPK_B)
     * DH4 = DH(EK_A, OPK_B)
     * SK = KDF(DH1 || DH2 || DH3 || DH4)
     *
     *
     * Alice deletes her ephemeral private key and the DH outputs
     *
     * Alice calculates the associated data AD that contains identity information for both parties
     * AD = Encode(IK_A) || Encode(IK_B)
     *
     * Alice then sends Bob an initial message containing:
     * Alice’s identity key IK_A
     * Alice’s ephemeral key EK_A
     * Identifiers stating which of Bob’s prekeys Alice used
     * An initial ciphertext encrypted with some AEAD encryption scheme using AD as associated data and using an encryption key SK
     */

    // Alice receives Bob's bundle
    PrekeyBundle b_bundle = server.GetBundle();

    InitialMessage* a_msg = alice.GenerateInitialMessage(&b_bundle);

    server.SendInitialMessage(a_msg);

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
    InitialMessage* initial_msg = server.GetInitialMessage();

    bob.HandleInitialMessage(initial_msg);

    std::cout << "Parties should compare identity keys via an off-band channel to complete verification!\n";
}

int main() {
    try {
        x3dh_key_exchange();
    } catch (const std::exception &e) {
        std::cerr << "error: " << e.what() << '\n';
        return 1;
    }
}

