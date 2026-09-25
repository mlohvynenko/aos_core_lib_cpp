/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CORE_COMMON_PKCS11_PRIVATEKEY_HPP_
#define AOS_CORE_COMMON_PKCS11_PRIVATEKEY_HPP_

#include "pkcs11.hpp"

namespace aos::pkcs11 {

/**
 * PKCS11 RSA private key.
 */
class PKCS11RSAPrivateKey : public crypto::PrivateKeyItf {
public:
    /**
     * Constructs object instance.
     *
     * @param allocator allocator to use for temporary objects.
     * @param session session context.
     * @param privKeyHandle private key handle.
     * @param pubKey public key.
     */
    PKCS11RSAPrivateKey(AllocatorItf& allocator, const SharedPtr<SessionContext>& session, ObjectHandle privKeyHandle,
        const crypto::RSAPublicKey& pubKey);

    /**
     * Returns public part of a private key.
     *
     * @return const PublicKeyItf&.
     */
    const crypto::PublicKeyItf& GetPublic() const override;

    /**
     * Calculates a signature of a given digest.
     * Currently supported PKCS#1v1.5 implementation only.
     *
     * @param digest input hash digest.
     * @param options signing options.
     * @param[out] signature result signature.
     * @return Error.
     */
    Error Sign(
        const Array<uint8_t>& digest, const crypto::SignOptions& options, Array<uint8_t>& signature) const override;

    /**
     * Decrypts a cipher message.
     * Implemented PKCS#1v1.5 decryption only.
     *
     * @param cipher encrypted message.
     * @param options decryption options.
     * @param[out] result decoded message.
     * @return Error.
     */
    Error Decrypt(
        const Array<uint8_t>& cipher, const crypto::DecryptionOptions& options, Array<uint8_t>& result) const override;

private:
    static constexpr uint8_t cSHA1Prefix[]
        = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
    static constexpr uint8_t cSHA224Prefix[] = {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c};
    static constexpr uint8_t cSHA256Prefix[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    static constexpr uint8_t cSHA384Prefix[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
    static constexpr uint8_t cSHA512Prefix[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

    static constexpr auto cMaxPrefixSize = Max(sizeof(cSHA1Prefix), sizeof(cSHA224Prefix), sizeof(cSHA256Prefix),
        sizeof(cSHA384Prefix), sizeof(cSHA512Prefix));

    Array<uint8_t> GetPrefix(crypto::Hash hash) const;

    AllocatorItf& mAllocator;

    SharedPtr<SessionContext> mSession;
    ObjectHandle              mPrivKeyHandle;
    crypto::RSAPublicKey      mPublicKey;
};

/**
 * Converter for mechanism options of RSA encryption/decryption.
 */
struct PCKS11RSAMechConverter : public StaticVisitor<RetWithError<CK_MECHANISM>> {
public:
    /**
     * Converts RSA PKCS1v15 decryption options.
     *
     * @param options pkcs1v15 decrypt options.
     * @return RetWithError<CK_MECHANISM>.
     */
    RetWithError<CK_MECHANISM> Visit(const crypto::PKCS1v15DecryptionOptions& options) const;

    /**
     * Converts RSA OAEP decryption options.
     *
     * @param options pkcs1v15 decrypt options.
     * @return RetWithError<CK_MECHANISM>.
     */
    RetWithError<CK_MECHANISM> Visit(const crypto::OAEPDecryptionOptions& options) const;

    /**
     * Rejects a GCM option: not applicable to an RSA key.
     *
     * @return RetWithError<CK_MECHANISM>.
     */
    RetWithError<CK_MECHANISM> Visit(const crypto::GCMDecryptionOptions& options) const;

private:
    mutable CK_RSA_PKCS_OAEP_PARAMS mOAEPParams = {};
};

/**
 * PKCS11 ECDSA private key.
 */
class PKCS11ECDSAPrivateKey : public crypto::PrivateKeyItf {
public:
    /**
     * Constructs object instance.
     *
     * @param session session context.
     * @param cryptoProvider provider of crypto interface.
     * @param privKeyHandle private key handle.
     * @param pubKey public key.
     */
    PKCS11ECDSAPrivateKey(const SharedPtr<SessionContext>& session, crypto::x509::ProviderItf& cryptoProvider,
        ObjectHandle privKeyHandle, const crypto::ECDSAPublicKey& pubKey);

    /**
     * Returns public part of a private key.
     *
     * @return const PublicKeyItf&.
     */
    const crypto::PublicKeyItf& GetPublic() const override;

    /**
     * Calculates a signature of a given digest.
     *
     * @param digest input hash digest.
     * @param options signing options.
     * @param[out] signature result signature.
     * @return Error.
     */
    Error Sign(
        const Array<uint8_t>& digest, const crypto::SignOptions& options, Array<uint8_t>& signature) const override;

    /**
     * Decrypts a cipher message.
     * There is no Decrypt implementation for ECDSA.
     * Some information here: https://stackoverflow.com/questions/76741626/how-to-decrypt-data-with-a-ecdsa-private-key
     *
     * @param cipher encrypted message.
     * @param options decryption options.
     * @param[out] result decoded message.
     * @return Error.
     */
    Error Decrypt(
        const Array<uint8_t>& cipher, const crypto::DecryptionOptions& options, Array<uint8_t>& result) const override
    {
        (void)cipher;
        (void)options;
        (void)result;

        return ErrorEnum::eFailed;
    }

private:
    SharedPtr<SessionContext>  mSession;
    crypto::x509::ProviderItf& mCryptoProvider;
    ObjectHandle               mPrivKeyHandle;
    crypto::ECDSAPublicKey     mPublicKey;
};

/**
 * Converter for mechanism options of AES-GCM decryption.
 */
struct PKCS11AESMechConverter : public StaticVisitor<RetWithError<CK_MECHANISM>> {
public:
    /**
     * Rejects a PKCS1v15 option: not applicable to a symmetric key.
     *
     * @return RetWithError<CK_MECHANISM>.
     */
    RetWithError<CK_MECHANISM> Visit(const crypto::PKCS1v15DecryptionOptions& options) const;

    /**
     * Rejects an OAEP option: not applicable to a symmetric key.
     *
     * @return RetWithError<CK_MECHANISM>.
     */
    RetWithError<CK_MECHANISM> Visit(const crypto::OAEPDecryptionOptions& options) const;

    /**
     * Converts GCM decryption options to a CKM_AES_GCM mechanism.
     *
     * @param options GCM decrypt options (IV).
     * @return RetWithError<CK_MECHANISM>.
     */
    RetWithError<CK_MECHANISM> Visit(const crypto::GCMDecryptionOptions& options) const;

private:
    mutable CK_GCM_PARAMS mGCMParams = {};
};

/**
 * A PKCS11 CKO_SECRET_KEY (AES) object that decrypts without ever reading the key's own value: the raw key
 * bytes never leave the token. Implements crypto::PrivateKeyItf so it can be loaded and handled the same way
 * as an RSA/ECDSA private key (see pkcs11::Utils::FindPrivateKey); a symmetric key has no public part or
 * signing capability, so GetPublic/Sign simply don't apply and Decrypt only accepts GCMDecryptionOptions.
 */
class AESPrivateKey : public crypto::PrivateKeyItf {
public:
    /**
     * Constructs object instance.
     *
     * @param session session context.
     * @param keyHandle secret key handle.
     */
    AESPrivateKey(const SharedPtr<SessionContext>& session, ObjectHandle keyHandle);

    /**
     * A symmetric key has no public part. Returns a placeholder that must never be meaningfully used: nothing
     * that knows this is a symmetric key has a reason to call this.
     *
     * @return const crypto::PublicKeyItf&.
     */
    const crypto::PublicKeyItf& GetPublic() const override;

    /**
     * Not supported: a symmetric key does not sign.
     *
     * @return Error always ErrorEnum::eNotSupported.
     */
    Error Sign(
        const Array<uint8_t>& digest, const crypto::SignOptions& options, Array<uint8_t>& signature) const override;

    /**
     * Decrypts an AES-256-GCM encrypted message using this key on the token. options must hold
     * GCMDecryptionOptions (the IV); cipher is the ciphertext followed by the 16-byte authentication tag, as
     * produced by a typical AEAD API. Returns ErrorEnum::eNotSupported for any other DecryptionOptions kind.
     *
     * @param cipher ciphertext followed by the authentication tag.
     * @param options decryption options; must hold GCMDecryptionOptions.
     * @param[out] result decoded message.
     * @return Error.
     */
    Error Decrypt(
        const Array<uint8_t>& cipher, const crypto::DecryptionOptions& options, Array<uint8_t>& result) const override;

    /**
     * Same as Decrypt, but reads the ciphertext incrementally from chunkProvider via a multi-part
     * PKCS11 operation instead of requiring it all in memory up front (see
     * SessionContext::DecryptMultiPart). result must still have capacity for the whole plaintext:
     * most PKCS11 modules, including SoftHSM2, only release AEAD-decrypted data once the
     * authentication tag has been verified, all at once, at the very end.
     *
     * @param chunkProvider supplies the cipher message in chunks.
     * @param options decryption options; must hold GCMDecryptionOptions.
     * @param[out] result decoded message.
     * @return Error. ErrorEnum::eNotSupported if this token doesn't support multi-part CKM_AES_GCM
     * decrypt operations at all: retry via Decrypt() instead.
     */
    Error StreamDecrypt(crypto::ChunkProviderItf& chunkProvider, const crypto::DecryptionOptions& options,
        Array<uint8_t>& result) const override;

private:
    // Only exists to satisfy PrivateKeyItf::GetPublic's reference-returning signature for a key type that
    // has no public part; GetKeyType/IsEqual are never meaningfully called on it.
    class NoPublicKey : public crypto::PublicKeyItf {
    public:
        crypto::KeyType GetKeyType() const override { return crypto::KeyType {}; }
        bool            IsEqual(const crypto::PublicKeyItf& pubKey) const override
        {
            (void)pubKey;

            return false;
        }
    };

    SharedPtr<SessionContext> mSession;
    ObjectHandle              mKeyHandle;
    NoPublicKey               mNoPublicKey;
};

} // namespace aos::pkcs11

#endif
