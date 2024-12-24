/*
 * Copyright (c) 2020, Ali Mohammad Pur <mpfard@serenityos.org>
 * Copyright (c) 2024, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/ByteBuffer.h>
#include <AK/Debug.h>
#include <AK/Random.h>
#include <LibCrypto/ASN1/ASN1.h>
#include <LibCrypto/ASN1/DER.h>
#include <LibCrypto/ASN1/PEM.h>
#include <LibCrypto/Certificate/Certificate.h>
#include <LibCrypto/OpenSSL.h>
#include <LibCrypto/PK/RSA.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

namespace Crypto::PK {

ErrorOr<RSA::KeyPairType> RSA::parse_rsa_key(ReadonlyBytes der, bool is_private, Vector<StringView> current_scope)
{
    KeyPairType keypair;

    ASN1::Decoder decoder(der);

    if (is_private) {
        // RSAPrivateKey ::= SEQUENCE {
        //      version             Version,
        //      modulus             INTEGER,
        //      publicExponent      INTEGER,
        //      privateExponent     INTEGER,
        //      prime1              INTEGER,
        //      prime2              INTEGER,
        //      exponent1           INTEGER,
        //      exponent2           INTEGER,
        //      coefficient         INTEGER,
        //      otherPrimeInfos     OtherPrimeInfos OPTIONAL
        // }

        ENTER_TYPED_SCOPE(Sequence, "RSAPrivateKey"sv);

        PUSH_SCOPE("version");
        READ_OBJECT(Integer, Crypto::UnsignedBigInteger, version);
        POP_SCOPE();
        if (version != 0) {
            ERROR_WITH_SCOPE(TRY(String::formatted("Invalid version value at {}", current_scope)));
        }

        PUSH_SCOPE("modulus");
        READ_OBJECT(Integer, Crypto::UnsignedBigInteger, modulus);
        POP_SCOPE();

        PUSH_SCOPE("publicExponent");
        READ_OBJECT(Integer, Crypto::UnsignedBigInteger, public_exponent);
        POP_SCOPE();

        PUSH_SCOPE("privateExponent");
        READ_OBJECT(Integer, Crypto::UnsignedBigInteger, private_exponent);
        POP_SCOPE();

        PUSH_SCOPE("prime1");
        READ_OBJECT(Integer, Crypto::UnsignedBigInteger, prime1);
        POP_SCOPE();

        PUSH_SCOPE("prime2");
        READ_OBJECT(Integer, Crypto::UnsignedBigInteger, prime2);
        POP_SCOPE();

        PUSH_SCOPE("exponent1");
        READ_OBJECT(Integer, Crypto::UnsignedBigInteger, exponent1);
        POP_SCOPE();

        PUSH_SCOPE("exponent2");
        READ_OBJECT(Integer, Crypto::UnsignedBigInteger, exponent2);
        POP_SCOPE();

        PUSH_SCOPE("coefficient");
        READ_OBJECT(Integer, Crypto::UnsignedBigInteger, coefficient);
        POP_SCOPE();

        keypair.private_key = {
            modulus,
            private_exponent,
            public_exponent,
            prime1,
            prime2,
            exponent1,
            exponent2,
            coefficient,
        };
        keypair.public_key = { modulus, public_exponent };

        EXIT_SCOPE();
        return keypair;
    } else {
        // RSAPublicKey ::= SEQUENCE {
        //      modulus         INTEGER,
        //      publicExponent  INTEGER
        // }

        ENTER_TYPED_SCOPE(Sequence, "RSAPublicKey"sv);

        PUSH_SCOPE("modulus");
        READ_OBJECT(Integer, Crypto::UnsignedBigInteger, modulus);
        POP_SCOPE();

        PUSH_SCOPE("publicExponent");
        READ_OBJECT(Integer, Crypto::UnsignedBigInteger, public_exponent);
        POP_SCOPE();

        keypair.public_key = { move(modulus), move(public_exponent) };

        EXIT_SCOPE();
        return keypair;
    }
}

#define OPENSSL_GET_KEY_PARAM(param, openssl_name)                                \
    auto param##_bn = TRY(OpenSSL_BN::create());                                  \
    auto* param##_bn_ptr = param##_bn.ptr();                                      \
    OPENSSL_TRY(EVP_PKEY_get_bn_param(key.ptr(), openssl_name, &param##_bn_ptr)); \
    auto param = TRY(openssl_bignum_to_unsigned_big_integer(param##_bn));

ErrorOr<RSA::KeyPairType> RSA::generate_key_pair(size_t bits, IntegerType e)
{
    auto ctx = TRY(OpenSSL_PKEY_CTX::wrap(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr)));

    OPENSSL_TRY(EVP_PKEY_keygen_init(ctx.ptr()));

    auto e_bn = TRY(unsigned_big_integer_to_openssl_bignum(e));

    auto* params_bld = OPENSSL_TRY_PTR(OSSL_PARAM_BLD_new());
    ArmedScopeGuard const free_params_bld = [&] { OSSL_PARAM_BLD_free(params_bld); };

    OPENSSL_TRY(OSSL_PARAM_BLD_push_size_t(params_bld, OSSL_PKEY_PARAM_RSA_BITS, bits));
    OPENSSL_TRY(OSSL_PARAM_BLD_push_BN(params_bld, OSSL_PKEY_PARAM_RSA_E, e_bn.ptr()));

    OPENSSL_TRY(EVP_PKEY_CTX_set_params(ctx.ptr(), OSSL_PARAM_BLD_to_param(params_bld)));

    auto key = TRY(OpenSSL_PKEY::create());
    auto* key_ptr = key.ptr();
    OPENSSL_TRY(EVP_PKEY_generate(ctx.ptr(), &key_ptr));

    OPENSSL_GET_KEY_PARAM(n, OSSL_PKEY_PARAM_RSA_N);
    OPENSSL_GET_KEY_PARAM(d, OSSL_PKEY_PARAM_RSA_D);
    OPENSSL_GET_KEY_PARAM(p, OSSL_PKEY_PARAM_RSA_FACTOR1);
    OPENSSL_GET_KEY_PARAM(q, OSSL_PKEY_PARAM_RSA_FACTOR2);
    OPENSSL_GET_KEY_PARAM(dp, OSSL_PKEY_PARAM_RSA_EXPONENT1);
    OPENSSL_GET_KEY_PARAM(dq, OSSL_PKEY_PARAM_RSA_EXPONENT2);
    OPENSSL_GET_KEY_PARAM(qinv, OSSL_PKEY_PARAM_RSA_COEFFICIENT1);

    RSAKeyPair<PublicKeyType, PrivateKeyType> keys {
        { n, e },
        { n, d, e, p, q, dp, dq, qinv }
    };
    return keys;
}

#undef OPENSSL_GET_KEY_PARAM

#define OPENSSL_SET_KEY_PARAM_NOT_ZERO(param, openssl_name, value)                       \
    auto param##_bn = TRY(unsigned_big_integer_to_openssl_bignum(value));                \
    if (!value.is_zero()) {                                                              \
        OPENSSL_TRY(OSSL_PARAM_BLD_push_BN(params_bld, openssl_name, param##_bn.ptr())); \
    }

ErrorOr<OpenSSL_PKEY> RSA::public_key_to_openssl_pkey(PublicKeyType const& public_key)
{
    auto ctx = TRY(OpenSSL_PKEY_CTX::wrap(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr)));

    OPENSSL_TRY(EVP_PKEY_fromdata_init(ctx.ptr()));

    auto* params_bld = OPENSSL_TRY_PTR(OSSL_PARAM_BLD_new());
    ArmedScopeGuard const free_params_bld = [&] { OSSL_PARAM_BLD_free(params_bld); };

    OPENSSL_SET_KEY_PARAM_NOT_ZERO(n, OSSL_PKEY_PARAM_RSA_N, public_key.modulus());
    OPENSSL_SET_KEY_PARAM_NOT_ZERO(e, OSSL_PKEY_PARAM_RSA_E, public_key.public_exponent());

    auto key = TRY(OpenSSL_PKEY::create());
    auto* key_ptr = key.ptr();
    OPENSSL_TRY(EVP_PKEY_fromdata(ctx.ptr(), &key_ptr, EVP_PKEY_PUBLIC_KEY, OSSL_PARAM_BLD_to_param(params_bld)));
    return key;
}

ErrorOr<OpenSSL_PKEY> RSA::private_key_to_openssl_pkey(PrivateKeyType const& private_key)
{
    auto ctx = TRY(OpenSSL_PKEY_CTX::wrap(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr)));

    OPENSSL_TRY(EVP_PKEY_fromdata_init(ctx.ptr()));

    auto* params_bld = OPENSSL_TRY_PTR(OSSL_PARAM_BLD_new());
    ArmedScopeGuard const free_params_bld = [&] { OSSL_PARAM_BLD_free(params_bld); };

    OPENSSL_SET_KEY_PARAM_NOT_ZERO(n, OSSL_PKEY_PARAM_RSA_N, private_key.modulus());
    OPENSSL_SET_KEY_PARAM_NOT_ZERO(e, OSSL_PKEY_PARAM_RSA_E, private_key.public_exponent());
    OPENSSL_SET_KEY_PARAM_NOT_ZERO(d, OSSL_PKEY_PARAM_RSA_D, private_key.private_exponent());
    OPENSSL_SET_KEY_PARAM_NOT_ZERO(p, OSSL_PKEY_PARAM_RSA_FACTOR1, private_key.prime1());
    OPENSSL_SET_KEY_PARAM_NOT_ZERO(q, OSSL_PKEY_PARAM_RSA_FACTOR2, private_key.prime2());
    OPENSSL_SET_KEY_PARAM_NOT_ZERO(dp, OSSL_PKEY_PARAM_RSA_EXPONENT1, private_key.exponent1());
    OPENSSL_SET_KEY_PARAM_NOT_ZERO(dq, OSSL_PKEY_PARAM_RSA_EXPONENT2, private_key.exponent2());
    OPENSSL_SET_KEY_PARAM_NOT_ZERO(qinv, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, private_key.coefficient());

    auto key = TRY(OpenSSL_PKEY::create());
    auto* key_ptr = key.ptr();
    OPENSSL_TRY(EVP_PKEY_fromdata(ctx.ptr(), &key_ptr, EVP_PKEY_KEYPAIR, OSSL_PARAM_BLD_to_param(params_bld)));
    return key;
}

#undef OPENSSL_SET_KEY_PARAM_NOT_ZERO

ErrorOr<void> RSA::encrypt(ReadonlyBytes in, Bytes& out)
{
    auto key = TRY(public_key_to_openssl_pkey(m_public_key));

    auto ctx = TRY(OpenSSL_PKEY_CTX::wrap(EVP_PKEY_CTX_new_from_pkey(nullptr, key.ptr(), nullptr)));

    OPENSSL_TRY(EVP_PKEY_encrypt_init(ctx.ptr()));
    TRY(configure(ctx));

    size_t out_size = out.size();
    OPENSSL_TRY(EVP_PKEY_encrypt(ctx.ptr(), out.data(), &out_size, in.data(), in.size()));
    out = out.slice(0, out_size);
    return {};
}

ErrorOr<void> RSA::decrypt(ReadonlyBytes in, Bytes& out)
{
    auto key = TRY(private_key_to_openssl_pkey(m_private_key));

    auto ctx = TRY(OpenSSL_PKEY_CTX::wrap(EVP_PKEY_CTX_new_from_pkey(nullptr, key.ptr(), nullptr)));

    OPENSSL_TRY(EVP_PKEY_decrypt_init(ctx.ptr()));
    TRY(configure(ctx));

    size_t out_size = out.size();
    OPENSSL_TRY(EVP_PKEY_decrypt(ctx.ptr(), out.data(), &out_size, in.data(), in.size()));
    out = out.slice(0, out_size);
    return {};
}

ErrorOr<void> RSA::sign(ReadonlyBytes message, Bytes& signature)
{
    auto key = TRY(private_key_to_openssl_pkey(m_private_key));

    auto ctx = TRY(OpenSSL_PKEY_CTX::wrap(EVP_PKEY_CTX_new_from_pkey(nullptr, key.ptr(), nullptr)));

    OPENSSL_TRY(EVP_PKEY_sign_init(ctx.ptr()));
    TRY(configure(ctx));

    size_t signature_size = signature.size();
    OPENSSL_TRY(EVP_PKEY_sign(ctx.ptr(), signature.data(), &signature_size, message.data(), message.size()));
    signature = signature.slice(0, signature_size);
    return {};
}

ErrorOr<bool> RSA::verify(ReadonlyBytes message, ReadonlyBytes signature)
{
    auto key = TRY(public_key_to_openssl_pkey(m_public_key));

    auto ctx = TRY(OpenSSL_PKEY_CTX::wrap(EVP_PKEY_CTX_new_from_pkey(nullptr, key.ptr(), nullptr)));

    OPENSSL_TRY(EVP_PKEY_verify_init(ctx.ptr()));
    TRY(configure(ctx));

    auto ret = EVP_PKEY_verify(ctx.ptr(), signature.data(), signature.size(), message.data(), message.size());
    if (ret == 1)
        return true;
    if (ret == 0)
        return false;
    OPENSSL_TRY(ret);
    VERIFY_NOT_REACHED();
}

void RSA::import_private_key(ReadonlyBytes bytes, bool pem)
{
    ByteBuffer decoded_bytes;
    if (pem) {
        auto decoded = decode_pem(bytes);
        if (decoded.type == PEMType::RSAPrivateKey) {
            decoded_bytes = decoded.data;
        } else if (decoded.type == PEMType::PrivateKey) {
            ASN1::Decoder decoder(decoded.data);
            auto maybe_key = Certificate::parse_private_key_info(decoder, {});
            if (maybe_key.is_error()) {
                dbgln("Failed to parse private key info: {}", maybe_key.error());
                VERIFY_NOT_REACHED();
            }

            m_private_key = maybe_key.release_value().rsa;
            return;
        } else {
            dbgln("Expected a PEM encoded private key");
            VERIFY_NOT_REACHED();
        }
    }

    auto maybe_key = parse_rsa_key(decoded_bytes, true, {});
    if (maybe_key.is_error()) {
        dbgln("Failed to parse RSA private key: {}", maybe_key.error());
        VERIFY_NOT_REACHED();
    }
    m_private_key = maybe_key.release_value().private_key;
}

void RSA::import_public_key(ReadonlyBytes bytes, bool pem)
{
    ByteBuffer decoded_bytes;
    if (pem) {
        auto decoded = decode_pem(bytes);
        if (decoded.type == PEMType::RSAPublicKey) {
            decoded_bytes = decoded.data;
        } else if (decoded.type == PEMType::PublicKey) {
            ASN1::Decoder decoder(decoded.data);
            auto maybe_key = Certificate::parse_subject_public_key_info(decoder, {});
            if (maybe_key.is_error()) {
                dbgln("Failed to parse subject public key info: {}", maybe_key.error());
                VERIFY_NOT_REACHED();
            }

            m_public_key = maybe_key.release_value().rsa;
            return;
        } else {
            dbgln("Expected a PEM encoded public key");
            VERIFY_NOT_REACHED();
        }
    }

    auto maybe_key = parse_rsa_key(decoded_bytes, false, {});
    if (maybe_key.is_error()) {
        dbgln("Failed to parse RSA public key: {}", maybe_key.error());
        VERIFY_NOT_REACHED();
    }
    m_public_key = maybe_key.release_value().public_key;
}

ErrorOr<bool> RSA_PKCS1_EMSA::verify(ReadonlyBytes message, ReadonlyBytes signature)
{
    auto key = TRY(public_key_to_openssl_pkey(m_public_key));
    auto const* hash_type = TRY(this->hash_type());

    auto ctx = TRY(OpenSSL_MD_CTX::create());

    auto key_ctx = TRY(OpenSSL_PKEY_CTX::wrap(EVP_PKEY_CTX_new(key.ptr(), nullptr)));
    EVP_MD_CTX_set_pkey_ctx(ctx.ptr(), key_ctx.ptr());

    OPENSSL_TRY(EVP_DigestVerifyInit(ctx.ptr(), nullptr, hash_type, nullptr, key.ptr()));
    TRY(configure(key_ctx));

    auto res = EVP_DigestVerify(ctx.ptr(), signature.data(), signature.size(), message.data(), message.size());
    if (res == 1)
        return true;
    if (res == 0)
        return false;
    OPENSSL_TRY(res);
    VERIFY_NOT_REACHED();
}

ErrorOr<void> RSA_PKCS1_EMSA::sign(ReadonlyBytes message, Bytes& signature)
{
    auto key = TRY(public_key_to_openssl_pkey(m_public_key));
    auto const* hash_type = TRY(this->hash_type());

    auto ctx = TRY(OpenSSL_MD_CTX::create());

    auto key_ctx = TRY(OpenSSL_PKEY_CTX::wrap(EVP_PKEY_CTX_new(key.ptr(), nullptr)));
    EVP_MD_CTX_set_pkey_ctx(ctx.ptr(), key_ctx.ptr());

    OPENSSL_TRY(EVP_DigestSignInit(ctx.ptr(), nullptr, hash_type, nullptr, key.ptr()));
    TRY(configure(key_ctx));

    size_t signature_size = signature.size();
    OPENSSL_TRY(EVP_DigestSign(ctx.ptr(), signature.data(), &signature_size, message.data(), message.size()));
    signature = signature.slice(0, signature_size);
    return {};
}

}
