/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteBuffer.h>
#include <LibCrypto/Hash/HashManager.h>
#include <LibCrypto/OpenSSLForward.h>

namespace Crypto::Hash {

static ErrorOr<char const*> hash_kind_to_openssl_digest(HashKind hash)
{
    switch (hash) {
    case HashKind::SHA1:
        return "SHA-1";
    case HashKind::SHA256:
        return "SHA-256";
    case HashKind::SHA384:
        return "SHA-384";
    case HashKind::SHA512:
        return "SHA-512";
    default:
        return Error::from_string_literal("Unsupported hash kind");
    }
}

class OpenSSLKeyDerivationFunction {
    AK_MAKE_NONCOPYABLE(OpenSSLKeyDerivationFunction);

public:
    ~OpenSSLKeyDerivationFunction()
    {
        EVP_KDF_free(m_kdf);
    }

protected:
    explicit OpenSSLKeyDerivationFunction(EVP_KDF* kdf, HashKind hash_kind)
        : m_kdf(kdf)
    {
        m_hash_name = MUST(hash_kind_to_openssl_digest(hash_kind));
    }

    char const* m_hash_name;
    EVP_KDF* m_kdf;
};

}
