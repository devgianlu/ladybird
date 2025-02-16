/*
 * Copyright (c) 2023, stelar7 <dudedbz@gmail.com>
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibCrypto/Hash/OpenSSLKeyDerivationFunction.h>

namespace Crypto::Hash {

class PBKDF2 : public OpenSSLKeyDerivationFunction {
public:
    PBKDF2(HashKind hash_kind);

    ErrorOr<ByteBuffer> derive_key(ReadonlyBytes password, ReadonlyBytes salt, u32 iterations, u32 key_length_bytes);
};

}
