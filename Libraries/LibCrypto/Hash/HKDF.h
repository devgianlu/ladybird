/*
 * Copyright (c) 2023, stelar7 <dudedbz@gmail.com>
 * Copyright (c) 2024, Ben Wiederhake <BenWiederhake.GitHub@gmx.de>
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibCrypto/Hash/OpenSSLKeyDerivationFunction.h>

namespace Crypto::Hash {

class HKDF : public OpenSSLKeyDerivationFunction {
public:
    HKDF(HashKind hash_kind);

    // Note: The output is different for a salt of length zero and an absent salt,
    // so Optional<ReadonlyBytes> really is the correct type.
    ErrorOr<ByteBuffer> derive_key(Optional<ReadonlyBytes> maybe_salt, ReadonlyBytes input_keying_material, ReadonlyBytes info, u32 key_length_bytes);
};

}
