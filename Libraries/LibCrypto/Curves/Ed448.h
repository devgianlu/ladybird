/*
 * Copyright (c) 2024, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteBuffer.h>

namespace Crypto::Curves {

class Ed448 {
public:

    size_t key_size() { return 57; }
    size_t signature_size() { return 0; }
    ErrorOr<ByteBuffer> generate_private_key();
    ErrorOr<ByteBuffer> generate_public_key(ReadonlyBytes private_key);
};

}
