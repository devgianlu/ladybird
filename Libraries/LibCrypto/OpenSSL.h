/*
 * Copyright (c) 2024, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Error.h>

#include <openssl/err.h>

namespace Crypto {

#define OPENSSL_TRY_PTR(...)                                                                 \
    ({                                                                                       \
        auto* _temporary_result = (__VA_ARGS__);                                             \
        if (!_temporary_result) [[unlikely]] {                                               \
            auto err = ERR_get_error();                                                      \
            VERIFY(err);                                                                     \
            auto* err_message = ERR_error_string(err, nullptr);                              \
            return Error::from_string_view(StringView { err_message, strlen(err_message) }); \
        }                                                                                    \
        _temporary_result;                                                                   \
    })

#define OPENSSL_TRY(...)                                                                     \
    ({                                                                                       \
        auto _temporary_result = (__VA_ARGS__);                                              \
        if (_temporary_result != 1) [[unlikely]] {                                           \
            auto err = ERR_get_error();                                                      \
            VERIFY(err);                                                                     \
            auto* err_message = ERR_error_string(err, nullptr);                              \
            return Error::from_string_view(StringView { err_message, strlen(err_message) }); \
        }                                                                                    \
        _temporary_result;                                                                   \
    })

}
