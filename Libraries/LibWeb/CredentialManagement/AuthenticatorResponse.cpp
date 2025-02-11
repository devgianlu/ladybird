/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibJS/Runtime/ArrayBuffer.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/CredentialManagement/AuthenticatorResponse.h>

namespace Web::CredentialManagement {

GC_DEFINE_ALLOCATOR(AuthenticatorResponse);

AuthenticatorResponse::~AuthenticatorResponse() { }

GC::Ref<JS::ArrayBuffer> AuthenticatorResponse::client_data_json() const
{
    return MUST(JS::ArrayBuffer::create(realm(), static_cast<size_t>(0)));
}

AuthenticatorResponse::AuthenticatorResponse(JS::Realm& realm)
    : PlatformObject(realm)
{
}

void AuthenticatorResponse::initialize(JS::Realm& realm)
{
    Base::initialize(realm);
    WEB_SET_PROTOTYPE_FOR_INTERFACE(AuthenticatorResponse);
}
}
