/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Forward.h>
#include <LibWeb/Bindings/AuthenticatorResponsePrototype.h>
#include <LibWeb/Bindings/PlatformObject.h>
#include <LibWeb/WebIDL/Promise.h>

namespace Web::CredentialManagement {

class AuthenticatorResponse : public Bindings::PlatformObject {
    WEB_PLATFORM_OBJECT(AuthenticatorResponse, Bindings::PlatformObject);
    GC_DECLARE_ALLOCATOR(AuthenticatorResponse);

public:
    [[nodiscard]] static GC::Ref<AuthenticatorResponse> create(JS::Realm&);

    virtual ~AuthenticatorResponse() override;

    GC::Ref<JS::ArrayBuffer> client_data_json() const;

protected:
    explicit AuthenticatorResponse(JS::Realm&);
    virtual void initialize(JS::Realm&) override;
};

}
