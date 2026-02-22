/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibURL/Parser.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/CredentialManagement/FederatedCredential.h>
#include <LibWeb/CredentialManagement/FederatedCredentialOperations.h>

namespace Web::CredentialManagement {

GC_DEFINE_ALLOCATOR(FederatedCredential);

// https://www.w3.org/TR/credential-management-1/#dom-federatedcredential-federatedcredential
WebIDL::ExceptionOr<GC::Ref<FederatedCredential>> FederatedCredential::construct_impl(JS::Realm& realm, FederatedCredentialInit const& data)
{
    // AD-HOC: Aligning with how Chromium retrieves the origin by parsing the URL from init.provider.
    auto url = URL::Parser::basic_parse(data.provider);
    if (!url.has_value())
        WebIDL::SyntaxError::create(realm, "'provider' is not a valid url."_utf16);
    auto origin = url.value().origin();

    // 1. Let r be the result of executing Create a FederatedCredential from FederatedCredentialInit on data. If that
    // threw an exception, rethrow that exception.
    // 2. Return r.
    return create_federated_credential(realm, data, origin);
}

FederatedCredential::~FederatedCredential()
{
}

FederatedCredential::FederatedCredential(JS::Realm& realm, FederatedCredentialInit const& init, URL::Origin const& origin)
    : Credential(realm, init.id)
    , CredentialUserData(init.name.value_or(String {}), init.icon_url.value_or(String {}))
    , m_provider(init.provider)
    , m_origin(origin)
{
}

void FederatedCredential::initialize(JS::Realm& realm)
{
    WEB_SET_PROTOTYPE_FOR_INTERFACE(FederatedCredential);
    Base::initialize(realm);
}

}
