/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "CredentialsContainer.h"

#include <LibWeb/Bindings/ExceptionOrUtils.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/CredentialManagement/FederatedCredential.h>

namespace Web::CredentialManagement {

GC_DEFINE_ALLOCATOR(FederatedCredential);

GC::Ref<FederatedCredential> FederatedCredential::create(JS::Realm& realm)
{
    return realm.create<FederatedCredential>(realm);
}

// https://w3c.github.io/webappsec-credential-management/#abstract-opdef-create-a-federatedcredential-from-federatedcredentialinit
WebIDL::ExceptionOr<GC::Ref<FederatedCredential>> FederatedCredential::create_from_federated_credential_init(JS::Realm& realm, FederatedCredentialInit const& init)
{
    // 1. Let c be a new FederatedCredential object.
    auto c = realm.create<FederatedCredential>(realm);

    // 2. If any of the following are the empty string, throw a TypeError exception:
    //      - init.id's value
    //      - init.provider's value
    if (init.id.is_empty() || init.provider.is_empty())
        return realm.vm().throw_completion<JS::TypeError>("id and provider must not be empty"sv);

    // 3. Set c’s properties as follows:
    //      id -> init.id's value
    c->m_id = init.id;
    //      provider -> init.provider's value
    c->m_provider = init.provider;
    //      iconURL -> init.iconURL's value
    c->m_icon_url = init.icon_url.value_or({});
    //      name -> init.name's value
    c->m_name = init.name.value_or({});
    //      [[origin]] -> init.origin's value.
    c->m_origin = init.origin;

    // 4. Return c.
    return c;
}

// https://w3c.github.io/webappsec-credential-management/#dom-federatedcredential-federatedcredential
WebIDL::ExceptionOr<GC::Ref<FederatedCredential>> FederatedCredential::construct_impl(JS::Realm& realm, FederatedCredentialInit const& init)
{
    // 1. Let r be the result of executing Create a FederatedCredential from FederatedCredentialInit on data.
    //    If that threw an exception, rethrow that exception.
    auto r = create_from_federated_credential_init(realm, init);
    if (r.is_error())
        return r.exception();

    // 2. Return r.
    return r.value();
}

FederatedCredential::~FederatedCredential()
{
}

FederatedCredential::FederatedCredential(JS::Realm& realm)
    : Credential(realm)
{
}

void FederatedCredential::initialize(JS::Realm& realm)
{
    Base::initialize(realm);
    WEB_SET_PROTOTYPE_FOR_INTERFACE(FederatedCredential);
}

// // https://w3c.github.io/webappsec-credential-management/#create-federatedcredential
JS::ThrowCompletionOr<Variant<Empty, GC::Ref<Credential>, GC::Ref<CreateCredentialAlgorithm>>> FederatedCredentialInterface::create(JS::Realm& realm, URL::Origin const& origin, CredentialCreationOptions const& options, bool) const
{
    // 1. Assert: options["federated"] exists, and sameOriginWithAncestors is unused.
    VERIFY(options.federated.has_value());

    // 2. Set options["federated"]'s origin member’s value to origin’s value.
    auto new_options = options;
    new_options.federated->origin = origin.serialize();

    // 3. Return the result of executing Create a FederatedCredential from FederatedCredentialInit given options["federated"].
    // If that threw an exception, then rethrow that exception.
    auto maybe_result = FederatedCredential::create_from_federated_credential_init(realm, *new_options.federated);
    if (maybe_result.is_error())
        return Bindings::exception_to_throw_completion(realm.vm(), maybe_result.release_error());

    return maybe_result.release_value();
}

}
