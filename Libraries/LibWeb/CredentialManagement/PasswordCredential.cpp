/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/ExceptionOrUtils.h>
#include <LibWeb/CredentialManagement/CredentialsContainer.h>
#include <LibWeb/CredentialManagement/PasswordCredential.h>
#include <LibWeb/CredentialManagement/PasswordCredentialOperations.h>
#include <LibWeb/HTML/AutocompleteElement.h>
#include <LibWeb/XHR/FormData.h>

namespace Web::CredentialManagement {

GC_DEFINE_ALLOCATOR(PasswordCredential);

// https://www.w3.org/TR/credential-management-1/#dom-passwordcredential-passwordcredential
WebIDL::ExceptionOr<GC::Ref<PasswordCredential>> PasswordCredential::construct_impl(JS::Realm& realm, GC::Ptr<HTML::HTMLFormElement> const& form)
{
    // 1. Let origin be the current settings object's origin.
    auto origin = HTML::current_principal_settings_object().origin();

    // 2. Let r be the result of executing Create a PasswordCredential from an HTMLFormElement given form and origin.
    // 3. If r is an exception, throw r. Otherwise, return r.
    return create_password_credential(realm, form, origin);
}

// https://www.w3.org/TR/credential-management-1/#dom-passwordcredential-passwordcredential-data
WebIDL::ExceptionOr<GC::Ref<PasswordCredential>> PasswordCredential::construct_impl(JS::Realm& realm, PasswordCredentialData const& data)
{
    // AD-HOC: Let origin be the current settings object's origin.
    auto origin = HTML::current_principal_settings_object().origin();

    // 1. Let r be the result of executing Create a PasswordCredential from PasswordCredentialData on data.
    // 2. If r is an exception, throw r.
    return create_password_credential(realm, data, origin);
}

PasswordCredential::~PasswordCredential()
{
}

PasswordCredential::PasswordCredential(JS::Realm& realm, PasswordCredentialData const& data, URL::Origin const& origin)
    : Credential(realm, data.id)
    , CredentialUserData(data.name.value_or(String {}), data.icon_url.value_or(String {}))
    , m_password(data.password)
    , m_origin(origin)
{
}

void PasswordCredential::initialize(JS::Realm& realm)
{
    WEB_SET_PROTOTYPE_FOR_INTERFACE(PasswordCredential);
    Base::initialize(realm);
}

// https://w3c.github.io/webappsec-credential-management/#create-passwordcredential
JS::ThrowCompletionOr<Variant<Empty, GC::Ref<Credential>, GC::Ref<CreateCredentialAlgorithm>>> PasswordCredentialInterface::create(JS::Realm& realm, URL::Origin const& origin, CredentialCreationOptions const& options, bool) const
{
    // 1. Assert: options["password"] exists, and sameOriginWithAncestors is unused.
    VERIFY(options.password.has_value());

    auto maybe_result = options.password->visit(
        // 2. If options["password"] is an HTMLFormElement, return the result of executing Create a PasswordCredential
        //    from an HTMLFormElement given options["password"] and origin. Rethrow any exceptions.
        [&](GC::Root<HTML::HTMLFormElement> const& form) {
            return create_password_credential(realm, *form, origin);
        },
        // 3. If options["password"] is a PasswordCredentialData, return the result of executing
        //     Create a PasswordCredential from PasswordCredentialData given options["password"]. Rethrow any exceptions.
        [&](PasswordCredentialData const& data) {
            return create_password_credential(realm, data, origin);
        },
        // 4. Throw a TypeError exception.
        [&](auto) {
            return realm.vm().throw_completion<JS::TypeError>("options.password must be an HTMLFormElement or a PasswordCredentialData"sv);
        });
    if (maybe_result.is_error())
        return Bindings::exception_to_throw_completion(realm.vm(), maybe_result.release_error());

    return maybe_result.release_value();
}

}
