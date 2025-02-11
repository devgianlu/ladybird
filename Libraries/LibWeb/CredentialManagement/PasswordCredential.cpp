/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/ExceptionOrUtils.h>
#include <LibWeb/CredentialManagement/CredentialsContainer.h>
#include <LibWeb/CredentialManagement/PasswordCredential.h>
#include <LibWeb/HTML/AutocompleteElement.h>
#include <LibWeb/XHR/FormData.h>

namespace Web::CredentialManagement {

GC_DEFINE_ALLOCATOR(PasswordCredential);

GC::Ref<PasswordCredential> PasswordCredential::create(JS::Realm& realm)
{
    return realm.create<PasswordCredential>(realm);
}

// https://w3c.github.io/webappsec-credential-management/#abstract-opdef-create-a-passwordcredential-from-passwordcredentialdata
WebIDL::ExceptionOr<GC::Ref<PasswordCredential>> PasswordCredential::create_from_password_credential_data(JS::Realm& realm, PasswordCredentialData const& data)
{
    // 1. Let c be a new PasswordCredential object.
    auto c = realm.create<PasswordCredential>(realm);

    // 2. If any of the following are the empty string, throw a TypeError exception:
    //    - data’s id member’s value
    //    - data’s origin member’s value
    //    - data’s password member’s value
    if (data.id.is_empty() || data.origin.is_empty() || data.password.is_empty())
        return realm.vm().throw_completion<JS::TypeError>("id, origin and password must not be empty"sv);

    // 3. Set c’s properties as follows:
    //      password -> data’ s password member’ s value
    c->m_password = data.password;
    //      id -> data’ s id member’ s value
    c->m_id = data.id;
    //      iconURL -> data’ s iconURL member’ s value
    c->m_icon_url = data.icon_url.value_or({});
    //      name -> data’ s name member’ s value
    c->m_name = data.name.value_or({});
    //      [[origin]] -> data’ s origin member’ s value.
    c->m_origin = data.origin;

    // 4. Return c.
    return c;
}

// https://w3c.github.io/webappsec-credential-management/#abstract-opdef-create-a-passwordcredential-from-an-htmlformelement
WebIDL::ExceptionOr<GC::Ref<PasswordCredential>> PasswordCredential::create_from_an_html_form_element(JS::Realm& realm, HTML::HTMLFormElement& form, URL::Origin const& origin)
{
    // 1. Let data be a new PasswordCredentialData dictionary.
    PasswordCredentialData data {};

    // 2. Set data’s origin member’s value to origin’s value.
    data.origin = origin.serialize();

    // 3. Let formData be the result of executing the FormData constructor on form.
    auto form_data = TRY(XHR::FormData::construct_impl(realm, form));

    // 4. Let elements be a list of all the submittable elements whose form owner is form, in tree order.
    auto elements = form.get_submittable_elements();

    // 5. Let newPasswordObserved be false.
    bool new_password_observed = false;

    // 6. For each field in elements, run the following steps:
    for (auto& field : elements) {
        // 1. If field does not have an autocomplete attribute, then skip to the next field.
        if (!field->has_attribute(HTML::AttributeNames::autocomplete))
            continue;

        // 2. Let name be the value of field’s name attribute.
        auto maybe_name = field->name();
        if (!maybe_name.has_value())
            continue;

        auto name = maybe_name.value().to_string();

        // 3. If formData’s has() method returns false when executed on name, then skip to the next field.
        if (!form_data->has(maybe_name.value().to_string()))
            continue;

        // 4. If field’s autocomplete attribute’s value contains one or more autofill detail tokens (tokens), then:
        if (is<HTML::AutocompleteElement>(*field)) {
            auto tokens = as<HTML::AutocompleteElement>(*field).autocomplete_tokens();

            // 1. For each token in tokens:
            for (auto& token : tokens) {
                // 1. If token is an ASCII case-insensitive match for one of the following strings, run the associated steps:
                if (token.equals_ignoring_ascii_case("new-password"sv)) {
                    // Set data’s password member’s value to the result of executing formData’s get() method on name,
                    // and newPasswordObserved to true.
                    data.password = form_data->get(name).get<String>();
                    new_password_observed = true;
                } else if (token.equals_ignoring_ascii_case("current-password"sv)) {
                    // If newPasswordObserved is false, set data’s password member’s value to
                    // the result of executing formData’s get() method on name.
                    if (!new_password_observed) {
                        data.password = form_data->get(name).get<String>();
                    }
                } else if (token.equals_ignoring_ascii_case("photo"sv)) {
                    // Set data’s iconURL member’s value to the result of executing formData’s get() method on name.
                    data.icon_url = form_data->get(name).get<String>();
                } else if (token.equals_ignoring_ascii_case("name"sv) || token.equals_ignoring_ascii_case("nickname"sv)) {
                    // Set data’s name member’s value to the result of executing formData’s get() method on name.
                    data.name = form_data->get(name).get<String>();
                } else if (token.equals_ignoring_ascii_case("username"sv)) {
                    // Set data’s id member’s value to the result of executing formData’s get() method on name.
                    data.id = form_data->get(name).get<String>();
                }
            }
        }
    }

    // 7. Let c be the result of executing Create a PasswordCredential from PasswordCredentialData on data.
    //    If that threw an exception, rethrow that exception.
    // 8. Assert: c is a PasswordCredential.
    auto c = TRY(create_from_password_credential_data(realm, data));

    // 9. Return c.
    return c;
}

// https://w3c.github.io/webappsec-credential-management/#dom-passwordcredential-passwordcredential
WebIDL::ExceptionOr<GC::Ref<PasswordCredential>> PasswordCredential::construct_impl(JS::Realm& realm, HTML::HTMLFormElement& form)
{
    // 1. Let origin be the current settings object's origin.
    auto origin = HTML::current_principal_settings_object().origin();

    // 2. Let r be the result of executing Create a PasswordCredential from an HTMLFormElement given form and origin.
    auto r = create_from_an_html_form_element(realm, form, origin);

    // 3. If r is an exception, throw r.
    if (r.is_error())
        return r.exception();

    // 4. Otherwise, return r.
    return r.value();
}

// https://www.w3.org/TR/credential-management-1/#dom-passwordcredential-passwordcredential-data
WebIDL::ExceptionOr<GC::Ref<PasswordCredential>> PasswordCredential::construct_impl(JS::Realm& realm, PasswordCredentialData const& data)
{
    // 1. Let r be the result of executing Create a PasswordCredential from PasswordCredentialData on data.
    auto r = create_from_password_credential_data(realm, data);

    // 2. If r is an exception, throw r.
    if (r.is_error())
        return r.exception();

    // Otherwise, return r.
    return r.value();
}

PasswordCredential::~PasswordCredential()
{
}

PasswordCredential::PasswordCredential(JS::Realm& realm)
    : Credential(realm)
{
}

void PasswordCredential::initialize(JS::Realm& realm)
{
    Base::initialize(realm);
    WEB_SET_PROTOTYPE_FOR_INTERFACE(PasswordCredential);
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
            return PasswordCredential::create_from_an_html_form_element(realm, *form, origin);
        },
        // 3. If options["password"] is a PasswordCredentialData, return the result of executing
        //     Create a PasswordCredential from PasswordCredentialData given options["password"]. Rethrow any exceptions.
        [&](PasswordCredentialData const& data) {
            return PasswordCredential::create_from_password_credential_data(realm, data);
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
