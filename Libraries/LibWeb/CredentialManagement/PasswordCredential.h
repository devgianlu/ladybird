/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Forward.h>
#include <LibWeb/Bindings/PasswordCredentialPrototype.h>
#include <LibWeb/Bindings/PlatformObject.h>
#include <LibWeb/CredentialManagement/Credential.h>
#include <LibWeb/HTML/HTMLFormElement.h>

namespace Web::CredentialManagement {

class PasswordCredentialInterface final : public CredentialInterface {
    CREDENTIAL_INTERFACE(PasswordCredentialInterface);

public:
    virtual String type() const override { return "password"_string; }
    virtual String options_member_identifier() const override { return "password"_string; }
    virtual Optional<String> get_permission_policy() const override { return {}; }
    virtual Optional<String> create_permission_policy() const override { return {}; }

    virtual String discovery() const override { return "credential store"_string; }
    virtual bool supports_conditional_user_mediation() const override
    {
        // NOTE: PasswordCredential does not override is_conditional_mediation_available(),
        //       therefore conditional mediation is not supported.
        return false;
    }

    // https://w3c.github.io/webappsec-credential-management/#create-passwordcredential
    virtual JS::ThrowCompletionOr<Variant<Empty, GC::Ref<Credential>, GC::Ref<CreateCredentialAlgorithm>>> create(JS::Realm&, URL::Origin const&, CredentialCreationOptions const&, bool) const override;
};

class PasswordCredential final : public Credential {
    WEB_PLATFORM_OBJECT(PasswordCredential, Credential);
    GC_DECLARE_ALLOCATOR(PasswordCredential);

public:
    [[nodiscard]] static GC::Ref<PasswordCredential> create(JS::Realm&);
    static WebIDL::ExceptionOr<GC::Ref<PasswordCredential>> construct_impl(JS::Realm&, HTML::HTMLFormElement&);
    static WebIDL::ExceptionOr<GC::Ref<PasswordCredential>> construct_impl(JS::Realm&, PasswordCredentialData const&);

    virtual ~PasswordCredential() override;

    String const& password() const { return m_password; }

    String type() const override { return "password"_string; }
    virtual CredentialInterface const* interface() const override
    {
        return PasswordCredentialInterface::the();
    }

    // https://w3c.github.io/webappsec-credential-management/#abstract-opdef-create-a-passwordcredential-from-passwordcredentialdata
    static WebIDL::ExceptionOr<GC::Ref<PasswordCredential>> create_from_password_credential_data(JS::Realm&, PasswordCredentialData const&);

    // https://w3c.github.io/webappsec-credential-management/#abstract-opdef-create-a-passwordcredential-from-an-htmlformelement
    static WebIDL::ExceptionOr<GC::Ref<PasswordCredential>> create_from_an_html_form_element(JS::Realm&, HTML::HTMLFormElement&, URL::Origin const&);

private:
    explicit PasswordCredential(JS::Realm&);
    virtual void initialize(JS::Realm&) override;

    String m_origin;
    // TODO: Use Core::SecretString when it comes back
    String m_password;
};

struct PasswordCredentialData : CredentialData {
    Optional<String> name;
    Optional<String> icon_url;
    String origin;
    String password;
};

using PasswordCredentialInit = Variant<PasswordCredentialData, GC::Root<HTML::HTMLFormElement>>;

}
