/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Base64.h>
#include <LibJS/Forward.h>
#include <LibJS/Runtime/ArrayBuffer.h>
#include <LibWeb/Bindings/PlatformObject.h>
#include <LibWeb/Bindings/PublicKeyCredentialPrototype.h>
#include <LibWeb/CredentialManagement/AuthenticatorResponse.h>
#include <LibWeb/CredentialManagement/Credential.h>
#include <LibWeb/WebIDL/Buffers.h>
#include <LibWeb/WebIDL/Promise.h>
#include <LibWeb/WebIDL/Types.h>

namespace Web::CredentialManagement {

struct AuthenticationExtensionsClientOutputs {
};

struct AuthenticationExtensionsClientInputs {
};

struct AuthenticatorSelectionCriteria {
    String authenticator_attachment;
    String resident_key;
    bool require_resident_key { false };
    String user_verification = "preferred"_string;
};

struct PublicKeyCredentialEntity {
    String name;
};

struct PublicKeyCredentialUserEntity : PublicKeyCredentialEntity {
    GC::Root<WebIDL::BufferSource> id;
    String display_name;
};

struct PublicKeyCredentialRpEntity : PublicKeyCredentialEntity {
    Optional<String> id;
};

typedef WebIDL::Long COSEAlgorithmIdentifier;

struct PublicKeyCredentialParameters {
    String type;
    COSEAlgorithmIdentifier alg;
};

struct PublicKeyCredentialDescriptor {
    String type;
    GC::Root<WebIDL::BufferSource> id;
    Optional<Vector<String>> transports;
};

struct PublicKeyCredentialCreationOptions {
    PublicKeyCredentialRpEntity rp;
    PublicKeyCredentialUserEntity user;

    GC::Root<WebIDL::BufferSource> challenge;
    Vector<PublicKeyCredentialParameters> pub_key_cred_params;

    Optional<WebIDL::UnsignedLong> timeout;
    Vector<PublicKeyCredentialDescriptor> exclude_credentials = {};
    Optional<AuthenticatorSelectionCriteria> authenticator_selection;
    Vector<String> hints = {};
    String attestation = "none"_string;
    Vector<String> attestation_formats = {};
    Optional<AuthenticationExtensionsClientInputs> extensions;
};

struct PublicKeyCredentialRequestOptions {
    GC::Root<WebIDL::BufferSource> challenge;
    Optional<WebIDL::UnsignedLong> timeout;
    Optional<String> rp_id;
    Vector<PublicKeyCredentialDescriptor> allow_credentials = {};
    String user_verification = "preferred"_string;
    Vector<String> hints = {};
    Optional<AuthenticationExtensionsClientInputs> extensions;
};

struct CollectedClientData {
    String type;
    String challenge;
    String origin;
    Optional<bool> cross_origin;
    Optional<String> top_origin;

    // https://w3c.github.io/webauthn/#clientdatajson-serialization
    String to_json() const;
};

class PublicKeyCredentialInterface final : public CredentialInterface {
    CREDENTIAL_INTERFACE(PublicKeyCredentialInterface);

public:
    virtual String type() const override { return "public-key"_string; }
    virtual String options_member_identifier() const override { return "publicKey"_string; }
    virtual Optional<String> get_permission_policy() const override { return "publickey-credentials-get"_string; }
    virtual Optional<String> create_permission_policy() const override { return "publickey-credentials-create"_string; }

    virtual String discovery() const override { return "remote"_string; }
    virtual bool supports_conditional_user_mediation() const override
    {
        return false; // FIXME
    }

    // https://w3c.github.io/webauthn/#sctn-createCredential
    virtual JS::ThrowCompletionOr<Variant<Empty, GC::Ref<Credential>, GC::Ref<CreateCredentialAlgorithm>>> create(JS::Realm&, URL::Origin const&, CredentialCreationOptions const&, bool) const override;
};

class PublicKeyCredential final : public Credential {
    WEB_PLATFORM_OBJECT(PublicKeyCredential, Credential);
    GC_DECLARE_ALLOCATOR(PublicKeyCredential);

public:
    [[nodiscard]] static GC::Ref<PublicKeyCredential> create(JS::Realm&);

    virtual ~PublicKeyCredential() override;

    GC::Ref<JS::ArrayBuffer> raw_id() const { return JS::ArrayBuffer::create(realm(), m_raw_id); }
    GC::Ref<AuthenticatorResponse> response() const;
    Optional<String> authenticator_attachment() const;
    AuthenticationExtensionsClientOutputs get_client_extension_results() const;
    JS::Object const* to_json() const;

    String type() const override { return "public-key"_string; }
    virtual CredentialInterface const* interface() const override
    {
        return PublicKeyCredentialInterface::the();
    }

protected:
    explicit PublicKeyCredential(JS::Realm&);
    virtual void initialize(JS::Realm&) override;

private:
    ByteBuffer m_raw_id;
};

}
