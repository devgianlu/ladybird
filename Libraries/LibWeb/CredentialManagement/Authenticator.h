/*
 * Copyright (c) 2026, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/CredentialManagement/PublicKeyCredential.h>

namespace Web::CredentialManagement {

// https://w3c.github.io/webauthn/#public-key-credential-source
class PublicKeyCredentialSource {
};

struct CredTypesAndPubKeyAlg {
    String type;
    COSEAlgorithmIdentifier alg;
};

// https://w3c.github.io/webauthn/#sctn-authenticator-taxonomy
class WEB_API Authenticator {
public:
    virtual ~Authenticator() = default;

    virtual String const& protocol() const = 0;

    virtual String const& transport() const = 0;

    // https://w3c.github.io/webauthn/#authenticator-attachment-modality
    virtual String const& attachment_modality() const = 0;

    // https://w3c.github.io/webauthn/#client-side-discoverable-public-key-credential-source
    virtual bool can_store_client_side_discoverable_public_key_credential_source() const = 0;

    // https://w3c.github.io/webauthn/#user-verification
    virtual bool is_capable_of_user_verification() const = 0;

    // https://w3c.github.io/webauthn/#sctn-op-make-cred
    virtual void make_credential(
        ReadonlyBytes hash,
        PublicKeyCredentialRpEntity const& rp_entity,
        PublicKeyCredentialUserEntity const& user_entity,
        bool require_resident_key,
        bool require_user_presence,
        bool require_user_verification,
        Vector<CredTypesAndPubKeyAlg> cred_types_and_pub_key_algs,
        Vector<PublicKeyCredentialDescriptor> const& exclude_credential_descriptor_list,
        bool enterprise_attestation_possible,
        Vector<String> const& attestation_formats,
        HashMap<String, void*> const& extensions) const = 0;

    // https://w3c.github.io/webauthn/#sctn-op-cancel
    virtual void cancel() const = 0;

    virtual void set_on_success(Function<void(ReadonlyBytes)>) const = 0;
    virtual void set_on_cancel(Function<void()>) const = 0;
    virtual void set_on_invalid_state(Function<void()>) const = 0;
    virtual void set_on_error(Function<void()>) const = 0;
};

WEB_API Vector<Authenticator const*> const& get_available_authenticators();
WEB_API void add_authenticator(Authenticator const*);
WEB_API void remove_authenticator(Authenticator const*);
WEB_API void set_on_authenticator_available(Function<void(Authenticator const*)>);
WEB_API void set_on_authenticator_unavailable(Function<void(Authenticator const*)>);

}
