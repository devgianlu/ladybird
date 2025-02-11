/*
 * Copyright (c) 2026, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/CredentialManagement/Authenticator.h>
#include <LibWeb/CredentialManagement/PublicKeyCredential.h>

namespace Web::CredentialManagement {

// https://w3c.github.io/webauthn/#sctn-automation-virtual-authenticators
class WEB_API VirtualAuthenticator : public Authenticator {
public:
    ~VirtualAuthenticator() override = default;

    static ErrorOr<VirtualAuthenticator*> create(AuthenticatorConfiguration const&);

    String const& authenticator_id() const { return m_authenticator_id; }
    String const& protocol() const override { return m_protocol; }
    String const& transport() const override { return m_transport; }

    String const& attachment_modality() const override;
    bool can_store_client_side_discoverable_public_key_credential_source() const override;
    bool is_capable_of_user_verification() const override;
    void make_credential(ReadonlyBytes hash, PublicKeyCredentialRpEntity const& rp_entity, PublicKeyCredentialUserEntity const& user_entity, bool require_resident_key, bool require_user_presence, bool require_user_verification, Vector<CredTypesAndPubKeyAlg> cred_types_and_pub_key_algs, Vector<PublicKeyCredentialDescriptor> const& exclude_credential_descriptor_list, bool enterprise_attestation_possible, Vector<String> const& attestation_formats, HashMap<String, void*> const& extensions) const override;
    void cancel() const override;

    void set_on_success(Function<void(ReadonlyBytes)>) const override;
    void set_on_cancel(Function<void()>) const override;
    void set_on_invalid_state(Function<void()>) const override;
    void set_on_error(Function<void()>) const override;

protected:
    VirtualAuthenticator(
        String authenticator_id,
        String protocol,
        String transport,
        bool has_resident_key,
        bool has_user_verification,
        bool is_user_consenting,
        bool is_user_verified,
        Vector<String> extensions,
        bool default_backup_eligibility,
        bool default_backup_state)
        : m_authenticator_id(move(authenticator_id))
        , m_protocol(move(protocol))
        , m_transport(move(transport))
        , m_has_resident_key(has_resident_key)
        , m_has_user_verification(has_user_verification)
        , m_is_user_consenting(is_user_consenting)
        , m_is_user_verified(is_user_verified)
        , m_extensions(move(extensions))
        , m_default_backup_eligibility(default_backup_eligibility)
        , m_default_backup_state(default_backup_state)
        , m_attachment_modality(MUST(String::from_byte_string("platform"))) // FIXME
    {
    }

private:
    String m_authenticator_id;
    String m_protocol;
    String m_transport;
    bool m_has_resident_key;
    bool m_has_user_verification;
    bool m_is_user_consenting;
    bool m_is_user_verified;
    Vector<String> m_extensions;
    bool m_default_backup_eligibility;
    bool m_default_backup_state;

    String m_attachment_modality; // FIXME
};

WEB_API void add_virtual_authenticator(VirtualAuthenticator const*);
WEB_API bool remove_virtual_authenticator(String const& authenticator_id);

}
