/*
 * Copyright (c) 2026, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/JsonObject.h>
#include <LibWeb/CredentialManagement/VirtualAuthenticator.h>

namespace Web::CredentialManagement {

ErrorOr<VirtualAuthenticator*> VirtualAuthenticator::create(AuthenticatorConfiguration const& config)
{
    if (!config.protocol.has_value())
        return Error::from_string_literal("Missing protocol");

    auto protocol = config.protocol.value();
    if (protocol != "ctap1/u2f"sv && protocol != "ctap2"sv && protocol != "ctap2_1"sv)
        return Error::from_string_literal("Invalid protocol");

    if (!config.transport.has_value())
        return Error::from_string_literal("Missing transport");

    auto transport = config.transport.value();

    // https://w3c.github.io/webauthn/#enumdef-authenticatortransport
    if (transport != "usb"sv && transport != "nfc"sv && transport != "ble"sv && transport != "smart-card"sv && transport != "hybrid"sv && transport != "internal"sv)
        return Error::from_string_literal("Invalid transport");

    static u32 s_virtual_authenticators_count = 0;

    // An non-null string made using up to 48 characters from the unreserved production defined in Appendix A of [RFC3986]
    // that uniquely identifies the Virtual Authenticator.
    auto authenticator_id = TRY(String::formatted("virtual-authenticator-{}", s_virtual_authenticators_count++));

    return new VirtualAuthenticator(
        move(authenticator_id),
        move(protocol),
        move(transport),
        config.has_resident_key,
        config.has_user_verification,
        config.is_user_consenting,
        config.is_user_verified,
        config.extensions,
        config.default_backup_eligibility,
        config.default_backup_state);
}

String const& VirtualAuthenticator::attachment_modality() const
{
    return m_attachment_modality;
}

bool VirtualAuthenticator::can_store_client_side_discoverable_public_key_credential_source() const
{
    return false; // FIXME
}

bool VirtualAuthenticator::is_capable_of_user_verification() const
{
    return m_has_user_verification;
}

void VirtualAuthenticator::make_credential(
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
    HashMap<String, void*> const& extensions) const
{
    (void)hash;
    (void)rp_entity;
    (void)user_entity;
    (void)require_resident_key;
    (void)require_user_presence;
    (void)require_user_verification;
    (void)cred_types_and_pub_key_algs;
    (void)exclude_credential_descriptor_list;
    (void)enterprise_attestation_possible;
    (void)attestation_formats;
    (void)extensions;
}

void VirtualAuthenticator::cancel() const
{
}

void VirtualAuthenticator::set_on_success(Function<void(ReadonlyBytes)>) const
{
}

void VirtualAuthenticator::set_on_cancel(Function<void()>) const
{
}

void VirtualAuthenticator::set_on_invalid_state(Function<void()>) const
{
}

void VirtualAuthenticator::set_on_error(Function<void()>) const
{
}

// https://w3c.github.io/webauthn/#virtual-authenticator-database
static Vector<VirtualAuthenticator const*> s_virtual_authenticators;

void add_virtual_authenticator(VirtualAuthenticator const* authenticator)
{
    s_virtual_authenticators.append(authenticator);

    add_authenticator(authenticator);
}

bool remove_virtual_authenticator(String const& authenticator_id)
{
    return s_virtual_authenticators.remove_first_matching([&](auto const& authenticator) {
        if (authenticator->authenticator_id() != authenticator_id)
            return false;

        remove_authenticator(authenticator);
        return true;
    });
}

}
