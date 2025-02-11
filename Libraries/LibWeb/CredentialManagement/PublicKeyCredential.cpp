/*
 * Copyright (c) 2026, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCrypto/Hash/HashManager.h>
#include <LibWeb/Bindings/ExceptionOrUtils.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/CredentialManagement/Authenticator.h>
#include <LibWeb/CredentialManagement/CredentialsContainer.h>
#include <LibWeb/CredentialManagement/PublicKeyCredential.h>
#include <LibWeb/DOM/Document.h>
#include <LibWeb/HTML/Window.h>
#include <LibWeb/HTML/WindowProxy.h>
#include <LibWeb/Platform/Timer.h>
#include <LibWeb/WebIDL/AbstractOperations.h>

namespace Web::CredentialManagement {

GC_DEFINE_ALLOCATOR(PublicKeyCredential);

PublicKeyCredential::~PublicKeyCredential() { }

GC::Ref<AuthenticatorResponse> PublicKeyCredential::response() const
{
    return realm().create<AuthenticatorResponse>(realm());
}

Optional<String> PublicKeyCredential::authenticator_attachment() const
{
    return { }; // TODO
}

AuthenticationExtensionsClientOutputs PublicKeyCredential::get_client_extension_results() const
{
    return AuthenticationExtensionsClientOutputs { }; // TODO
}

JS::Object const* PublicKeyCredential::to_json() const
{
    return JS::Object::create(realm(), { }); // TODO
}

PublicKeyCredential::PublicKeyCredential(JS::Realm& realm)
    : Credential(realm)
{
}

void PublicKeyCredential::initialize(JS::Realm& realm)
{
    Base::initialize(realm);
    WEB_SET_PROTOTYPE_FOR_INTERFACE(PublicKeyCredential);
}

// https://w3c.github.io/webauthn/#clientdatajson-serialization
String CollectedClientData::to_json() const
{
    return { }; // TODO
}

static bool handle_authenticator_became_available(
    Authenticator const* authenticator,
    PublicKeyCredentialCreationOptions const& pk_options,
    ReadonlyBytes client_data_hash,
    Vector<CredTypesAndPubKeyAlg> const& cred_types_and_pub_key_algs,
    HashMap<String, void*> const& authenticator_extensions)
{
    // 2. If pkOptions.authenticatorSelection is present:
    if (pk_options.authenticator_selection.has_value()) {
        // 1. If pkOptions.authenticatorSelection.authenticatorAttachment is present
        //    and its value is not equal to authenticator’s authenticator attachment modality, continue.
        if (pk_options.authenticator_selection->authenticator_attachment.has_value() && pk_options.authenticator_selection->authenticator_attachment != authenticator->attachment_modality()) {
            return false;
        }

        // 2. If pkOptions.authenticatorSelection.residentKey
        //    is present and set to required
        if (!pk_options.authenticator_selection->resident_key.has_value() && pk_options.authenticator_selection->resident_key == Bindings::ResidentKeyRequirement::Required) {
            // If the authenticator is not capable of storing a client-side discoverable public key credential source, continue.
            if (!authenticator->can_store_client_side_discoverable_public_key_credential_source())
                return false;
        }
        // is present and set to preferred or discouraged
        else if (pk_options.authenticator_selection->resident_key.has_value() && (pk_options.authenticator_selection->resident_key == Bindings::ResidentKeyRequirement::Preferred || pk_options.authenticator_selection->resident_key == Bindings::ResidentKeyRequirement::Discouraged)) {
            // No effect.
        }
        // is not present
        else {
            // if pkOptions.authenticatorSelection.requireResidentKey is set to true and the authenticator is not capable
            // of storing a client-side discoverable public key credential source, continue.
            if (pk_options.authenticator_selection->require_resident_key && !authenticator->can_store_client_side_discoverable_public_key_credential_source())
                return false;
        }
    }

    // 3. Let requireResidentKey be the effective resident key requirement for credential creation, a Boolean value, as follows:
    bool require_resident_key;

    //    If pkOptions.authenticatorSelection.residentKey
    //    is present and set to required
    if (pk_options.authenticator_selection->resident_key.has_value() && pk_options.authenticator_selection->resident_key == Bindings::ResidentKeyRequirement::Required) {
        // Let requireResidentKey be true.
        require_resident_key = true;
    }
    // is present and set to preferred
    else if (pk_options.authenticator_selection->resident_key.has_value() && pk_options.authenticator_selection->resident_key == Bindings::ResidentKeyRequirement::Preferred) {
        // If the authenticator
        // is capable of client-side credential storage modality
        if (authenticator->can_store_client_side_discoverable_public_key_credential_source()) {
            // Let requireResidentKey be true.
            require_resident_key = true;
        }
        // is not capable of client-side credential storage modality, or if the client cannot determine authenticator capability,
        else {
            // Let requireResidentKey be false.
            require_resident_key = false;
        }
    }
    // is present and set to discouraged
    else if (pk_options.authenticator_selection->resident_key.has_value() && pk_options.authenticator_selection->resident_key == Bindings::ResidentKeyRequirement::Discouraged) {
        // Let requireResidentKey be false.
        require_resident_key = false;
    }
    // is not present
    else {
        // Let requireResidentKey be the value of pkOptions.authenticatorSelection.requireResidentKey.
        require_resident_key = pk_options.authenticator_selection->require_resident_key;
    }

    // 4. Let userVerification be the effective user verification requirement for credential creation, a Boolean value, as follows.
    bool user_verification;

    // If pkOptions.authenticatorSelection.userVerification
    // is set to required
    if (pk_options.authenticator_selection->user_verification == Bindings::UserVerificationRequirement::Required) {
        // Let userVerification be true.
        user_verification = true;
    }
    // is set to preferred
    else if (pk_options.authenticator_selection->user_verification == Bindings::UserVerificationRequirement::Preferred) {
        // If the authenticator
        // is capable of user verification
        if (authenticator->is_capable_of_user_verification()) {
            // Let userVerification be true.
            user_verification = true;
        }
        // is not capable of user verification
        else {
            // Let userVerification be false.
            user_verification = false;
        }

    }
    // is set to discouraged
    else if (pk_options.authenticator_selection->user_verification == Bindings::UserVerificationRequirement::Discouraged) {
        // Let userVerification be false.
        user_verification = false;
    } else {
        VERIFY_NOT_REACHED();
    }

    // 5. Let enterpriseAttestationPossible be a Boolean value, as follows.
    bool enterprise_attestation_possible;

    // If pkOptions.attestation
    // is set to enterprise
    if (pk_options.attestation == Bindings::AttestationConveyancePreference::Enterprise) {
        // TODO: Let enterpriseAttestationPossible be true if the user agent wishes to support enterprise attestation for pkOptions.rp.id (see step 8, above). Otherwise false.
        enterprise_attestation_possible = true;
    }
    // otherwise
    else {
        // Let enterpriseAttestationPossible be false.
        enterprise_attestation_possible = false;
    }

    // 6. Let attestationFormats be a list of strings, initialized to the value of pkOptions.attestationFormats.
    auto attestation_formats = pk_options.attestation_formats;

    // 7. If pkOptions.attestation
    // is set to none
    if (pk_options.attestation == Bindings::AttestationConveyancePreference::None) {
        // Set attestationFormats be the single-element list containing the string “none”
        attestation_formats = { "none"_string };
    }

    // 8. Let excludeCredentialDescriptorList be a new list.
    Vector<PublicKeyCredentialDescriptor> exclude_credential_descriptor_list;

    // 9. For each credential descriptor C in pkOptions.excludeCredentials:
    for (auto& c : pk_options.exclude_credentials) {
        // 1. If C.transports is not empty, and authenticator is connected over a transport not mentioned in C.transports, the client MAY continue.
        if (c.transports.has_value() && !c.transports->is_empty() && !c.transports->contains_slow(authenticator->transport()))
            continue;

        // 2. Otherwise, Append C to excludeCredentialDescriptorList.
        exclude_credential_descriptor_list.append(c);
    }

    // 10. Invoke the authenticatorMakeCredential operation on authenticator with clientDataHash, pkOptions.rp, pkOptions.user,
    //     requireResidentKey, userVerification, credTypesAndPubKeyAlgs, excludeCredentialDescriptorList, enterpriseAttestationPossible,
    //     attestationFormats, and authenticatorExtensions as parameters.
    authenticator->make_credential(
        client_data_hash,
        pk_options.rp,
        pk_options.user,
        require_resident_key,
        /* FIXME: requireUserPresence */ true,
        user_verification,
        cred_types_and_pub_key_algs,
        exclude_credential_descriptor_list,
        enterprise_attestation_possible,
        attestation_formats,
        authenticator_extensions);
    return true;
}

static GC::Ref<CreateCredentialAlgorithm> handle_authenticator_success(JS::Realm& realm, ReadonlyBytes att_object, String const& client_data_json, Bindings::AttestationConveyancePreference attestation_conveyance_preference, HashMap<String, void*> const& client_extensions)
{
    struct CredentialCreationData {
        ByteBuffer attestation_object_result;
        ByteBuffer client_data_json_result;
        Bindings::AttestationConveyancePreference attestation_conveyance_preference_option;
        AuthenticationExtensionsClientOutputs client_extension_results;
    };
    // 2. Let credentialCreationData be a struct whose items are:
    //    - attestationObjectResult: whose value is the bytes returned from the successful authenticatorMakeCredential operation.
    //    - clientDataJSONResult: whose value is the bytes of clientDataJSON.
    //    - attestationConveyancePreferenceOption: whose value is the value of pkOptions.attestation.
    //    - clientExtensionResults: whose value is an AuthenticationExtensionsClientOutputs object containing
    //      extension identifier → client extension output entries. The entries are created by running each extension’s client extension
    //      processing algorithm to create the client extension outputs, for each client extension in pkOptions.extensions.
    auto credential_creation_data = CredentialCreationData {
        .attestation_object_result = MUST(ByteBuffer::copy(att_object)),
        .client_data_json_result = MUST(ByteBuffer::copy(client_data_json.bytes())),
        .attestation_conveyance_preference_option = attestation_conveyance_preference,
        .client_extension_results = AuthenticationExtensionsClientOutputs { }, // FIXME
    };

    (void)client_extensions;

    // 3. Let constructCredentialAlg be an algorithm that takes a global object global, and whose steps are:
    return GC::create_function(realm.heap(), [](JS::Object const& global) -> JS::ThrowCompletionOr<GC::Ref<Credential>> {
        (void)global;

        // TODO
        return throw_completion(WebIDL::NotAllowedError::create(*global.vm().current_realm(), "Constructing a credential from an authenticator response is not allowed"_utf16));
    });
}

// https://w3c.github.io/webauthn/#sctn-createCredential
JS::ThrowCompletionOr<Variant<Empty, GC::Ref<Credential>, GC::Ref<CreateCredentialAlgorithm>>> PublicKeyCredentialInterface::create(JS::Realm& realm, URL::Origin const& origin, CredentialCreationOptions const& options, bool same_origin_with_ancestors) const
{
    // 1. Assert: options.publicKey is present.
    VERIFY(options.public_key.has_value());

    // 2. If sameOriginWithAncestors is false:
    if (!same_origin_with_ancestors) {
        // 1. If options.mediation is present with the value conditional:
        if (options.mediation == Bindings::CredentialMediationRequirement::Conditional) {
            // 1. Throw a "NotAllowedError" DOMException
            return throw_completion(WebIDL::NotAllowedError::create(realm, "Conditional mediation is not allowed"_utf16));
        }

        auto& window = as<HTML::Window>(realm.global_object());

        // 2. If the relevant global object, as determined by the calling create() implementation, does not have transient activation:
        if (!window.has_transient_activation()) {
            // 1. Throw a "NotAllowedError" DOMException.
            return throw_completion(WebIDL::NotAllowedError::create(realm, "Transient activation is required"_utf16));
        }

        // 3. Consume user activation of the relevant global object.
        window.consume_user_activation();

        // 4. If the origin that is creating a credential is different from the top-level origin of the relevant global object
        // (i.e., is a different origin than the user can see in the address bar), the client SHOULD make this fact clear to the user.
        if (origin != HTML::relevant_settings_object(window).origin()) {
            // TODO: We don't have a UI to make this clear to the user, so we'll just print a warning in the console.
            warnln("The origin creating the credential is different from the top-level origin");
        }
    }

    // 3. Let pkOptions be the value of options.publicKey.
    auto pk_options = options.public_key.value();

    // 4. If pkOptions.timeout is present, check if its value lies within a reasonable range as defined by the client
    //    and if not, correct it to the closest value lying within that range. Set a timer lifetimeTimer to this adjusted value.
    //    If pkOptions.timeout is not present, then set lifetimeTimer to a client-specific default.
    // TODO: default, check value, etc
    auto lifetime_timer = Web::Platform::Timer::create_single_shot(realm.heap(), 10000, nullptr);

    // 5. If the length of pkOptions.user.id is not between 1 and 64 bytes (inclusive) then throw a TypeError.
    if (pk_options.user.id->byte_length() < 1 || pk_options.user.id->byte_length() > 64)
        return realm.vm().throw_completion<JS::TypeError>("user.id must be between 1 and 64 bytes"sv);

    // 6. Let callerOrigin be origin. If callerOrigin is an opaque origin, throw a "NotAllowedError" DOMException.
    auto caller_origin = origin;
    if (caller_origin.is_opaque())
        return throw_completion(WebIDL::NotAllowedError::create(realm, "Caller origin must not be opaque"_utf16));

    // 7. Let effectiveDomain be the callerOrigin’s effective domain. If effective domain is not a valid domain, then throw a "SecurityError" DOMException.
    auto effective_domain = caller_origin.effective_domain();
    if (!effective_domain.has_value())
        return throw_completion(WebIDL::SecurityError::create(realm, "Caller origin must have a valid domain"_utf16));

    // 8. If pkOptions.rp.id
    //    is present
    if (pk_options.rp.id.has_value()) {
        // FIXME: We don't support related origin requests, so we'll just hardcode this to false.
        //        https://w3c.github.io/webauthn/#sctn-related-origins
        constexpr bool supports_related_origin_requests = false;

        // If pkOptions.rp.id is not a registrable domain suffix of and is not equal to effectiveDomain, and if the client
        //    supports related origin requests
        if (!DOM::is_a_registrable_domain_suffix_of_or_is_equal_to(pk_options.rp.id.value(), effective_domain.value()) && supports_related_origin_requests) {
            // 1. Let rpIdRequested be the value of pkOptions.rp.id.
            // 2. TODO: Run the related origins validation procedure with arguments callerOrigin and rpIdRequested.
            //          If the result is false, throw a "SecurityError" DOMException.
            TODO();
        }
        // does not support related origin requests
        else {
            // throw a "SecurityError" DOMException.
            return throw_completion(WebIDL::SecurityError::create(realm, "rp.id must be a registrable domain suffix of the caller origin"_utf16));
        }
    }
    //    is not present
    else {
        // Set pkOptions.rp.id to effectiveDomain.
        pk_options.rp.id = effective_domain->serialize();
    }

    // 9. Let credTypesAndPubKeyAlgs be a new list whose items are pairs of PublicKeyCredentialType and a COSEAlgorithmIdentifier.
    auto cred_types_and_pub_key_algs = Vector<CredTypesAndPubKeyAlg> { };

    // 10. If pkOptions.pubKeyCredParams’s size
    // is zero
    if (pk_options.pub_key_cred_params.is_empty()) {
        // Append the following pairs of PublicKeyCredentialType and COSEAlgorithmIdentifier values to credTypesAndPubKeyAlgs:
        //  - public-key and -7 ("ES256").
        //  - public-key and -257 ("RS256").
        cred_types_and_pub_key_algs.append(CredTypesAndPubKeyAlg { "public-key"_string, -7 });
        cred_types_and_pub_key_algs.append(CredTypesAndPubKeyAlg { "public-key"_string, -257 });
    }
    // is non-zero
    else {
        // For each current of pkOptions.pubKeyCredParams:
        for (auto& current : pk_options.pub_key_cred_params) {
            // 1. If current.type does not contain a PublicKeyCredentialType supported by this implementation, then continue.
            if (current.type != "public-key"_string)
                continue;

            // 2. Let alg be current.alg.
            auto alg = current.alg;

            // 3. Append the pair of current.type and alg to credTypesAndPubKeyAlgs.
            cred_types_and_pub_key_algs.append(CredTypesAndPubKeyAlg { current.type, alg });
        }

        // If credTypesAndPubKeyAlgs is empty, throw a "NotSupportedError" DOMException.
        if (cred_types_and_pub_key_algs.is_empty())
            return throw_completion(WebIDL::NotSupportedError::create(realm, "No supported credential types"_utf16));
    }

    // 11. Let clientExtensions be a new map and let authenticatorExtensions be a new map.
    auto client_extensions = HashMap<String, void*> { };
    auto authenticator_extensions = HashMap<String, void*> { };

    // 12. If pkOptions.extensions is present, then for each extensionId → clientExtensionInput of pkOptions.extensions:
    if (pk_options.extensions.has_value()) {
        // TODO
    }

    // 13. Let collectedClientData be a new CollectedClientData instance whose fields are:
    auto challenge_buffer = TRY_OR_THROW_OOM(realm.vm(), WebIDL::get_buffer_source_copy(pk_options.challenge->raw_object()));
    auto challenge_buffer_base64 = TRY_OR_THROW_OOM(realm.vm(), encode_base64url(challenge_buffer));

    auto collected_client_data = CollectedClientData {
        // The string "webauthn.create".
        .type = "webauthn.create"_string,
        // The base64url encoding of pkOptions.challenge.
        .challenge = challenge_buffer_base64,
        // The serialization of callerOrigin.
        .origin = caller_origin.serialize(),
        // The inverse of the value of the sameOriginWithAncestors argument passed to this internal method.
        .cross_origin = !same_origin_with_ancestors,
        // The serialization of callerOrigin’s top-level origin if the sameOriginWithAncestors argument passed to this internal method is false, else undefined.
        .top_origin = same_origin_with_ancestors ? Optional<String> { } : caller_origin.serialize(), // FIXME: top level origin
    };

    // 14. Let clientDataJSON be the JSON-compatible serialization of client data constructed from collectedClientData.
    auto client_data_json = collected_client_data.to_json();

    // 15. Let clientDataHash be the hash of the serialized client data represented by clientDataJSON.
    //     This is the hash (computed using SHA-256) of the JSON-compatible serialization of client data, as constructed by the client.
    auto client_data_hash = ::Crypto::Hash::SHA256::hash(client_data_json);

    // 16. If options.signal is present and aborted, throw the options.signal’s abort reason.
    if (options.signal && options.signal->aborted())
        return throw_completion(options.signal->reason());

    // 17. Let issuedRequests be a new ordered set.
    auto issued_requests = Vector<Authenticator const*> { };

    // 18. Let authenticators represent a value which at any given instant is a set of client platform-specific handles,
    //     where each item identifies an authenticator presently available on this client platform at that instant.
    auto authenticators = get_available_authenticators();

    // 19. If options.mediation is present with the value conditional:
    if (options.mediation == Bindings::CredentialMediationRequirement::Conditional) {
        // 1. If the user agent has not recently mediated an authentication, the origin of said authentication is not callerOrigin,
        //    or the user does not consent to this type of credential creation, throw a "NotAllowedError" DOMException.
        // TODO
    }

    // 20. Consider the value of hints and craft the user interface accordingly, as the user-agent sees fit.
    // TODO

    // 21. Start lifetimeTimer.
    lifetime_timer->start();

    // 22. While lifetimeTimer has not expired, perform the following actions depending upon lifetimeTimer,
    //     and the state and response for each authenticator in authenticators:
    Variant<Empty, JS::Completion, GC::Ref<CreateCredentialAlgorithm>> result = Empty { };

    auto listen_for_authenticator = [&](Authenticator const* authenticator) {
        // If any authenticator indicates success,
        authenticator->set_on_success([&](auto att_object) {
            // 1. Remove authenticator from issuedRequests. This authenticator is now the selected authenticator.
            issued_requests.remove_first_matching([&](auto* it) { return it == authenticator; });

            auto construct_credential_alg = handle_authenticator_success(realm, att_object, client_data_json, pk_options.attestation, client_extensions);

            // 4. For each remaining authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove it from issuedRequests.
            issued_requests.remove_all_matching([&](auto* it) {
                it->cancel();
                return true;
            });

            // 5. Return constructCredentialAlg and terminate this algorithm.
            result = construct_credential_alg;
        });

        // If any authenticator returns a status indicating that the user cancelled the operation,
        authenticator->set_on_cancel([&] {
            // 1. Remove authenticator from issuedRequests.
            issued_requests.remove_first_matching([&](auto* it) { return it == authenticator; });

            // 2. For each remaining authenticator in issuedRequests invoke the authenticatorCancel operation
            //    on authenticator and remove it from issuedRequests.
            issued_requests.remove_all_matching([&](auto* it) {
                it->cancel();
                return true;
            });
        });

        // If any authenticator returns an error status equivalent to "InvalidStateError",
        authenticator->set_on_invalid_state([&] {
            // 1. Remove authenticator from issuedRequests.
            issued_requests.remove_first_matching([&](auto* it) { return it == authenticator; });

            // 2. For each remaining authenticator in issuedRequests invoke the authenticatorCancel operation
            //    on authenticator and remove it from issuedRequests.
            issued_requests.remove_all_matching([&](auto* it) {
                it->cancel();
                return true;
            });

            // 3. Throw an "InvalidStateError" DOMException.
            result = throw_completion(WebIDL::InvalidStateError::create(realm, "An authenticator returned an invalid state error"_utf16));
        });

        // If any authenticator returns an error status not equivalent to "InvalidStateError",
        authenticator->set_on_error([&] {
            // Remove authenticator from issuedRequests.
            issued_requests.remove_first_matching([&](auto* it) { return it == authenticator; });
        });
    };

    for (auto* authenticator : authenticators) {
        listen_for_authenticator(authenticator);
    }

    // If an authenticator becomes available on this client device,
    set_on_authenticator_available([&](Authenticator const* authenticator) {
        listen_for_authenticator(authenticator);

        // 1. This authenticator is now the candidate authenticator.
        if (handle_authenticator_became_available(authenticator, pk_options, client_data_hash.bytes(), cred_types_and_pub_key_algs, authenticator_extensions)) {
            // 11. Append authenticator to issuedRequests.
            issued_requests.append(authenticator);
        }
    });

    // If an authenticator ceases to be available on this client device,
    set_on_authenticator_unavailable([&](Authenticator const* authenticator) {
        // Remove authenticator from issuedRequests.
        issued_requests.remove_first_matching([&](auto* it) { return it == authenticator; });
    });

    while (true) {
        if (result.has<JS::Completion>()) {
            return result.get<JS::Completion>();
        }
        if (result.has<GC::Ref<CreateCredentialAlgorithm>>()) {
            return result.get<GC::Ref<CreateCredentialAlgorithm>>();
        }

        // If lifetimeTimer expires,
        if (!lifetime_timer->is_active()) {
            // For each authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator
            // and remove authenticator from issuedRequests.
            issued_requests.remove_all_matching([&](auto* it) {
                it->cancel();
                return true;
            });
            break;
        }

        // TODO: If the user exercises a user agent user-interface option to cancel the process,
        //       For each authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator
        //       and remove authenticator from issuedRequests. Throw a "NotAllowedError" DOMException.

        // If options.signal is present and aborted,
        if (options.signal && options.signal->aborted()) {
            // For each authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator
            // and remove authenticator from issuedRequests. Then throw the options.signal’s abort reason.
            issued_requests.remove_all_matching([&](auto* it) {
                it->cancel();
                return true;
            });

            return throw_completion(options.signal->reason());
        }

        sleep(1);
    }

    // 23. Throw a "NotAllowedError" DOMException.
    return throw_completion(WebIDL::NotAllowedError::create(realm, "No authenticator was able to create a credential"_utf16));
}

}
