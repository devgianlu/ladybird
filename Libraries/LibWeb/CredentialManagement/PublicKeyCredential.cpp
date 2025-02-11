/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "CredentialsContainer.h"

#include <LibCrypto/Hash/HashManager.h>
#include <LibWeb/Bindings/ExceptionOrUtils.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/CredentialManagement/PublicKeyCredential.h>
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
    return {};
}

AuthenticationExtensionsClientOutputs PublicKeyCredential::get_client_extension_results() const
{
    return AuthenticationExtensionsClientOutputs {};
}

JS::Object const* PublicKeyCredential::to_json() const
{
    return JS::Object::create(realm(), {});
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
    return {}; // FIXME
}

// https://w3c.github.io/webauthn/#sctn-createCredential
JS::ThrowCompletionOr<Variant<Empty, GC::Ref<Credential>, GC::Ref<CreateCredentialAlgorithm>>> PublicKeyCredentialInterface::create(JS::Realm& realm, URL::Origin const& origin, CredentialCreationOptions const& options, bool same_origin_with_ancestors) const
{
    // 1. Assert: options.publicKey is present.
    VERIFY(options.public_key.has_value());

    // 2. If sameOriginWithAncestors is false:
    if (!same_origin_with_ancestors) {
        // TODO
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
        return realm.vm().throw_completion<JS::TypeError>("Caller origin must not be opaque"sv);

    // 7. Let effectiveDomain be the callerOrigin’s effective domain. If effective domain is not a valid domain, then throw a "SecurityError" DOMException.
    auto effective_domain = caller_origin.effective_domain();
    if (!effective_domain.has_value())
        return throw_completion(WebIDL::SecurityError::create(realm, "Caller origin must have a valid domain"_utf16));

    // 8. If pkOptions.rp.id
    //    is present
    if (pk_options.rp.id.has_value()) {
        // If pkOptions.rp.id is not a registrable domain suffix of and is not equal to effectiveDomain, and if the client
        //    supports related origin requests
        if (false) {
            // 1. Let rpIdRequested be the value of pkOptions.rp.id.
            // 2. Run the related origins validation procedure with arguments callerOrigin and rpIdRequested. If the result is false, throw a "SecurityError" DOMException.
            // TODO
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
    struct CredTypesAndPubKeyAlg {
        String type;
        COSEAlgorithmIdentifier alg;
    };
    auto cred_types_and_pub_key_algs = Vector<CredTypesAndPubKeyAlg> {};

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
            // TODO: 1. If current.type does not contain a PublicKeyCredentialType supported by this implementation, then continue.

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
    // TODO

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
        .top_origin = same_origin_with_ancestors ? Optional<String> {} : caller_origin.serialize(), // FIXME: top level origin
    };

    // 14. Let clientDataJSON be the JSON-compatible serialization of client data constructed from collectedClientData.
    auto client_data_json = collected_client_data.to_json();

    // 15. Let clientDataHash be the hash of the serialized client data represented by clientDataJSON.
    //     This is the hash (computed using SHA-256) of the JSON-compatible serialization of client data, as constructed by the client.
    auto client_data_hash = ::Crypto::Hash::SHA256::hash(client_data_json);
    (void)client_data_hash;

    // 16. If options.signal is present and aborted, throw the options.signal’s abort reason.
    if (options.signal && options.signal->aborted())
        return throw_completion(options.signal->reason());

    // 17. Let issuedRequests be a new ordered set.
    // TODO

    // 18. Let authenticators represent a value which at any given instant is a set of client platform-specific handles,
    //     where each item identifies an authenticator presently available on this client platform at that instant.
    // TODO

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
    while (lifetime_timer->is_active()) {
        // TODO
    }

    // 23. Throw a "NotAllowedError" DOMException.
    return throw_completion(WebIDL::NotAllowedError::create(realm, "????"_utf16));
}

}
