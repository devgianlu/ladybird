/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/CredentialManagement/CredentialsContainer.h>
#include <LibWeb/HTML/Scripting/TemporaryExecutionContext.h>
#include <LibWeb/HTML/Window.h>
#include <LibWeb/Platform/EventLoopPlugin.h>

namespace Web::CredentialManagement {

GC_DEFINE_ALLOCATOR(CredentialsContainer);

GC::Ref<CredentialsContainer> CredentialsContainer::create(JS::Realm& realm)
{
    return realm.create<CredentialsContainer>(realm);
}

CredentialsContainer::~CredentialsContainer() { }

JS::ThrowCompletionOr<GC::Ref<WebIDL::Promise>> CredentialsContainer::get(CredentialRequestOptions const&)
{
    return WebIDL::create_rejected_promise(realm(), JS::PrimitiveString::create(realm().vm(), "Not implemented"sv));
}

JS::ThrowCompletionOr<GC::Ref<WebIDL::Promise>> CredentialsContainer::store(Credential const&)
{
    return WebIDL::create_rejected_promise(realm(), JS::PrimitiveString::create(realm().vm(), "Not implemented"sv));
}

// https://w3c.github.io/webappsec-credential-management/#algorithm-same-origin-with-ancestors
static bool is_same_origin_with_its_ancestors(HTML::EnvironmentSettingsObject& settings)
{
    auto& global = settings.global_object();

    // 1. FIXME: If settings’s relevant global object has no associated Document, return false.
    // 2. Let document be settings’ relevant global object's associated Document.
    auto& document = verify_cast<HTML::Window>(global).associated_document();

    // 3. If document has no browsing context, return false.
    if (!document.browsing_context())
        return false;

    // 4. Let origin be settings’ origin.
    auto origin = settings.origin();

    // 5. Let navigable be document’s node navigable.
    auto navigable = document.navigable();

    // 6. While navigable has a non-null parent:
    while (navigable->parent()) {
        // 1. Set navigable to navigable’s parent.
        navigable = navigable->parent();

        // 2. If navigable’s active document's origin is not same origin with origin, return false.
        if (!origin.is_same_origin(navigable->active_document()->origin()))
            return false;
    }

    // 7. Return true.
    return true;
}

// https://w3c.github.io/webappsec-credential-management/#credentialrequestoptions-relevant-credential-interface-objects
template<typename OptionsType>
static Vector<GC::Ref<Credential>> relevant_credential_interface_objects(OptionsType const& options)
{
    // 1. Let settings be the current settings object.
    auto& settings = HTML::current_principal_settings_object();
    (void)settings;

    // 2. Let relevant interface objects be an empty set.
    Vector<GC::Ref<Credential>> interfaces;

    // 3. For each optionKey → optionValue of options:
    // NOTE: We cannot iterate like the spec says.
    //      1. Let credentialInterfaceObject be the Appropriate Interface Object (on settings’ global object) whose Options Member Identifier is optionKey.
    //      2. Assert: credentialInterfaceObject’s [[type]] slot equals the Credential Type whose Options Member Identifier is optionKey.
    //      3. Append credentialInterfaceObject to relevant interface objects.

#define APPEND_CREDENTIAL_INTERFACE_OBJECT(key, type_)                      \
    if (options.key.has_value()) {                                          \
        auto credential_interface_object = type_::create(settings.realm()); \
        VERIFY(credential_interface_object->type() == #key);                \
        interfaces.append(move(credential_interface_object));               \
    }

    // https://w3c.github.io/webappsec-credential-management/#credential-type-registry-appropriate-interface-object
    APPEND_CREDENTIAL_INTERFACE_OBJECT(password, PasswordCredential);
    APPEND_CREDENTIAL_INTERFACE_OBJECT(federated, FederatedCredential);
    // TODO: digital
    // TODO: identity
    // TODO: otp
    // TODO: publicKey

    // 4. Return relevant interface objects.
    return interfaces;
}

// https://w3c.github.io/webappsec-credential-management/#algorithm-create
JS::ThrowCompletionOr<GC::Ref<WebIDL::Promise>> CredentialsContainer::create(CredentialCreationOptions const& options)
{
    // 1. Let settings be the current settings object.
    auto& settings = HTML::current_principal_settings_object();

    // 2. Assert: settings is a secure context.
    VERIFY(HTML::is_secure_context(settings));

    // 3. Let global be settings’ global object.
    auto& global = settings.global_object();

    // 4. Let document be the relevant global object's associated Document.
    auto& document = verify_cast<HTML::Window>(global).associated_document();

    // 5. If document is not fully active, then return a promise rejected with an "InvalidStateError" DOMException.
    if (!document.is_fully_active())
        return WebIDL::create_rejected_promise_from_exception(realm(), WebIDL::InvalidStateError::create(realm(), "Document is not fully active"_string));

    // 6. Let sameOriginWithAncestors be true if the current settings object is same-origin with its ancestors, and false otherwise.
    auto same_origin_with_ancestors = is_same_origin_with_its_ancestors(settings);
    (void)same_origin_with_ancestors; // FIXME

    // 7. Let interfaces be the set of options’ relevant credential interface objects.
    auto interfaces = relevant_credential_interface_objects(options);

    // 8. Return a promise rejected with NotSupportedError if any of the following statements are true:
    //    FIXME: 1. global does not have an associated Document.
    //    2. interfaces’ size is greater than 1.
    if (interfaces.size() > 1)
        return WebIDL::create_rejected_promise_from_exception(realm(), WebIDL::NotSupportedError::create(realm(), "Too many crendetial types"_string));

    // 9. For each interface in interfaces:
    for (auto& interface : interfaces) {
        // 1. Let permission be the interface’s [[type]] Create Permissions Policy.
        // 2. If permission is null, continue.
        // 3. If document is not allowed to use permission, return a promise rejected with a "NotAllowedError" DOMException.

        // https://w3c.github.io/webappsec-credential-management/#credential-type-registry-create-permissions-policy
        if (interface->type() == "public-key") {
            // TODO: https://w3c.github.io/webauthn/#publickey-credentials-create-feature
            VERIFY_NOT_REACHED();
        }
    }

    // 10. If options.signal is aborted, then return a promise rejected with options.signal’s abort reason.
    if (options.signal && options.signal->aborted())
        return WebIDL::create_rejected_promise(realm(), options.signal->reason());

    // NOTE: The spec does not mention this check
    if (interfaces.size() < 1)
        return WebIDL::create_rejected_promise_from_exception(realm(), WebIDL::NotSupportedError::create(realm(), "No crendetial types"_string));

    // 11. Let type be interfaces[0]'s [[type]].
    auto type = interfaces[0]->type();

    // 12. If settings’ active credential types contains type, return a promise rejected with a "NotAllowedError" DOMException.
    if (settings.active_credential_types().contains_slow(type))
        return WebIDL::create_rejected_promise_from_exception(realm(), WebIDL::NotAllowedError::create(realm(), "Credential type is not allowed"_string));

    // 13. Append type to settings’ active credential types.
    settings.active_credential_types().append(type);

    // 14. Let origin be settings’s origin.
    auto origin = settings.origin();

    // 15. Let p be a new promise.
    auto promise = WebIDL::create_promise(realm());

    // 16. Run the following steps in parallel:
    Platform::EventLoopPlugin::the().deferred_invoke(GC::create_function(realm().heap(), [this, promise = GC::Root(promise), &global, &document, interfaces = move(interfaces), &origin, &options, same_origin_with_ancestors] {
        HTML::TemporaryExecutionContext execution_context { realm(), HTML::TemporaryExecutionContext::CallbacksEnabled::Yes };

        // 1. Let r be the result of executing interfaces[0]'s [[Create]](origin, options, sameOriginWithAncestors)
        //    internal method on origin, options, and sameOriginWithAncestors.
        auto maybe_r = interfaces[0]->internal_create(origin, options, same_origin_with_ancestors);
        // If that threw an exception:
        if (maybe_r.is_error()) {
            // 1. Let e be the thrown exception.
            auto e = maybe_r.error_value();
            // 2. Queue a task on global’s DOM manipulation task source to run the following substeps:
            queue_global_task(HTML::Task::Source::DOMManipulation, global, GC::create_function(document.heap(), [&] {
                // 1. Reject p with e.
                WebIDL::reject_promise(realm(), *promise, e);
            }));
            // 3. Terminate these substeps.
            return;
        }

        auto r = maybe_r.release_value();

        // 2. If r is a Credential or null, resolve p with r, and terminate these substeps.
        if (r.has<Empty>()) {
            WebIDL::resolve_promise(realm(), *promise, JS::js_null());
            return;
        }
        if (r.has<GC::Ref<Credential>>()) {
            auto& credential = r.get<GC::Ref<Credential>>();
            WebIDL::resolve_promise(realm(), *promise, credential);
            return;
        }

        // 3. Assert: r is an algorithm (as defined in §2.2.1.4 [[Create]] internal method).
        VERIFY(r.has<GC::Ref<CreateCredentialAlgorithm>>());

        // 4. Queue a task on global’s DOM manipulation task source to run the following substeps:
        queue_global_task(HTML::Task::Source::DOMManipulation, global, GC::create_function(document.heap(), [&] {
            auto& r_algo = r.get<GC::Ref<CreateCredentialAlgorithm>>();

            // 1. Resolve p with the result of promise-calling r given global.
            auto maybe_result = r_algo->function()(global);
            if (maybe_result.is_error()) {
                WebIDL::reject_promise(realm(), *promise, maybe_result.error_value());
                return;
            }

            auto& result = maybe_result.value();
            WebIDL::resolve_promise(realm(), *promise, result);
        }));
    }));

    // 17. React to p:
    auto on_completion = GC::create_function(realm().heap(), [&settings, &type](JS::Value) -> WebIDL::ExceptionOr<JS::Value> {
        // 1. Remove type from settings’ active credential types.
        settings.active_credential_types().remove_first_matching([&](auto& v) { return v == type; });

        return JS::js_undefined();
    });
    WebIDL::react_to_promise(*promise, on_completion, on_completion);

    // 18. Return p.
    return promise;
}

JS::ThrowCompletionOr<GC::Ref<WebIDL::Promise>> CredentialsContainer::prevent_silent_access()
{
    return WebIDL::create_rejected_promise(realm(), JS::PrimitiveString::create(realm().vm(), "Not implemented"sv));
}

CredentialsContainer::CredentialsContainer(JS::Realm& realm)
    : PlatformObject(realm)
{
}

void CredentialsContainer::initialize(JS::Realm& realm)
{
    Base::initialize(realm);
    WEB_SET_PROTOTYPE_FOR_INTERFACE(CredentialsContainer);
}

}
