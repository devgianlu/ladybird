/*
 * Copyright (c) 2026, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/CredentialManagement/Authenticator.h>

namespace Web::CredentialManagement {

Vector<Authenticator const*> s_authenticators;
Function<void(Authenticator const*)> s_on_authenticator_available;
Function<void(Authenticator const*)> s_on_authenticator_unavailable;

Vector<Authenticator const*> const& get_available_authenticators()
{
    return s_authenticators;
}

void add_authenticator(Authenticator const* authenticator)
{
    s_authenticators.append(authenticator);

    if (s_on_authenticator_available)
        s_on_authenticator_available(authenticator);
}

void remove_authenticator(Authenticator const* authenticator)
{
    s_authenticators.remove_first_matching([&](auto* it) { return it == authenticator; });

    if (s_on_authenticator_unavailable)
        s_on_authenticator_unavailable(authenticator);
}

void set_on_authenticator_available(Function<void(Authenticator const*)> callback)
{
    s_on_authenticator_available = move(callback);
}

void set_on_authenticator_unavailable(Function<void(Authenticator const*)> callback)
{
    s_on_authenticator_unavailable = move(callback);
}

}
