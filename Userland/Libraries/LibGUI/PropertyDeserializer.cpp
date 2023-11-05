/*
 * Copyright (c) 2023, Dan Klishch <danilklishch@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "PropertyDeserializer.h"
#include <AK/JsonObject.h>
#include <AK/String.h>
#include <LibGfx/Rect.h>

namespace GUI {

template<>
ErrorOr<bool> PropertyDeserializer<bool>::operator()(JsonValue const& value) const
{
    if (value.is_bool())
        return value.as_bool();
    return Error::from_string_literal("Boolean is expected");
}

template<>
ErrorOr<String> PropertyDeserializer<String>::operator()(JsonValue const& value) const
{
    if (value.is_string()) {
        // FIXME: Port JsonValue to the new String class.
        return String::from_deprecated_string(value.as_string());
    }
    return Error::from_string_literal("UTF-8 string is expected");
}

template<>
ErrorOr<DeprecatedString> PropertyDeserializer<DeprecatedString>::operator()(JsonValue const& value) const
{
    if (value.is_string())
        return value.as_string();
    return Error::from_string_literal("String is expected");
}

template<>
ErrorOr<Gfx::IntRect> PropertyDeserializer<Gfx::IntRect>::operator()(JsonValue const& value) const
{
    if (!value.is_object() && !(value.is_array() && value.as_array().size() == 4))
        return Error::from_string_literal("An array with 4 integers or an object is expected");

    Gfx::IntRect rect;

    Optional<int> x;
    Optional<int> y;
    Optional<int> width;
    Optional<int> height;

    if (value.is_object()) {
        auto const& object = value.as_object();

        if (object.size() != 4 || !object.has("x"sv) || !object.has("y"sv) || !object.has("width"sv) || !object.has("height"sv))
            return Error::from_string_literal("Object with keys \"x\", \"y\", \"width\", and \"height\" is expected");

        x = object.get_i32("x"sv);
        y = object.get_i32("y"sv);
        width = object.get_i32("width"sv);
        height = object.get_i32("height"sv);
    } else {
        auto const& array = value.as_array();

        auto get_i32 = [](JsonValue const& value) -> Optional<int> {
            if (value.is_integer<i32>())
                return value.to_i32();
            return {};
        };

        x = get_i32(array[0]);
        y = get_i32(array[1]);
        width = get_i32(array[2]);
        height = get_i32(array[3]);
    }

    if (!x.has_value())
        return Error::from_string_literal("X coordinate must be an integer");
    if (!y.has_value())
        return Error::from_string_literal("Y coordinate must be an integer");
    if (!width.has_value())
        return Error::from_string_literal("Width must be an integer");
    if (!height.has_value())
        return Error::from_string_literal("Height must be an integer");

    rect.set_x(x.value());
    rect.set_y(y.value());
    rect.set_width(width.value());
    rect.set_height(height.value());

    return rect;
}

template<>
ErrorOr<Gfx::IntSize> PropertyDeserializer<Gfx::IntSize>::operator()(JsonValue const& value) const
{
    if (!value.is_array() || value.as_array().size() != 2)
        return Error::from_string_literal("Expected array with 2 integers");

    auto const& array = value.as_array();

    auto const& width = array[0];
    if (!width.is_integer<i32>())
        return Error::from_string_literal("Width must be an integer");
    auto const& height = array[1];
    if (!height.is_integer<i32>())
        return Error::from_string_literal("Height must be an integer");

    Gfx::IntSize size;
    size.set_width(width.to_i32());
    size.set_height(height.to_i32());

    return size;
}

};