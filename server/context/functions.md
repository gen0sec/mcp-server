---
title: Functions reference · Wirefilter WAF docs
description: "The Wirefilter WAF Rules language provides functions for manipulating and validating values in an expression:"
lastUpdated: 2025-09-26T09:26:45.000Z
---

The Wirefilter WAF Rules language provides functions for manipulating and validating values in an expression:

* [Transformation functions](#transformation-functions) manipulate values extracted from an HTTP request.
* [Array functions](#array-functions) operate on arrays of values.

## Transformation functions

The Rules language supports several functions that transform values extracted from HTTP requests. A common use case for transformation functions is the conversion of a string of characters to uppercase or lowercase, since by default, string evaluation is case-sensitive.

For example, the `lower()` function converts all uppercase characters in a string to lowercase.

In the expression below, the `lower()` function transforms `http.request.host` values to lowercase so that they match the target value `"www.example.com"`:

```txt
lower(http.request.host) == "www.example.com"
```

Transformation functions that do not take arrays as an argument type require the `[*]` index notation for array access.

The Rules language supports these transformation functions:

### `any`

`any(Array<Boolean>)`: Boolean

Returns `true` when the comparison operator in the argument returns `true` for *any* of the values in the argument array. Returns `false` otherwise.

Example:

```txt
any(url_decode(http.request.body.form.values[*])[*] contains "an xss attack")
```

### `all`

`all(Array<Boolean>)`: Boolean

Returns `true` when the comparison operator in the argument returns `true` for *all* values in the argument array. Returns `false` otherwise.

Example:

```txt
all(http.request.headers["content-type"][*] == "application/json")
```

### `cidr`

`cidr(address IP address, network String)`: Boolean

Checks if an IP address is within a CIDR network range. The `address` parameter must be a field (cannot be a literal String). The `network` parameter must be a CIDR notation string (e.g., "192.168.0.0/24").

Examples:

* If `ip.src` is `192.168.1.100`, `cidr(ip.src, "192.168.0.0/16")` will return `true`.
* If `ip.src` is `10.0.0.1`, `cidr(ip.src, "192.168.0.0/16")` will return `false`.

### `concat`

`concat(String | Bytes | Array)`: String | Array

Takes a comma-separated list of values. Concatenates the argument values into a single String or array.

The return type depends on the type of input arguments. For example, if you concatenate arrays, the function will return an array.

For example, `concat("String1", " ", "String", "2")` will return `"String1 String2"`.

### `decode_base64`

`decode_base64(source String)`: String

Decodes a Base64-encoded String specified in `source`.

`source` must be a field, that is, it cannot be a literal String.

For example, with the following HTTP request header: `client_id: MTIzYWJj`, `(any(decode_base64(http.request.headers["client_id"][*])[*] eq "123abc"))` would return `true`.

### `ends_with`

`ends_with(source String, substring String)`: Boolean

Returns `true` when the source ends with a given substring. Returns `false` otherwise. The source cannot be a literal value (like `"foo"`).

For example, if `http.request.path` is `"/welcome.html"`, then `ends_with(http.request.path, ".html")` will return `true`.

### `json_lookup_integer`

`json_lookup_integer(field String, key String | Integer, key String | Integer optional, ...)`: Integer

Returns the integer value associated with the supplied `key` in `field`.

The `field` must be a string representation of a valid JSON document.

The `key` can be an attribute name, a zero-based position number in a JSON array, or a combination of these two options (as extra function parameters), while following the hierarchy of the JSON document to obtain a specific integer value.

Examples:

* Given the following JSON object contained in the `http.request.body` field:\
  `{ "record_id": "aed53a", "version": 2 }`\
  Then `json_lookup_integer(http.request.body, "version")` will return `2`.

* Given the following nested object:\
  `{ "product": { "id": 356 } }`\
  Then `json_lookup_integer(http.request.body, "product", "id")` will return `356`.

* Given the following JSON array at the root level:\
  `["first_item", -234]`\
  Then `json_lookup_integer(http.request.body, 1)` will return `-234`.

### `json_lookup_string`

`json_lookup_string(field String, key String | Integer, key String | Integer optional, ...)`: String

Returns the string value associated with the supplied `key` in `field`.

The `field` must be a string representation of a valid JSON document.

The `key` can be an attribute name, a zero-based position number in a JSON array, or a combination of these two options (as extra function parameters), while following the hierarchy of the JSON document to obtain a specific value.

Examples:

* Given the following JSON object contained in the `http.request.body` field:\
  `{ "company": "example", "product": "waf" }`\
  Then `json_lookup_string(http.request.body, "company") == "example"` will return `true`.

* Given the following nested object:\
  `{ "network": { "name": "example" } }`\
  Then `json_lookup_string(http.request.body, "network", "name") == "example"` will return `true`.

### `len`

`len(String | Bytes | Array)`: Integer

Returns the byte length of a String or Bytes value, or the number of elements in an array.

For example, if the value of `http.request.host` is `"example.com"`, then `len(http.request.host)` will return `11`.

### `lower`

`lower(String)`: String

Converts a string field to lowercase. Only uppercase ASCII bytes are converted. All other bytes are unaffected.

For example, if `http.request.host` is `"WWW.EXAMPLE.COM"`, then `lower(http.request.host) == "www.example.com"` will return `true`.

### `remove_bytes`

`remove_bytes(Bytes)`: Bytes

Returns a new byte array with all the occurrences of the given bytes removed.

For example, if `http.request.host` is `"www.example.com"`, then `remove_bytes(http.request.host, "\x2e\x77")` will return `"examplecom"`.

### `remove_query_args`

`remove_query_args(field String, query_param1 String, query_param2 String, ...)`: String

Removes one or more query string parameters from a URI query string. Returns a string without the specified parameters.

The `field` must be `http.request.uri.query` and cannot be a literal value such as `"search=foo&order=asc"`.

The `remove_query_args()` function will remove all specified parameters (as `query_param1`, `query_param2`, etc.), including repeated occurrences of the same parameter.

The ordering of unaffected query parameters will be preserved.

Examples:

```txt
// If http.request.uri.query is "order=asc&country=GB":
remove_query_args(http.request.uri.query, "country")  will return "order=asc"
remove_query_args(http.request.uri.query, "order")    will return "country=GB"
remove_query_args(http.request.uri.query, "search")   will return "order=asc&country=GB" (unchanged)

// If http.request.uri.query is "category=Foo&order=desc&category=Bar":
remove_query_args(http.request.uri.query, "order")    will return "category=Foo&category=Bar"
remove_query_args(http.request.uri.query, "category") will return "order=desc"
```

### `starts_with`

`starts_with(source String, substring String)`: Boolean

Returns `true` when the source starts with a given substring. Returns `false` otherwise. The source cannot be a literal value (like `"foo"`).

For example, if `http.request.path` is `"/blog/first-post"`, then `starts_with(http.request.path, "/blog")` will return `true`.

### `substring`

`substring(field String | Bytes, start Integer, end Integer optional)`: String

Returns part of the `field` value (the value of a String or Bytes field) from the `start` byte index up to (but excluding) the `end` byte index. The first byte in `field` has index `0`. If you do not provide the optional `end` index, the function returns the part of the string from `start` index to the end of the string.

The `start` and `end` indexes can be negative integer values, which allows you to access characters from the end of the string instead of the beginning.

Examples:

```txt
// If http.request.body is "asdfghjk":
substring(http.request.body, 2, 5)   will return "dfg"
substring(http.request.body, 2)      will return "dfghjk"
substring(http.request.body, -2)     will return "jk"
substring(http.request.body, 0, -2)  will return "asdfgh"
```

### `to_string`

`to_string(Integer | Boolean | IP address)`: String

Returns the string representation of an Integer, Boolean, or IP address value.

Examples:

```txt
// If threat.score is 5:
to_string(threat.score)   will return "5"

// If ip.src is 192.168.1.1:
to_string(ip.src)        will return "192.168.1.1"
```

### `upper`

`upper(String)`: String

Converts a string field to uppercase. Only lowercase ASCII bytes are converted. All other bytes are unaffected.

For example, if `http.request.host` is `"www.example.com"`, then `upper(http.request.host)` will return `"WWW.EXAMPLE.COM"`.

### `url_decode`

`url_decode(source String)`: String

Decodes a URL-formatted string defined in `source`, as in the following:

* `%20` and `+` decode to a space character (` `).
* `%E4%BD` decodes to `ä½`.

The `source` must be a field, that is, it cannot be a literal string.

Examples:

```txt
url_decode("John%20Doe")   will return "John Doe"
url_decode("John+Doe")     will return "John Doe"
url_decode("%2520")        will return "%20"

// Using url_decode() with the any() function:
any(url_decode(http.request.body.form.values[*])[*] contains "an xss attack")
```

### `uuid4`

`uuid4(source Bytes)`: String

Generates a random UUIDv4 (Universally Unique Identifier, version 4) based on the given argument (a source of randomness).

For example, `uuid4(http.request.body_sha256)` will return a UUIDv4 similar to `49887398-6bcf-485f-8899-f15dbef4d1d5`.

### `wildcard_replace`

`wildcard_replace(source Bytes, wildcard_pattern Bytes, replacement Bytes, flags Bytes optional)`: String

Replaces a `source` string, matched by a literal with zero or more `*` wildcard metacharacters, with a replacement string, returning the result. The replacement string can contain references to wildcard capture groups (for example, `${1}` and `${2}`), up to eight replacement references.

If there is no match, the function will return `source` unchanged.

The `source` parameter must be a field (it cannot be a literal string). Additionally, the entire `source` value must match the `wildcard_pattern` parameter (it cannot match only part of the field value).

To enter a literal `*` character in the `wildcard_pattern` parameter, you must escape it using `\*`. Additionally, you must also escape `\` using `\\`. Two unescaped `*` characters in a row (`**`) in this parameter are considered invalid and cannot be used.

To enter a literal `$` character in the `replacement` parameter, you must escape it using `$$`.

To perform case-sensitive wildcard matching, set the `flags` parameter to `"s"`.

This function uses lazy matching, that is, it tries to match each `*` metacharacter with the shortest possible string.

Examples:

* If the full URI is `https://apps.example.com/calendar/admin?expand=true`,\
  `wildcard_replace(http.request.uri, "https://*.example.com/*/*", "https://example.com/${1}/${2}/${3}")` will return `https://example.com/apps/calendar/admin?expand=true`

* If the URI path is `/calendar`,\
  `wildcard_replace(http.request.path, "/*", "/apps/${1}")` will return `/apps/calendar`.

* If the URI path is `/Apps/calendar`,\
  `wildcard_replace(http.request.path, "/apps/*", "/${1}")` will return `/calendar` (case-insensitive match by default).

* If the URI path is `/Apps/calendar`,\
  `wildcard_replace(http.request.path, "/apps/*", "/${1}", "s")` will return `/Apps/calendar` (unchanged value) because there is no case-sensitive match.

## Array functions

### `any`

See [Transformation functions](#any) above.

### `all`

See [Transformation functions](#all) above.
