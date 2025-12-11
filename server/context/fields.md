---
title: Fields reference · Wirefilter WAF docs
description: "The Wirefilter WAF Rules language supports different types of fields such as:"
lastUpdated: 2025-01-17T12:22:49.000Z
---

The Wirefilter WAF Rules language supports different types of fields such as:

* Request fields that represent the basic properties of incoming requests, including specific fields for accessing request headers, URI components, and the request body.
* IP and threat intelligence fields that represent computed or derived values related to threat intelligence about an HTTP request.
* Signal fields that represent network fingerprinting data (JA4, JA4H, JA4T, JA4L, JA4S, JA4X).

## HTTP Request Fields

These fields represent properties of incoming HTTP requests:

| Field | Type | Description |
|-------|------|-------------|
| `http.request.method` | Bytes | HTTP request method (GET, POST, etc.) |
| `http.request.scheme` | Bytes | Request scheme (http, https) |
| `http.request.host` | Bytes | Host header value |
| `http.request.port` | Int | Port number (default: 80 for http, 443 for https) |
| `http.request.path` | Bytes | URI path component |
| `http.request.uri` | Bytes | Full URI including path and query |
| `http.request.query` | Bytes | Query string component |
| `http.request.user_agent` | Bytes | User-Agent header value |
| `http.request.content_type` | Bytes | Content-Type header value |
| `http.request.content_length` | Int | Content-Length header value or body size |
| `http.request.body` | Bytes | Request body content |
| `http.request.body_sha256` | Bytes | SHA256 hash of request body (hex encoded) |
| `http.request.headers` | Map(Array(Bytes)) | Map of header names (lowercase) to arrays of header values |

## IP and Threat Intelligence Fields

These fields represent information about the source IP address and threat intelligence:

| Field | Type | Description |
|-------|------|-------------|
| `ip.src` | Ip | Source IP address |
| `ip.src.country` | Bytes | Source IP country code |
| `ip.src.asn` | Int | Source IP ASN number |
| `ip.src.asn_org` | Bytes | Source IP ASN organization name |
| `ip.src.asn_country` | Bytes | Source IP ASN country code |
| `threat.score` | Int | Threat intelligence score (0-100) |
| `threat.advice` | Bytes | Threat intelligence advice/recommendation |

## Signal Fields (Network Fingerprinting)

These fields represent JA4+ network fingerprinting data:

### JA4 Fields
| Field | Type | Description |
|-------|------|-------------|
| `signal.ja4` | Bytes | JA4 TLS fingerprint |
| `signal.ja4_raw` | Bytes | JA4 raw fingerprint |
| `signal.ja4_unsorted` | Bytes | JA4 unsorted fingerprint |
| `signal.ja4_raw_unsorted` | Bytes | JA4 raw unsorted fingerprint |

### TLS Fields
| Field | Type | Description |
|-------|------|-------------|
| `signal.tls_version` | Bytes | TLS version |
| `signal.cipher_suite` | Bytes | TLS cipher suite |
| `signal.sni` | Bytes | Server Name Indication |
| `signal.alpn` | Bytes | Application-Layer Protocol Negotiation |

### JA4H Fields (HTTP Fingerprinting)
| Field | Type | Description |
|-------|------|-------------|
| `signal.ja4h` | Bytes | JA4H HTTP fingerprint |
| `signal.ja4h_method` | Bytes | HTTP method used in fingerprint |
| `signal.ja4h_version` | Bytes | HTTP version (HTTP/1.0, HTTP/1.1, HTTP/2.0) |
| `signal.ja4h_has_cookie` | Int | Whether request has Cookie header (0 or 1) |
| `signal.ja4h_has_referer` | Int | Whether request has Referer header (0 or 1) |
| `signal.ja4h_header_count` | Int | Number of headers in request |
| `signal.ja4h_language` | Bytes | Language from Accept-Language header |

### JA4T Fields (TCP Fingerprinting)
| Field | Type | Description |
|-------|------|-------------|
| `signal.ja4t` | Bytes | JA4T TCP fingerprint |
| `signal.ja4t_window_size` | Int | TCP window size |
| `signal.ja4t_ttl` | Int | TCP TTL value |
| `signal.ja4t_mss` | Int | TCP Maximum Segment Size |
| `signal.ja4t_window_scale` | Int | TCP window scale factor |

### JA4L Fields (TLS Handshake Timing)
| Field | Type | Description |
|-------|------|-------------|
| `signal.ja4l_client` | Bytes | JA4L client fingerprint |
| `signal.ja4l_server` | Bytes | JA4L server fingerprint |
| `signal.ja4l_syn_time` | Int | SYN packet timestamp |
| `signal.ja4l_synack_time` | Int | SYN-ACK packet timestamp |
| `signal.ja4l_ack_time` | Int | ACK packet timestamp |
| `signal.ja4l_ttl_client` | Int | Client TTL value |
| `signal.ja4l_ttl_server` | Int | Server TTL value |

### JA4S Fields (TLS Session)
| Field | Type | Description |
|-------|------|-------------|
| `signal.ja4s` | Bytes | JA4S TLS session fingerprint |
| `signal.ja4s_proto` | Bytes | Protocol version |
| `signal.ja4s_version` | Bytes | TLS version |
| `signal.ja4s_cipher` | Int | Cipher suite ID |
| `signal.ja4s_alpn` | Bytes | ALPN value |

### JA4X Fields (TLS Certificate)
| Field | Type | Description |
|-------|------|-------------|
| `signal.ja4x` | Bytes | JA4X certificate fingerprint |
| `signal.ja4x_issuer_rdns` | Bytes | Certificate issuer RDN sequence |
| `signal.ja4x_subject_rdns` | Bytes | Certificate subject RDN sequence |
| `signal.ja4x_extensions` | Bytes | Certificate extensions |

## Field Access Examples

### Accessing HTTP Request Fields
```txt
http.request.method eq "POST"
http.request.path contains "/admin"
http.request.host == "example.com"
```

### Accessing Headers
```txt
http.request.headers["user-agent"][*] contains "bot"
http.request.headers["content-type"][0] == "application/json"
```

### Accessing IP and Threat Fields
```txt
ip.src.country eq "US"
ip.src.asn in {12345 67890}
threat.score gt 50
```

### Accessing Signal Fields
```txt
signal.ja4h_version == "HTTP/1.1"
signal.ja4h_has_cookie == 1
starts_with(signal.ja4h, "ge11")
```

## Notes

* All header names in `http.request.headers` are normalized to lowercase
* String fields are case-sensitive by default
* IP addresses can be IPv4 or IPv6
* Signal fields may be empty strings if the corresponding data is not available
* Integer fields default to 0 if data is not available
