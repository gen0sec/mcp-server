---
title: Actions reference · Wirefilter WAF docs
description: Learn about actions supported by the WAF Rules language, including Block, Challenge, RateLimit, and Allow.
lastUpdated: 2025-11-27T11:05:45.000Z
---

The action of a rule tells the WAF how to handle matches for the rule [expression](expressions.md).

## Supported actions

The table below lists the actions available in the WAF Rules language.

Some actions like *Block* and *Challenge*, called terminating actions, will stop the evaluation of the remaining rules. The *RateLimit* action may also terminate evaluation depending on the rate limit configuration.

| Action | API Value | Description | Terminating action? |
| - | - | - | - |
| **Block** | `block` | Matching requests are denied access to the site. The HTTP status code returned is typically `403` (Forbidden). | Yes |
| **Challenge** | `challenge` | Useful for ensuring that the visitor accessing the site is human, not automated. The client that made the request must pass an interactive challenge. If successful, the WAF accepts the matched request; otherwise, it is blocked. | Yes |
| **RateLimit** | `ratelimit` | Applies rate limiting to matching requests based on the configured rate limit settings. The rate limit configuration specifies the time period and maximum number of requests allowed. When the rate limit is exceeded, requests may be blocked or challenged. | Yes (when rate limit exceeded) |
| **Allow** | `allow` | Matching requests are allowed to proceed without any action. This is the default action when no rules match. | No |

## Action Details

### Block Action

The Block action denies access to matching requests. When a rule with the Block action matches:

* The request is immediately terminated
* An HTTP response with status code `403` (Forbidden) is typically returned
* No further rules are evaluated
* The response may include custom error content

Example rule expression with Block action:

```txt
http.request.method eq "POST" and http.request.path contains "/admin" and threat.score gt 50
```

Action: `block`

### Challenge Action

The Challenge action requires the client to complete an interactive challenge before proceeding. When a rule with the Challenge action matches:

* The request is temporarily held
* An interactive challenge is presented to the client
* If the challenge is passed, the request proceeds normally
* If the challenge fails, the request is blocked
* No further rules are evaluated after a successful challenge

Example rule expression with Challenge action:

```txt
threat.score gt 30 and threat.score le 50
```

Action: `challenge`

### RateLimit Action

The RateLimit action applies rate limiting to matching requests. When a rule with the RateLimit action matches:

* The request is evaluated against the rate limit configuration
* The rate limit configuration specifies:
  * `period`: Time period in seconds
  * `requests`: Maximum number of requests allowed in the period
* If the rate limit is not exceeded, the request proceeds
* If the rate limit is exceeded, the request may be blocked or challenged (depending on configuration)
* Rate limits are typically tracked per IP address or other identifier

Example rule expression with RateLimit action:

```txt
http.request.path contains "/api"
```

Action: `ratelimit`

Rate limit configuration example:

```json
{
  "period": 60,
  "requests": 100
}
```

This configuration allows 100 requests per 60 seconds (1 minute).

### Allow Action

The Allow action explicitly allows matching requests to proceed. When a rule with the Allow action matches:

* The request proceeds normally
* No blocking or challenging occurs
* Further rules may still be evaluated (depending on rule ordering)

Example rule expression with Allow action:

```txt
ip.src.country eq "US" and threat.score lt 10
```

Action: `allow`

## Rule Evaluation Order

Rules are evaluated in the order they are defined. When a rule matches:

1. If the action is a terminating action (Block, Challenge, or RateLimit when exceeded), rule evaluation stops
2. If the action is Allow, evaluation may continue to check for other rules
3. The first matching rule with a terminating action determines the final outcome

## Best Practices

* Use **Allow** actions for whitelisting trusted sources or low-risk requests
* Use **Challenge** for suspicious but not clearly malicious requests
* Use **Block** for clearly malicious requests or high threat scores
* Use **RateLimit** to protect against abuse and DDoS attacks
* Order rules from most specific to least specific
* Place Allow rules before Block rules when you want to whitelist specific cases
