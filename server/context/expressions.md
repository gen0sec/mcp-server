---
title: Rule expressions · Wirefilter WAF docs
description: "The Wirefilter WAF Rules language supports two kinds of expressions: simple and compound."
lastUpdated: 2025-08-20T21:45:15.000Z
---

The Wirefilter WAF Rules language supports two kinds of expressions: simple and compound.

## Simple expressions

**Simple expressions** compare a value from an HTTP request to a value defined in the expression. For example, this simple expression matches Microsoft Exchange Autodiscover requests:

```txt
http.request.uri.path matches "/autodiscover\.(xml|src)$"
```

Simple expressions have the following syntax:

```txt
<field> <comparison_operator> <value>
```

Where:

* [Fields](fields.md) specify properties associated with an HTTP request.

* [Comparison operators](operators.md#comparison-operators) define how values must relate to actual request data for an expression to return `true`.

* [Values](values.md) represent the data associated with fields. When evaluating a rule, the WAF compares these values with the actual data obtained from the request.

## Compound expressions

**Compound expressions** use [logical operators](operators.md#logical-operators) such as `and` to combine two or more expressions into a single expression.

For example, this expression uses the `and` operator to target requests to `www.example.com` that are not on ports 80 or 443:

```txt
http.request.host eq "www.example.com" and not http.request.port in {80 443}
```

Compound expressions have the following general syntax:

```txt
<expression> <logical_operator> <expression>
```

Compound expressions allow you to generate sophisticated, highly targeted rules.

## Maximum rule expression length

The maximum length of a rule expression is 4,096 characters.

## Additional features

You can also use the following Rules language features in your expressions:

* [Grouping symbols](operators.md#grouping-symbols) allow you to explicitly group expressions that should be evaluated together.

* [Functions](functions.md) allow you to manipulate and validate values in expressions.
