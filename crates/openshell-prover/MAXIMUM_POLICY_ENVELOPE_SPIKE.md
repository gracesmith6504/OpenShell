<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Maximum Policy Envelope Spike

This spike tests whether OpenShell can compare a candidate policy against a
security-approved maximum policy and reject any candidate that allows more than
the maximum.

Core check:

```text
exists x:
  candidate_allows(x)
  AND NOT maximum_allows(x)
```

Rust normalizes schema-level OpenShell policy semantics, such as access presets
and unsupported field detection. Z3 owns the action variables (`binary`, `host`,
`port`, `protocol`, `method`, and `path`) and checks whether any symbolic action
is allowed by the candidate but not by the maximum. Host, path, and binary globs
compile to Z3 regular-expression constraints. If the solver finds such an `x`,
the candidate exceeds the maximum. If no such `x` exists, the candidate is within
the modeled maximum. If either policy uses a surface the spike does not model
yet, the check fails closed as `Unsupported`.

## Demo 1: Narrow Candidate Within Maximum

Maximum:

```yaml
version: 1
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/*
    binaries:
      - path: /usr/bin/gh
```

Candidate:

```yaml
version: 1
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123
    binaries:
      - path: /usr/bin/gh
```

Result:

```text
WithinMax
```

Why: the candidate narrows the approved path from one issue path glob to one
specific issue.

## Demo 2: Broad Path Proposal Exceeds Maximum

Maximum:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/OpenShell/issues/*
```

Candidate:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/**
```

Result:

```text
ExceedsMax {
  binary: "/usr/bin/gh",
  host: "api.github.com",
  port: 443,
  protocol: "rest",
  method: "GET",
  path: "/repos/NVIDIA/",
  reason: "candidate allows an action outside the maximum policy"
}
```

Why: the candidate allows requests outside the approved issue path. The
counterexample is a concrete model selected by Z3: a request the broader
candidate would allow but the maximum would not.

## Demo 3: Method Escalation Exceeds Maximum

Maximum:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/**
```

Candidate:

```yaml
rules:
  - allow:
      method: POST
      path: /repos/NVIDIA/OpenShell/issues
```

Result:

```text
ExceedsMax {
  method: "POST",
  ...
}
```

Why: the candidate adds a mutating HTTP method outside the maximum's approved
read-only method.

## Demo 4: Host, Binary, and Port Broadening

These candidate changes all exceed a narrower maximum:

```text
host: api.github.com       -> *.github.com
binary: /usr/bin/gh        -> /usr/bin/*
port: 443                  -> [443, 8443]
```

Why: each change creates at least one action that the maximum does not allow.

L4-only endpoints are not modeled in this spike. They fail closed as
`Unsupported` rather than being compared against the REST-only symbolic action
domain.

## Demo 5: Unsupported Surfaces Fail Closed

Maximum:

```yaml
access: full
deny_rules:
  - method: POST
    path: /admin/**
```

Result:

```text
Unsupported {
  reason: "maximum policy rule 'github' uses deny_rules, which policy envelope checks do not model yet"
}
```

Why: deny rules change containment semantics. Until the prover models allow plus
deny precedence, the check must not approve these cases.

Other surfaces currently fail closed:

```text
query constraints
GraphQL operation and field constraints
MCP tool/resource constraints
CIDR-only allowed_ips
endpoint path scoping
L4-only endpoints
```

## Narrowness Companion

The maximum-policy check answers whether a candidate stays under a
security-approved ceiling. That is the immediate enterprise gate. The related
narrowness question is different:

```text
How much broader is this candidate than the current policy?
```

A first useful shape is to reuse the same symbolic model and score the proposed
delta:

```text
delta = candidate_allows(x) AND NOT current_allows(x)
score(delta) <= budget
```

The current spike includes a first narrowness check. Z3 proves whether each
modeled candidate grant adds any action outside the current policy:

```text
exists x:
  candidate_grant_allows(x)
  AND NOT current_policy_allows(x)
```

Rust then scores the shape of each delta grant. This is deliberately coarse for
the spike:

```text
exact new grant:        +1
single path wildcard:   +2
host/binary wildcard:   +3
recursive glob (**):    +6
```

A conservative budget can allow one exact grant and reject recursive globs:

```rust
NarrownessBudget {
    max_delta_grants: 1,
    max_total_score: 1,
    allow_recursive_globs: false,
}
```

## Demo 6: One Exact Path Fits A Narrow Budget

Current:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/OpenShell/issues/123
```

Candidate:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/OpenShell/issues/123
  - allow:
      method: GET
      path: /repos/NVIDIA/OpenShell/issues/456
```

Result:

```text
WithinBudget {
  total_score: 1,
  delta_grants: [
    {
      method: "GET",
      path: "/repos/NVIDIA/OpenShell/issues/456",
      reasons: [NewGrant]
    }
  ]
}
```

Why: the candidate adds one exact modeled grant. The grant allows both `GET` and
runtime-implied `HEAD`, but the budget counts the source grant once.

## Demo 7: Lazy Recursive Path Exceeds A Narrow Budget

Current:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/OpenShell/issues/123
```

Candidate:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/**
```

Result:

```text
ExceedsBudget {
  total_score: 7,
  delta_grants: [
    {
      method: "GET",
      path: "/repos/NVIDIA/**",
      reasons: [NewGrant, RecursivePathGlob]
    }
  ]
}
```

Why: the candidate still fits under a maximum policy if that maximum is broad
enough, but it is not a narrow update over the current policy. This is the
mechanism that can pressure agents away from requesting lazy `**` access.

This spike should not over-design the product surface yet. The useful next proof
is validating whether this budget shape is useful enough for policy proposal
auto-approval, or whether we need richer semantic categories before productizing
it.

## Current Test Command

```shell
mise exec -- cargo test -p openshell-prover
```

Maximal-policy tests include:

```text
envelope::tests::exact_rest_rule_is_within_maximum
envelope::tests::broader_rest_path_exceeds_maximum
envelope::tests::method_escalation_exceeds_maximum
envelope::tests::host_wildcard_broadening_exceeds_maximum
envelope::tests::binary_wildcard_broadening_exceeds_maximum
envelope::tests::port_broadening_exceeds_maximum
envelope::tests::l4_candidate_exceeds_l7_maximum
envelope::tests::maximum_wildcards_cover_exact_candidate
envelope::tests::deny_rules_are_unsupported_until_modeled
envelope::tests::query_graphql_cidr_and_mcp_surfaces_are_unsupported
envelope::tests::narrowness_allows_one_exact_path_delta_within_budget
envelope::tests::narrowness_allows_one_exact_method_delta_within_budget
envelope::tests::narrowness_rejects_multiple_exact_grants_over_budget
envelope::tests::narrowness_rejects_recursive_path_glob_as_too_broad
```

## Readout

This validates the product shape for REST/path/binary/host/port maximum-policy
envelopes and narrowness budgets with symbolic Z3 counterexample queries. Deny
rules, MCP, GraphQL, query constraints, CIDR, and L4-only endpoints can land as
follow-on modeled surfaces once the containment and delta mechanics are proven
useful.
