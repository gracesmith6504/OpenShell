// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor middleware application for L7 requests.

use crate::l7::relay::L7EvalContext;
use crate::opa::PolicyGenerationGuard;
use miette::{Result, miette};
use openshell_ocsf::{
    ActionId, ActivityId, DetectionFindingBuilder, DispositionId, Endpoint, FindingInfo,
    HttpActivityBuilder, HttpRequest, SeverityId, StatusId, Url as OcsfUrl, ocsf_emit,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncWrite};

pub enum MiddlewareApplyResult {
    Allowed(crate::l7::provider::L7Request),
    Denied(String),
}

/// Smallest body-buffering limit across the entries that actually resolved to a
/// registered binding. Unresolved entries (`is_resolved() == false`) report a
/// zero limit and are excluded here: they are handled by their `on_error` policy
/// in `evaluate_described` without inspecting the body, so letting a zero drag
/// the chain limit to zero would spuriously fail the whole chain over capacity.
/// Returns `None` when no entry resolved, so the caller can skip buffering.
pub(super) fn middleware_chain_body_limit(
    chain: &[openshell_supervisor_middleware::DescribedChainEntry],
) -> Option<usize> {
    chain
        .iter()
        .filter(|entry| entry.is_resolved())
        .map(openshell_supervisor_middleware::DescribedChainEntry::max_body_bytes)
        .min()
}

pub async fn apply_middleware_chain<C: AsyncRead + AsyncWrite + Unpin + Send>(
    req: crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
    chain: Vec<openshell_supervisor_middleware::ChainEntry>,
    runner: &openshell_supervisor_middleware::ChainRunner,
    generation_guard: &PolicyGenerationGuard,
) -> Result<MiddlewareApplyResult> {
    apply_middleware_chain_for_scheme(req, client, ctx, "https", chain, runner, generation_guard)
        .await
}

pub async fn apply_middleware_chain_for_scheme<C: AsyncRead + AsyncWrite + Unpin + Send>(
    req: crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
    scheme: &str,
    chain: Vec<openshell_supervisor_middleware::ChainEntry>,
    runner: &openshell_supervisor_middleware::ChainRunner,
    generation_guard: &PolicyGenerationGuard,
) -> Result<MiddlewareApplyResult> {
    if chain.is_empty() {
        return Ok(MiddlewareApplyResult::Allowed(req));
    }
    let chain = runner.describe_chain(&chain).await?;
    let Some(max_body_bytes) = middleware_chain_body_limit(&chain) else {
        // No entry resolved to a registered binding, so nothing inspects the
        // body. Apply each entry's `on_error` policy without buffering (an
        // unresolved binding is handled before the body is read) and forward
        // the original request unchanged if the chain allows.
        let input = middleware_request_input(
            scheme,
            &req,
            ctx,
            BTreeMap::new(),
            String::new(),
            Vec::new(),
        );
        let outcome = runner.evaluate_described(&chain, input).await?;
        emit_middleware_events(ctx, &req, &outcome);
        return Ok(if outcome.allowed {
            MiddlewareApplyResult::Allowed(req)
        } else {
            MiddlewareApplyResult::Denied(outcome.reason)
        });
    };
    let buffered = match crate::l7::rest::buffer_request_body_for_middleware(
        &req,
        client,
        Some(generation_guard),
        max_body_bytes,
    )
    .await?
    {
        crate::l7::rest::BufferResult::Buffered(buffered) => buffered,
        crate::l7::rest::BufferResult::OverCapacity { recoverable } => {
            return Ok(resolve_unbuffered_body(ctx, req, &chain, recoverable));
        }
    };
    let headers = safe_middleware_headers(&buffered.headers)?;
    let query = raw_query_from_request_headers(&buffered.headers)?;
    let input = middleware_request_input(scheme, &req, ctx, headers, query, buffered.body);
    let outcome = runner.evaluate_described(&chain, input).await?;
    emit_middleware_events(ctx, &req, &outcome);
    let rebuilt = crate::l7::rest::rebuild_request_with_buffered_body(
        &req,
        &buffered.headers,
        &outcome.body,
        &outcome.added_headers,
    )?;
    if outcome.allowed {
        Ok(MiddlewareApplyResult::Allowed(rebuilt))
    } else {
        Ok(MiddlewareApplyResult::Denied(outcome.reason))
    }
}

pub(super) fn middleware_request_input(
    scheme: &str,
    req: &crate::l7::provider::L7Request,
    ctx: &L7EvalContext,
    headers: BTreeMap<String, String>,
    query: String,
    body: Vec<u8>,
) -> openshell_supervisor_middleware::HttpRequestInput {
    openshell_supervisor_middleware::HttpRequestInput {
        request_id: uuid::Uuid::new_v4().to_string(),
        sandbox_id: openshell_ocsf::ctx::ctx().sandbox_id.clone(),
        scheme: scheme.into(),
        host: ctx.host.clone(),
        port: ctx.port,
        method: req.action.clone(),
        path: req.target.clone(),
        query,
        headers,
        body,
    }
}

pub(super) fn raw_query_from_request_headers(headers: &[u8]) -> Result<String> {
    let header_str =
        std::str::from_utf8(headers).map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let target = header_str
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| miette!("HTTP request line is missing a target"))?;
    Ok(target
        .split_once('?')
        .map_or_else(String::new, |(_, query)| query.to_string()))
}

/// Apply the chain's `on_error` policy when the request body cannot be buffered
/// for inspection because it exceeds the size cap. The RFC treats an unbufferable
/// body as an `on_error` event: it is denied unless every attached middleware is
/// `fail_open`, and passing it through is only safe when no bytes were consumed.
pub(super) fn resolve_unbuffered_body(
    ctx: &L7EvalContext,
    req: crate::l7::provider::L7Request,
    chain: &[openshell_supervisor_middleware::DescribedChainEntry],
    recoverable: bool,
) -> MiddlewareApplyResult {
    let all_fail_open = chain
        .iter()
        .all(|entry| entry.on_error() == openshell_supervisor_middleware::OnError::FailOpen);
    if recoverable && all_fail_open {
        emit_middleware_body_unavailable(ctx, false);
        return MiddlewareApplyResult::Allowed(req);
    }
    emit_middleware_body_unavailable(ctx, true);
    MiddlewareApplyResult::Denied("middleware_failed: request_body_over_capacity".into())
}

fn emit_middleware_body_unavailable(ctx: &L7EvalContext, denied: bool) {
    let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
        .severity(if denied {
            SeverityId::High
        } else {
            SeverityId::Medium
        })
        .finding_info(FindingInfo::new(
            "openshell.middleware.body_unavailable",
            "Supervisor middleware could not inspect request body",
        ))
        .evidence_pairs(&[
            ("policy", ctx.policy_name.as_str()),
            ("host", ctx.host.as_str()),
            ("disposition", if denied { "denied" } else { "fail_open" }),
        ])
        .message(if denied {
            "Request body exceeded middleware inspection cap; denied"
        } else {
            "Request body exceeded middleware inspection cap; passed through (fail_open)"
        })
        .build();
    ocsf_emit!(event);
}

fn safe_middleware_headers(headers: &[u8]) -> Result<BTreeMap<String, String>> {
    let header_str =
        std::str::from_utf8(headers).map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let mut out = BTreeMap::new();
    for line in header_str.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty()
            || matches!(
                name.as_str(),
                "authorization" | "cookie" | "host" | "content-length" | "transfer-encoding"
            )
            || name.starts_with("x-amz-")
            || name.starts_with("x-openshell-credential")
        {
            continue;
        }
        out.insert(name, value.trim().to_string());
    }
    Ok(out)
}

pub(super) fn middleware_network_input(ctx: &L7EvalContext) -> crate::opa::NetworkInput {
    crate::opa::NetworkInput {
        host: ctx.host.clone(),
        port: ctx.port,
        binary_path: PathBuf::from(&ctx.binary_path),
        binary_sha256: String::new(),
        ancestors: ctx.ancestors.iter().map(PathBuf::from).collect(),
        cmdline_paths: ctx.cmdline_paths.iter().map(PathBuf::from).collect(),
    }
}

/// Build the OCSF events describing a middleware chain outcome, in emission
/// order. Separated from `emit_middleware_events` so tests can assert on the
/// events deterministically without routing through the global tracing pipeline,
/// whose callsite-interest cache is process-global and races under parallel
/// tests.
pub(super) fn middleware_events(
    ctx: &L7EvalContext,
    req: &crate::l7::provider::L7Request,
    outcome: &openshell_supervisor_middleware::ChainOutcome,
) -> Vec<openshell_ocsf::OcsfEvent> {
    let mut events = Vec::new();
    for invocation in &outcome.applied {
        let allowed = invocation.decision == openshell_core::proto::Decision::Allow;
        let mut event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Other)
            .action(if allowed {
                ActionId::Allowed
            } else {
                ActionId::Denied
            })
            .disposition(if allowed {
                DispositionId::Allowed
            } else {
                DispositionId::Blocked
            })
            .severity(if allowed {
                SeverityId::Informational
            } else {
                SeverityId::Medium
            })
            .http_request(HttpRequest::new(
                &req.action,
                OcsfUrl::new("http", &ctx.host, &req.target, ctx.port),
            ))
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .firewall_rule(&ctx.policy_name, "middleware")
            .unmapped("transformed", invocation.transformed)
            .unmapped("failed", invocation.failed)
            .message(format!(
                "MIDDLEWARE {} {} decision={:?}",
                invocation.name, invocation.implementation, invocation.decision
            ));
        if !allowed && !outcome.reason.is_empty() {
            event = event
                .status(StatusId::Failure)
                .status_detail(&outcome.reason);
        }
        let event = event.build();
        events.push(event);

        // A middleware that failed but was bypassed under `fail_open` is an
        // enforcement failure operators must be able to alert on, even though the
        // request proceeded.
        if invocation.failed && allowed {
            let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(SeverityId::Medium)
                .finding_info(FindingInfo::new(
                    "openshell.middleware.failure",
                    "Supervisor middleware failed open",
                ))
                .evidence_pairs(&[
                    ("middleware", invocation.name.as_str()),
                    ("implementation", invocation.implementation.as_str()),
                ])
                .unmapped("middleware", invocation.name.as_str())
                .unmapped("implementation", invocation.implementation.as_str())
                .message(format!(
                    "Middleware {} failed and was bypassed (fail_open)",
                    invocation.name
                ))
                .build();
            events.push(event);
        }
    }
    if !outcome.allowed && outcome.reason.starts_with("middleware_failed:") {
        let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(SeverityId::High)
            .finding_info(FindingInfo::new(
                "openshell.middleware.failure",
                "Supervisor middleware failure",
            ))
            .message("Required supervisor middleware failed closed")
            .build();
        events.push(event);
    }
    for finding in &outcome.findings {
        let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(match finding.finding.severity.as_str() {
                "high" => SeverityId::High,
                "low" => SeverityId::Low,
                _ => SeverityId::Medium,
            })
            .finding_info(FindingInfo::new(
                &finding.finding.r#type,
                &finding.finding.label,
            ))
            .evidence_pairs(&[
                ("middleware", &finding.middleware),
                ("count", &finding.finding.count.to_string()),
            ])
            .unmapped("middleware", finding.middleware.as_str())
            .unmapped("count", finding.finding.count)
            .message(format!(
                "Middleware finding {} count={}",
                finding.finding.r#type, finding.finding.count
            ))
            .build();
        events.push(event);
    }
    events
}

/// Emit the OCSF events describing a middleware chain outcome through the
/// tracing pipeline.
fn emit_middleware_events(
    ctx: &L7EvalContext,
    req: &crate::l7::provider::L7Request,
    outcome: &openshell_supervisor_middleware::ChainOutcome,
) {
    for event in middleware_events(ctx, req, outcome) {
        ocsf_emit!(event);
    }
}
