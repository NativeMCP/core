//! The three lanes (H9): Streamable HTTP POST, Streamable HTTP SSE, the nMCP WebSocket
//! gateway, and the dispatch all three share.
//!
//! # The name
//!
//! `mcp_http` is a poor name, because a WebSocket stops being HTTP the moment it upgrades, and it
//! is kept because three things cite it. NMCP-REF-001's thirty divergence rows carry line numbers
//! in a file by this name; WD-2's acceptance criterion is a test enumerating each lane's method
//! table against those rows; and one of the tests below reads this module's own source through
//! `include_str!`. A better noun is not worth breaking the citations that make the divergences
//! tractable.
//!
//! # What is in here and what is not
//!
//! Admission is not. Whether a caller may proceed and as whom is [`crate::admission`], which all
//! three lanes reach identically, and it is a separate issue for that reason. **Everything
//! NMCP-REF-001 enumerates is in this file**, because every one of the thirty divergences is
//! about what happens to a caller who has already been admitted.
//!
//! The base reaches admission through `use super::*` from the crate root. It is a sibling module
//! here, so the imports are explicit and the dependency is visible in a diff.

// Nothing routes here yet. The MCP router that registers these three handlers is the
// composition root's, at I-078, and the route table beside it is I-077's. Same shape as
// `admission` at I-075a and `diagnostics` at I-076, and `allow` rather than `expect` for the same
// reason: this module's own tests drive what they cover, so the lint fires in the lib target and
// not in the lib-test target, and an unfulfilled expectation in either is an error.
#![allow(
    dead_code,
    reason = "the route table is I-077; the composition root is I-078"
)]

use crate::admission::{
    McpClientIdentity, authenticate_and_record, enforce_mcp_origin, session_profile_from_headers,
};
use crate::{AppState, peer::PeerSource};
use axum::Json;
use axum::extract::State;
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
// The base reaches this through `use super::*` from its crate root, where `lib.rs` imports
// `futures_util::StreamExt as _`. Without it in scope, `stream::iter(..).chain(..)` resolves to
// `Iterator::chain`, and the error names a trait that has nothing to do with the problem.
use futures_util::stream;
use futures_util::stream::StreamExt as _;
use nmcp_proto::stateless::{
    ClientInfo, HEADER_MCP_METHOD, HEADER_MCP_NAME, HEADER_MISMATCH, INVALID_PARAMS,
    META_CLIENT_CAPABILITIES, check_headers, check_version_agreement, parse_request_meta,
    removed_in_2026_07_28,
};
use nmcp_proto::tasks::{TaskHandle, TaskState};
use nmcp_proto::{
    DEFAULT_PROTOCOL_VERSION, JsonRpcRequest, ProtocolVersion, STATELESS_PROTOCOL_VERSION,
    TOOLS_LIST_TTL_MS, discover_result, failure, initialize_result, select_protocol_version,
    success, unsupported_protocol_version,
};
use nmcp_router::CallContext;
use nmcp_transport::{EventId, ResumeCursor, SessionId, SessionOwner, StreamId, TransportError};
use serde_json::{Value, json};

/// `tools/call`, and the decision to answer it as a task.
///
/// Split out of [`mcp_post`]'s method table: it is the one arm with a decision in it rather than
/// a shape, and the decision is worth its own reading. The tool has already run through the
/// governance ring by the time the task question is asked, so answering as a task changes the
/// shape of the response and nothing about authorization. That is deliberate and it is what
/// section 5 requires: authorization at creation.
async fn post_tools_call(
    state: &AppState,
    req: JsonRpcRequest,
    protocol_version: &str,
    stateless: Option<&ClientInfo>,
    mcp_identity: Option<McpClientIdentity>,
    session_profile: Option<String>,
    mcp_session_id: Option<SessionId>,
    peer_redacted: Option<String>,
) -> nmcp_proto::JsonRpcResponse {
    // Taken before `req.params` is moved into dispatch, and taken here rather than passed in
    // because eight arguments is the ceiling and a value the request already carries is the one
    // to drop.
    let id = req.id.clone();
    let params_for_task = req.params.clone();
    let tool_name = req
        .params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let tool_name = tool_name.as_str();
    // Stateless means stateless. A `Mcp-Session-Id` on a 2026-07-28 request is ignored
    // rather than honoured, because honouring it would let a client opt back into the
    // session-scoped behaviour the revision removed and get a different answer for the
    // same request depending on a header the revision does not define.
    let session = if stateless.is_some() {
        None
    } else {
        mcp_session_id
    };
    match dispatch_tool_as(
        state,
        req.params,
        session,
        mcp_identity.clone(),
        session_profile.clone(),
        stateless.map(ClientInfo::label),
        peer_redacted.clone(),
    )
    .await
    {
        Ok(value) => {
            // The tool has already run through the ring at this point, so answering as
            // a task changes the shape of the response and nothing about authorization.
            // That is deliberate: section 5 requires authorization at creation.
            if may_answer_as_task(state, protocol_version, &params_for_task, tool_name)
                && let Some(handle) = value.get("structuredContent").and_then(task_handle_from)
            {
                success(id, nmcp_proto::tasks::create_task_result(&handle))
            } else {
                success(id, value)
            }
        }
        Err(err) => failure(id, -32000, err.to_string(), None),
    }
}
/// `tasks/get` and `tasks/cancel`, dispatched as the tools they already are.
///
/// Split out of [`mcp_post`]'s method table on the section comment the base already carried, so
/// the diff moves lines and the emitted order is unchanged. `tasks/update` stays in the table
/// because it is a refusal by name rather than a dispatch, and moving a six-line refusal into a
/// function would put half of one decision in two places.
///
/// This is what keeps `tasks/cancel` from being a cheaper `execute_cancel`: the policy check,
/// ABAC, HITL gate and audit record are the tool's own, and the audit trail names the tool that
/// ran rather than a synonym for it.
async fn post_tasks_method(
    state: &AppState,
    req: &JsonRpcRequest,
    id: Option<Value>,
    mcp_identity: Option<McpClientIdentity>,
    session_profile: Option<String>,
    client_label: Option<String>,
) -> nmcp_proto::JsonRpcResponse {
    let tool = if req.method == "tasks/get" {
        "execute_status"
    } else {
        "execute_cancel"
    };
    match task_id_param(&req.params) {
        Err(message) => failure(id, -32602, message, None),
        Ok(task_id) => match dispatch_task_method(
            state,
            tool,
            task_id,
            mcp_identity.clone(),
            session_profile.clone(),
            client_label,
            None,
        )
        .await
        {
            Err(err) => failure(id, -32000, err.to_string(), None),
            Ok(value) if value.get("isError").and_then(Value::as_bool) == Some(true) => {
                failure(id, -32001, "task not found or not permitted", None)
            }
            Ok(value) => {
                if req.method == "tasks/cancel" {
                    // An empty acknowledgement, not a status. Cancellation is
                    // cooperative and eventually consistent, so a status here would be
                    // a snapshot the client has no right to rely on; it polls
                    // tasks/get for the outcome.
                    success(id, nmcp_proto::tasks::cancel_task_result())
                } else {
                    match value.get("structuredContent").and_then(task_handle_from) {
                        Some(handle) => success(id, nmcp_proto::tasks::get_task_result(&handle)),
                        None => failure(id, -32603, "job report was unreadable", None),
                    }
                }
            }
        },
    }
}
/// Which revision this request is, and whether it satisfies that revision's preconditions.
///
/// Two questions rather than one, and they are inseparable: the preconditions exist only on
/// 2026-07-28, and which revision this is is the answer that decides whether to ask.
///
/// Split out of [`post_preamble`] on the seam its own comments already draw.
fn post_revision(
    headers: &HeaderMap,
    req: &JsonRpcRequest,
) -> Result<(&'static str, Option<ClientInfo>), (StatusCode, Json<Value>)> {
    // Revision selection happens per request, after authentication and before dispatch. A
    // revision this server does not implement is refused rather than silently treated as the
    // default, because answering a 2026-07-28 request with 2025-11-25 semantics would look
    // like success and behave like a protocol violation.
    let protocol_version = match select_protocol_version(
        headers
            .get("mcp-protocol-version")
            .and_then(|value| value.to_str().ok()),
    ) {
        ProtocolVersion::Selected(version) => version,
        ProtocolVersion::Unsupported(requested) => {
            tracing::warn!(requested = %requested, "MCP: refused unsupported protocol version");
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::to_value(unsupported_protocol_version(req.id.clone(), &requested))
                        .unwrap_or_else(|_| json!({"jsonrpc":"2.0","error":{"code":-32603,"message":"serialization error"}})),
                ),
            ));
        }
    };

    // G5-2, G5-4. Everything 2026-07-28 requires of a request, checked before the governance
    // ring runs. Before rather than after because a request that fails these checks was never a
    // valid request, and running the ring on it would write an audit record for a call that the
    // protocol says did not happen.
    let stateless = if protocol_version == STATELESS_PROTOCOL_VERSION {
        match stateless_preconditions(req, headers, protocol_version) {
            Ok(client) => Some(client),
            Err(rejection) => {
                tracing::warn!(
                    method = %req.method,
                    code = rejection.code,
                    "MCP: refused a 2026-07-28 request: {}",
                    rejection.message
                );
                return Err((
                    rejection.status,
                    Json(
                        serde_json::to_value(failure(
                            req.id.clone(),
                            rejection.code,
                            rejection.message,
                            None,
                        ))
                        .unwrap_or_else(|_| json!({"jsonrpc":"2.0","error":{"code":-32603,"message":"serialization error"}})),
                    ),
                ));
            }
        }
    } else {
        None
    };
    Ok((protocol_version, stateless))
}
/// What a POST request has established by the time its method is answered.
///
/// Named fields rather than a tuple, and a struct rather than eight arguments threaded into the
/// method table: the names are the artifact. The base leaves this set implicit in the order of a
/// hundred and twenty lines, so the only way to know what a method arm may rely on is to read all
/// of them.
struct PostPreamble {
    policy: nmcp_policy::PolicyConfig,
    peer_redacted: Option<String>,
    mcp_identity: Option<McpClientIdentity>,
    protocol_version: &'static str,
    stateless: Option<ClientInfo>,
    session_profile: Option<String>,
    mcp_session_id: Option<SessionId>,
}

/// Origin, admission, revision, the 2026-07-28 preconditions, profile and session id.
///
/// Split out of [`mcp_post`] so the method table below is the whole of that function. A table is
/// the one shape worth keeping whole: cutting it in half puts two halves of one dispatch decision
/// in two places, which is how an arm gets added to one of them.
///
/// Every refusal here keeps the status and the body it had. The protocol specifies some as 400
/// and others as a 200 carrying a JSON-RPC error, and which is which is not a detail a split may
/// normalise: an install that never configured OAuth answers 200 for an authentication failure
/// precisely so that opting out changes nothing for the desktop connector.
async fn post_preamble(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    req: &JsonRpcRequest,
) -> Result<PostPreamble, (StatusCode, Json<Value>)> {
    let policy = state.policy();
    if let Err(err) = enforce_mcp_origin(&policy, headers) {
        return Err((
            StatusCode::OK,
            Json(
                serde_json::to_value(failure(req.id.clone(), -32001, err.to_string(), None))
                    .unwrap_or_else(|_| json!({"jsonrpc":"2.0","error":{"code":-32603,"message":"serialization error"}})),
            ),
        ));
    }
    // G3-15 AF-5 and AF-7. The socket address stays here, where the throttle needs full
    // resolution; only the redacted form travels onward into a record.
    let peer_addr = peer.map(|axum::extract::ConnectInfo(addr)| addr);
    let peer_redacted = peer_addr.map(|addr| PeerSource::from(addr).redacted());
    let mcp_identity = match authenticate_and_record(state, peer_addr, headers).await {
        Ok(identity) => identity,
        Err(err) => {
            // G3-11 RS-6. An install that declared itself a protected resource answers 401,
            // which is what carries the challenge and sends a client to the metadata
            // document. An install that did not keeps the 200-with-a-JSON-RPC-error shape
            // the desktop connector already reads, so opting out changes nothing.
            let status = if policy.oauth_resource.is_some() {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::OK
            };
            return Err((
                status,
                Json(
                    serde_json::to_value(failure(req.id.clone(), -32002, err.to_string(), None))
                        .unwrap_or_else(|_| json!({"jsonrpc":"2.0","error":{"code":-32603,"message":"serialization error"}})),
                ),
            ));
        }
    };

    // Revision, then that revision's own preconditions. One call rather than two, for the
    // reason `post_revision` states: the second question only exists on the revision the first
    // one identifies.
    let (protocol_version, stateless) = post_revision(headers, req)?;

    // G6-8. Resolved before dispatch and applied to both `tools/list` and `tools/call`, so a
    // session cannot see a tool it cannot call or call one it cannot see.
    //
    // RC-D8 is the second half of the same rule and core has it where the base does not:
    // `merged_tool_list_for` takes the caller as well as the profile, and `list_for` applies
    // `CallerToolAllowlist` unconditionally. Passing `None` here would compile and would leave a
    // restricted caller enumerating tools its own allowlist forbids.
    let session_profile = match session_profile_from_headers(
        &policy,
        mcp_identity.as_ref(),
        headers,
    ) {
        Ok(profile) => profile,
        Err(err) => {
            return Err((
                StatusCode::OK,
                Json(
                    serde_json::to_value(failure(req.id.clone(), -32003, err.to_string(), None))
                        .unwrap_or_else(|_| json!({"jsonrpc":"2.0","error":{"code":-32603,"message":"serialization error"}})),
                ),
            ));
        }
    };

    // Extract MCP-Session-Id for associating tool calls with transport sessions.
    let mcp_session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(SessionId::from_string);
    Ok(PostPreamble {
        policy,
        peer_redacted,
        mcp_identity,
        protocol_version,
        stateless,
        session_profile,
        mcp_session_id,
    })
}

/// POST /mcp - MCP Streamable HTTP request/response lane.
///
/// Returns a status code alongside the body because protocol-revision refusal is specified
/// as HTTP 400, not as a 200 carrying an error object. Every other path answers 200 with a
/// JSON-RPC envelope exactly as before.
pub(crate) async fn mcp_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    // G3-13 AF-5. Optional because a test drives this function directly, where there is no
    // connection and therefore no honest answer to "where from". `None` is recorded as
    // unknown rather than guessed at.
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    Json(req): Json<JsonRpcRequest>,
) -> (StatusCode, Json<Value>) {
    let PostPreamble {
        policy,
        peer_redacted,
        mcp_identity,
        protocol_version,
        stateless,
        session_profile,
        mcp_session_id,
    } = match post_preamble(&state, &headers, peer, &req).await {
        Ok(preamble) => preamble,
        Err(refusal) => return refusal,
    };

    // Advertised only when policy names a tool that can answer as one. A server that can never
    // produce a task should not claim it can, and this is what keeps the default-off state
    // invisible to a client rather than merely inert.
    let advertise_tasks = !policy.task_tools.is_empty();
    let id = req.id.clone();
    let response = match req.method.as_str() {
        "initialize" => {
            let mut result = initialize_result(protocol_version);
            if advertise_tasks && let Some(capabilities) = result.get_mut("capabilities") {
                nmcp_proto::tasks::advertise_in(capabilities);
            }
            success(id, result)
        }
        "notifications/initialized" => success(id, json!({"ok":true})),
        "tools/list" => success(
            id,
            json!({
                "tools": state.router.merged_tool_list_for(
                    session_profile.as_deref(),
                    mcp_identity.as_ref().map(|identity| identity.agent_id.as_str()),
                ),
                "ttlMs": TOOLS_LIST_TTL_MS,
            }),
        ),
        // Mandatory for servers under 2026-07-28 and harmless before it. Answered on every
        // supported revision so a client probing to learn which revisions exist does not
        // have to already know one.
        "server/discover" => {
            let mut result = discover_result(
                &state.router.merged_tool_list_for(
                    session_profile.as_deref(),
                    mcp_identity
                        .as_ref()
                        .map(|identity| identity.agent_id.as_str()),
                ),
            );
            if advertise_tasks && let Some(capabilities) = result.get_mut("capabilities") {
                nmcp_proto::tasks::advertise_in(capabilities);
            }
            success(id, result)
        }
        "tools/call" => {
            post_tools_call(
                &state,
                req,
                protocol_version,
                stateless.as_ref(),
                mcp_identity.clone(),
                session_profile.clone(),
                mcp_session_id,
                peer_redacted.clone(),
            )
            .await
        }
        // The tasks extension, and only on the revision that has it. On 2025-11-25 these are
        // method-not-found, because answering them would teach a client something false about
        // what that revision offers.
        "tasks/get" | "tasks/cancel" if stateless.is_some() => {
            post_tasks_method(
                &state,
                &req,
                id,
                mcp_identity.clone(),
                session_profile.clone(),
                stateless.as_ref().map(ClientInfo::label),
            )
            .await
        }
        // Defined by the extension and deliberately not implemented. tasks/update delivers input
        // for an input_required task, this server never produces that status because it does no
        // sampling, roots or elicitation, and accepting input the runtime has nowhere to route
        // would be a lie told politely.
        "tasks/update" if stateless.is_some() => failure(
            id,
            -32601,
            "tasks/update is not implemented: this server never produces an input_required task",
            None,
        ),
        _ => failure(id, -32601, "method not found", None),
    };
    // After the match rather than inside it, so an arm added later cannot forget it.
    let mut response = response;
    nmcp_proto::stamp_result_type(&mut response, protocol_version);
    (
        StatusCode::OK,
        Json(serde_json::to_value(response).unwrap_or_else(
            |_| json!({"jsonrpc":"2.0","error":{"code":-32603,"message":"serialization error"}}),
        )),
    )
}

/// Why a 2026-07-28 request was refused before it reached the governance ring.
struct StatelessRejection {
    status: StatusCode,
    code: i64,
    message: String,
}

/// Check everything 2026-07-28 asks of a request, and return who the client says it is.
///
/// The returned [`ClientInfo`] is self-reported and is deliberately not threaded into
/// authorization anywhere: SEP-2243 forbids treating transport-supplied values as trusted input
/// for security-sensitive decisions, and `agent_id` remains the only identity ABAC reads.
fn stateless_preconditions(
    req: &JsonRpcRequest,
    headers: &HeaderMap,
    negotiated: &str,
) -> Result<ClientInfo, StatelessRejection> {
    // A removed RPC is method-not-found rather than a bad request: the request was well formed,
    // it just named something this revision does not have. Answering it anyway would teach a
    // client something false about the server, which is the same dishonesty the supported
    // version list exists to prevent.
    if removed_in_2026_07_28(&req.method) {
        return Err(StatelessRejection {
            status: StatusCode::OK,
            code: -32601,
            message: format!(
                "'{}' was removed by MCP 2026-07-28 and is answered on 2025-11-25 only",
                req.method
            ),
        });
    }

    let header_value = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    check_headers(
        &req.method,
        Some(&req.params),
        header_value(HEADER_MCP_METHOD),
        header_value(HEADER_MCP_NAME),
    )
    .map_err(|err| StatelessRejection {
        status: StatusCode::BAD_REQUEST,
        code: HEADER_MISMATCH,
        message: err.to_string(),
    })?;

    let meta = parse_request_meta(Some(&req.params)).map_err(|err| StatelessRejection {
        status: StatusCode::BAD_REQUEST,
        code: INVALID_PARAMS,
        message: err.to_string(),
    })?;
    // The header already selected the revision. This refuses the case where the body names a
    // different one, which means the transport and the payload disagree about what request
    // this is.
    check_version_agreement(negotiated, &meta).map_err(|err| StatelessRejection {
        status: StatusCode::BAD_REQUEST,
        code: INVALID_PARAMS,
        message: err.to_string(),
    })?;
    Ok(meta.client_info)
}

/// GET /mcp - MCP Streamable HTTP SSE compatibility lane (PR-06).
///
/// Opens an SSE stream on the MCP listener (port 18770). The session registry from
/// `mcp-transport` manages session and stream lifecycle. Admin routes are never exposed here.
///
/// Request headers consumed:
///   Accept: text/event-stream  - required; returns 406 for other explicit Accept values
///   MCP-Session-Id             - if present, reuse the named session; 404 if expired
///   MCP-Stream-Id              - if present with MCP-Session-Id, replay that specific stream
///   Last-Event-ID              - if present with MCP-Stream-Id, replay events after that id
///
/// Response headers emitted:
///   Content-Type: text/event-stream
///   MCP-Session-Id             - the session UUID (new or reused)
///   MCP-Stream-Id              - the stream UUID created for this connection
///   MCP-Protocol-Version: 2025-11-25
pub(crate) async fn mcp_get_sse(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
) -> impl IntoResponse {
    // 1. Accept negotiation - only serve SSE; reject explicit non-SSE Accept values.
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if !accept.is_empty() && !accept.contains("text/event-stream") {
        return (
            StatusCode::NOT_ACCEPTABLE,
            Json(json!({"error": "GET /mcp requires Accept: text/event-stream"})),
        )
            .into_response();
    }

    // 2. Origin check - same policy as POST /mcp.
    let policy = state.policy();
    if let Err(err) = enforce_mcp_origin(&policy, &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": err.to_string()})),
        )
            .into_response();
    }

    let mcp_identity = match authenticate_and_record(
        &state,
        peer.map(|axum::extract::ConnectInfo(a)| a),
        &headers,
    )
    .await
    {
        Ok(identity) => identity,
        Err(err) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": err.to_string()})),
            )
                .into_response();
        }
    };
    // WD-24. The value is discarded and the refusal is kept, deliberately.
    //
    // This lane answers no method that returns a tool list, so it has nothing to scope and the
    // resolved profile has nowhere to go. What it does have is the same credential the other two
    // lanes evaluate, and `session_profile_from_headers` is the only thing that answers whether
    // that credential's profile can be honoured. Skipping the call, which is what the base does,
    // means a credential bound to a profile this server does not have is refused on POST,
    // refused on WebSocket, and admitted here: on the lane that is on by default.
    //
    // Refused with 403 rather than 401, matching the WebSocket lane. The credential was good;
    // what failed is a statement about this server's configuration, and answering 401 would send
    // a client to re-authenticate against a problem no new token can fix.
    if let Err(err) = session_profile_from_headers(&policy, mcp_identity.as_ref(), &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": err.to_string()})),
        )
            .into_response();
    }

    // G3-16. A session belongs to whoever created it, and only they may resume or replay it.
    let owner = SessionOwner::from_agent(
        mcp_identity
            .as_ref()
            .map(|identity| identity.agent_id.as_str()),
    );
    // 3. Session lifecycle.
    let incoming_session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(SessionId::from_string);

    let incoming_stream_id = headers
        .get("mcp-stream-id")
        .and_then(|v| v.to_str().ok())
        .map(StreamId::from_string);

    let last_event_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    let (session_id, stream_id, replayed) = match sse_session(
        &state,
        incoming_session_id,
        incoming_stream_id,
        last_event_id,
        &owner,
    ) {
        Ok(resolved) => resolved,
        Err(refusal) => return refusal,
    };

    // 4. Build SSE stream: replayed events first, then idle (keepalive keeps connection alive).
    let replay_events: Vec<Result<Event, std::convert::Infallible>> = replayed
        .into_iter()
        .map(|evt| {
            Ok(Event::default()
                .id(evt.event_id.to_string())
                .event(evt.event_type)
                .data(serde_json::to_string(&evt.payload).unwrap_or_default()))
        })
        .collect();

    let sse_stream = stream::iter(replay_events)
        .chain(stream::pending::<Result<Event, std::convert::Infallible>>());

    let session_id_val = session_id.to_string();
    let stream_id_val = stream_id.to_string();

    let mut response = Sse::new(sse_stream)
        .keep_alive(KeepAlive::default())
        .into_response();

    let h = response.headers_mut();
    if let Ok(v) = session_id_val.parse() {
        h.insert("mcp-session-id", v);
    }
    if let Ok(v) = stream_id_val.parse() {
        h.insert("mcp-stream-id", v);
    }
    if let Ok(v) = "2025-11-25".parse() {
        h.insert("mcp-protocol-version", v);
    }

    response
}

/// Resume a session this caller owns, or mint a new one, with a fresh stream either way.
///
/// Split out of [`mcp_get_sse`] on the seam it already had, so that function is negotiation and
/// response while this one is lifecycle.
///
/// `Result<_, Response>` rather than an option or a panic. Six paths through here are refusals
/// and they are not interchangeable: a session this caller does not own answers 404 identically
/// to one that does not exist, a stream limit answers 503 with `Retry-After`, and a session limit
/// answers 503 with the same header and a different body. Each stays exactly what it was.
///
/// `result_large_err` fires because an axum `Response` is 128 bytes and this returns one by value.
/// Boxing it is what the lint suggests and it is the wrong trade here: the `Err` arm is a complete
/// HTTP response that the caller returns on the very next line, so boxing adds an allocation on
/// the refusal path to save stack on a path that is about to open a long-lived SSE stream anyway.
#[allow(
    clippy::result_large_err,
    reason = "the Err arm is a complete HTTP response, returned immediately by the caller"
)]
fn sse_session(
    state: &AppState,
    incoming_session_id: Option<SessionId>,
    incoming_stream_id: Option<StreamId>,
    last_event_id: u64,
    owner: &SessionOwner,
) -> Result<(SessionId, StreamId, Vec<nmcp_transport::TransportEvent>), axum::response::Response> {
    let Some(sid) = incoming_session_id else {
        return sse_new_session(state, owner);
    };
    // G3-16. Ownership is checked BEFORE the session is touched at all, and a session this caller
    // does not own is answered exactly as a session that does not exist. Telling the two apart
    // would hand an attacker a session-id oracle, which is most of the work of the attack this
    // closes.
    if !state.transport.owns_session(&sid, owner) {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "session not found"})),
        )
            .into_response());
    }
    // Reuse the existing session. Always create a new stream for this connection; replay a
    // previous one only if MCP-Stream-Id and Last-Event-ID are both supplied.
    let new_stream_id = match state.transport.create_stream(&sid) {
        Ok(s) => s,
        Err(TransportError::SessionNotFound(_)) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "session not found or expired",
                    "code": "SESSION_EXPIRED"
                })),
            )
                .into_response());
        }
        Err(TransportError::StreamLimitExceeded(_)) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                [(axum::http::header::RETRY_AFTER, "1")],
                Json(json!({"error": "stream limit exceeded for session"})),
            )
                .into_response());
        }
        Err(err) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": err.to_string()})),
            )
                .into_response());
        }
    };

    let replayed = match (incoming_stream_id, last_event_id) {
        (Some(prev_stream_id), cursor) if cursor > 0 => {
            let resume = ResumeCursor {
                session_id: sid.clone(),
                stream_id: prev_stream_id,
                after_event_id: EventId::new(cursor),
            };
            state.transport.replay(&resume, owner).unwrap_or_default()
        }
        _ => vec![],
    };
    Ok((sid, new_stream_id, replayed))
}

/// A new session and its first stream, for a connection that named neither.
#[allow(
    clippy::result_large_err,
    reason = "as `sse_session`: the Err arm is a complete HTTP response"
)]
fn sse_new_session(
    state: &AppState,
    owner: &SessionOwner,
) -> Result<(SessionId, StreamId, Vec<nmcp_transport::TransportEvent>), axum::response::Response> {
    let sid = match state.transport.create_session(owner.clone()) {
        Ok(sid) => sid,
        Err(TransportError::SessionLimitExceeded) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                [(axum::http::header::RETRY_AFTER, "1")],
                Json(json!({"error": "session limit exceeded"})),
            )
                .into_response());
        }
        Err(err) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": err.to_string()})),
            )
                .into_response());
        }
    };
    let stream_id = match state.transport.create_stream(&sid) {
        Ok(s) => s,
        Err(err) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": err.to_string()})),
            )
                .into_response());
        }
    };
    Ok((sid, stream_id, vec![]))
}

/// The event type the WebSocket lane journals its responses under.
///
/// One type rather than one per method: the journal is a replay of what this socket sent, and a
/// resuming client replays it in order without needing to know which method produced which frame.
const WS_RESPONSE_EVENT: &str = "jsonrpc.response";

/// What this lane can actually do, which is not the same as what the registry can do.
///
/// WD-25. The welcome frame ships `TransportCapabilities` verbatim in the base, and two of its
/// fields are hardcoded `true` in `from_config` with nothing behind them:
/// `cancellation_routing` and `in_memory_replay`. NMCP-REF-001 D24 states it plainly: the frame
/// "describes the registry's compile-time configuration rather than the lane's behaviour".
///
/// `in_memory_replay` and `redaction_pipeline` are true from this issue onward, because the loop
/// below emits every response into the session's journal and `emit` redacts before it retains.
///
/// `cancellation_routing` is **withdrawn**. `CancellationRegistry` exists in `nmcp-transport` and
/// is named nowhere in this crate: no lane registers a token, nothing handles
/// `notifications/cancelled`, and no long-running handler polls one. Implementing it is its own
/// issue with its own acceptance criteria, and until then a client that asks gets `false`, which
/// is the true answer rather than a deferred one.
///
/// The correction belongs here rather than in `from_config`. The registry genuinely holds a
/// cancellation registry and genuinely could route with it. What is false is this lane's claim,
/// made on the registry's behalf about a wiring the registry cannot see, and this is the only
/// place that claim reaches a client.
fn advertised_capabilities(state: &AppState) -> nmcp_transport::TransportCapabilities {
    let mut capabilities = state.transport.capabilities();
    capabilities.cancellation_routing = false;
    capabilities
}

/// The subprotocol token this lane requires and negotiates. NMCP-DEC-001 row B-7.
///
/// A constant rather than four literals, which is what the base had: the required-header check,
/// the refusal that names what was required, the negotiated protocol list, and the welcome
/// frame. Four spellings of one name is three chances for a rename to land on some of them, and
/// the failure is a lane that refuses every client following its own documentation.
pub(crate) const WS_SUBPROTOCOL: &str = "nmcp.v1";

/// GET /mcp/ws - the nMCP WebSocket Model Context Gateway (PR-08).
///
/// Custom transport, NOT standard MCP. Label it as nMCP-specific in any client documentation.
///
/// Upgrade requirements:
///   Sec-WebSocket-Protocol: [`WS_SUBPROTOCOL`]  (required; 400 if absent)
///   Origin: localhost or 127.0.0.1 or configured allowed origin (403 if rejected)
///
/// Frame format: JSON text frames only. Each frame is a JSON-RPC 2.0 object.
///
/// Server to client welcome frame (first frame after upgrade):
///   `{"type":"connected","session_id":"...","stream_id":"...","protocol":"nmcp.v1"}`
///
/// Client to server: standard JSON-RPC requests (initialize, tools/list, tools/call).
/// Server to client: standard JSON-RPC responses.
///
/// Admin routes (doctor, support-bundle, metrics, policy) are NOT available here.
/// Service management (install, start, stop) is NOT available here.
/// No delete-like MCP tools are available here.
pub(crate) async fn mcp_websocket(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
) -> impl IntoResponse {
    // 1. Subprotocol check: the client must declare WS_SUBPROTOCOL.
    let declared = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let has_proto = declared
        .split(',')
        .map(str::trim)
        .any(|p| p == WS_SUBPROTOCOL);
    if !has_proto {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("required Sec-WebSocket-Protocol: {WS_SUBPROTOCOL}")
            })),
        )
            .into_response();
    }

    // 2. Origin check - same policy as POST /mcp and GET /mcp SSE.
    let policy = state.policy();
    if let Err(err) = enforce_mcp_origin(&policy, &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": err.to_string()})),
        )
            .into_response();
    }

    // G3-15 AF-5. The socket address travels into the connection whole, because WD-D3's
    // re-authentication runs the throttle per message and the throttle needs full resolution.
    // Redaction happens once inside the connection, where the record is written.
    let peer_addr = peer.map(|axum::extract::ConnectInfo(addr)| addr);
    let mcp_identity = match authenticate_and_record(&state, peer_addr, &headers).await {
        Ok(identity) => identity,
        Err(err) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": err.to_string()})),
            )
                .into_response();
        }
    };

    // 3. Profile resolution, refused before the upgrade rather than after it, so a credential
    // that cannot be honoured never becomes an open socket. Re-resolved per message below; this
    // one exists so the failure is an HTTP response a client can read rather than a close frame.
    if let Err(err) = session_profile_from_headers(&policy, mcp_identity.as_ref(), &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": err.to_string()})),
        )
            .into_response();
    }

    // 4. Upgrade, negotiating the subprotocol. The headers travel with the socket: WD-D3's
    // re-authentication needs the credential the client presented, and after the upgrade there
    // is no request left to read it from.
    ws.protocols([WS_SUBPROTOCOL])
        .on_upgrade(move |socket| handle_ws_connection(socket, state, headers, peer_addr))
        .into_response()
}

/// Handles an accepted WebSocket connection for the MCP gateway.
///
/// # WD-D3: this socket re-authenticates
///
/// The base establishes identity and profile once, before the upgrade, and hands them to this
/// function by value. A credential revoked by a policy edit keeps serving until the client
/// disconnects, and so does a profile the operator has since changed. Nothing ages the socket
/// out either: NMCP-SPEC-004 section 2 measured the idle TTL this loop claims handles cleanup and
/// found `expire_idle_at` has exactly two references in the tree, its definition and its own unit
/// test.
///
/// So the headers travel with the socket and admission runs per message, against the shared
/// policy handle, which is what POST and SSE already do per request. A timer was the alternative
/// and was rejected in the spec for the reason above: it would be a second mechanism to forget
/// to call, in a lane where the first one was already forgotten.
///
/// The cost is a map lookup and a signature verification per message, the same as one POST
/// request. It also means the throttle applies to a live socket, which is the correct direction:
/// a client hammering a revoked credential is what the throttle exists for, and exempting an
/// already-open connection would make the socket the way around it.
async fn handle_ws_connection(
    mut socket: WebSocket,
    state: AppState,
    headers: HeaderMap,
    peer_addr: Option<std::net::SocketAddr>,
) {
    // The identity at upgrade time decides who owns the session. It is re-established per message
    // below; this one exists because a session needs an owner before the first frame arrives.
    let Ok(opening_identity) = authenticate_and_record(&state, peer_addr, &headers).await else {
        let msg = json!({"type":"error","code":"UNAUTHORIZED","message":"authentication failed"});
        let _ = socket.send(WsMessage::Text(msg.to_string())).await;
        return;
    };
    // G3-15 AF-7. The socket address stays here, where the throttle needs full resolution; only
    // the redacted form travels onward into a record.
    let peer = peer_addr.map(|addr| PeerSource::from(addr).redacted());

    // Allocate a session and stream from the transport core.
    let session_id = match state.transport.create_session(SessionOwner::from_agent(
        opening_identity
            .as_ref()
            .map(|identity| identity.agent_id.as_str()),
    )) {
        Ok(sid) => sid,
        Err(err) => {
            let msg = json!({"type":"error","code":"SESSION_LIMIT","message":err.to_string()});
            let _ = socket.send(WsMessage::Text(msg.to_string())).await;
            return;
        }
    };
    let stream_id = match state.transport.create_stream(&session_id) {
        Ok(sid) => sid,
        Err(err) => {
            let msg = json!({"type":"error","code":"STREAM_LIMIT","message":err.to_string()});
            let _ = socket.send(WsMessage::Text(msg.to_string())).await;
            return;
        }
    };

    // Send welcome frame - client uses session_id for SSE resume or reconnect.
    let welcome = json!({
        "type": "connected",
        "session_id": session_id.as_str(),
        "stream_id": stream_id.as_str(),
        "protocol": WS_SUBPROTOCOL,
        "capabilities": advertised_capabilities(&state),
    });
    if socket
        .send(WsMessage::Text(welcome.to_string()))
        .await
        .is_err()
    {
        return;
    }

    // Message loop: one request at a time (request/response; no push in PR-08).
    while let Some(Ok(msg)) = socket.recv().await {
        match msg {
            WsMessage::Text(text) => {
                // WD-D3. Both of these are re-established here rather than captured above, and
                // they read the shared policy handle, so a policy edit lands on the next frame.
                let Ok(mcp_identity) = authenticate_and_record(&state, peer_addr, &headers).await
                else {
                    let msg = json!({
                        "type": "error",
                        "code": "UNAUTHORIZED",
                        "message": "this credential is no longer accepted"
                    });
                    let _ = socket.send(WsMessage::Text(msg.to_string())).await;
                    break;
                };
                let policy = state.policy();
                let Ok(session_profile) =
                    session_profile_from_headers(&policy, mcp_identity.as_ref(), &headers)
                else {
                    let msg = json!({
                        "type": "error",
                        "code": "FORBIDDEN",
                        "message": "the gateway profile for this credential is no longer available"
                    });
                    let _ = socket.send(WsMessage::Text(msg.to_string())).await;
                    break;
                };

                let response = handle_ws_message(
                    &state,
                    &text,
                    session_id.clone(),
                    mcp_identity,
                    session_profile,
                    peer.clone(),
                )
                .await;

                // WD-25. The one call site that makes `in_memory_replay` and
                // `redaction_pipeline` true, because `emit` is the only writer of the replay
                // journal and the only caller of the redactor. The welcome frame already tells
                // the client this session id is for "SSE resume or reconnect"; until now there
                // was nothing to resume.
                //
                // A failure here does not fail the request. The journal is bounded in events and
                // in bytes and the session can be evicted under pressure, so `emit` refusing is
                // an ordinary outcome of a working bound rather than a fault, and dropping a
                // socket because a replay buffer is full would trade a working request for a
                // best-effort one.
                if let Err(err) = state.transport.emit(
                    &session_id,
                    &stream_id,
                    WS_RESPONSE_EVENT,
                    response.clone(),
                ) {
                    tracing::debug!(error = %err, "WS: response not journalled for replay");
                }

                if socket
                    .send(WsMessage::Text(response.to_string()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            WsMessage::Close(_) => break,
            // Ignore binary, ping and pong; axum handles ping and pong automatically.
            _ => {}
        }
    }
    // The session outlives this loop in the registry. NMCP-REF-001 D13: the idle TTL that would
    // reclaim it has no caller, which is a defect this issue names and does not fix, because the
    // sweep belongs with the background tasks in NMCP-SPEC-004 section 5.3 rather than with a
    // lane. WD-D3 is what makes it not a security defect: a socket outliving its credential no
    // longer serves anything.
}

/// Processes a single WebSocket text frame as a JSON-RPC request and returns the response.
///
/// Returns the `Value` rather than the string the base returns. The body already builds one and
/// stringifies at the very end, and the caller needs the value: WD-25's journal entry is the
/// response, and parsing the string back to recover something this function just had would be a
/// cost paid per message to undo a conversion made one line earlier.
pub(crate) async fn handle_ws_message(
    state: &AppState,
    text: &str,
    session_id: SessionId,
    mcp_identity: Option<McpClientIdentity>,
    session_profile: Option<String>,
    peer: Option<String>,
) -> Value {
    let req: JsonRpcRequest = match serde_json::from_str(text) {
        Ok(r) => r,
        Err(err) => {
            return json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {"code": -32700, "message": format!("parse error: {err}")}
            });
        }
    };

    let id = req.id.clone();
    let response = match req.method.as_str() {
        "initialize" => {
            serde_json::to_value(success(id, initialize_result(DEFAULT_PROTOCOL_VERSION)))
        }
        "notifications/initialized" => serde_json::to_value(success(id, json!({"ok": true}))),
        "tools/list" => serde_json::to_value(success(
            id,
            json!({
                "tools": state.router.merged_tool_list_for(
                    session_profile.as_deref(),
                    mcp_identity.as_ref().map(|identity| identity.agent_id.as_str()),
                ),
                "ttlMs": TOOLS_LIST_TTL_MS,
            }),
        )),
        // G6-11. Scoped like every other method that returns a tool list. This one called
        // merged_tool_list() unfiltered while the POST lane and this lane's own tools/list
        // both scoped, so a session restricted to one gateway profile could enumerate every
        // upstream and every tool name through this single method. The ring still refused the
        // calls, so the leak was enumeration rather than invocation, and enumeration is most
        // of what a profile exists to prevent.
        "server/discover" => serde_json::to_value(success(
            id,
            discover_result(
                &state.router.merged_tool_list_for(
                    session_profile.as_deref(),
                    mcp_identity
                        .as_ref()
                        .map(|identity| identity.agent_id.as_str()),
                ),
            ),
        )),
        "tools/call" => {
            match dispatch_tool(
                state,
                req.params,
                Some(session_id),
                mcp_identity,
                session_profile,
                peer,
            )
            .await
            {
                Ok(value) => serde_json::to_value(success(id, value)),
                Err(err) => serde_json::to_value(failure(id, -32000, err.to_string(), None)),
            }
        }
        _ => serde_json::to_value(failure(id, -32601, "method not found", None)),
    };

    response.unwrap_or_else(|_| {
        json!({
            "jsonrpc": "2.0",
            "error": {"code": -32603, "message": "serialization error"}
        })
    })
}

/// Dispatch a tool call with no client identity to record.
///
/// The common form. Every revision but 2026-07-28 carries no `clientInfo`, and so does every
/// caller that is not the HTTP POST lane, so `None` is the truth rather than a placeholder.
pub(crate) async fn dispatch_tool(
    state: &AppState,
    params: Value,
    session_id: Option<SessionId>,
    mcp_identity: Option<McpClientIdentity>,
    session_profile: Option<String>,
    // G3-15 AF-7. Already redacted; see CallContext::peer. `None` means a caller with no
    // transport, which is every CLI and test path, and reads as "local" in the record exactly
    // as it did before.
    peer: Option<String>,
) -> anyhow::Result<Value> {
    dispatch_tool_as(
        state,
        params,
        session_id,
        mcp_identity,
        session_profile,
        None,
        peer,
    )
    .await
}

/// What the server suggests a client wait between `tasks/get` calls.
///
/// One second: long enough not to hammer a governed endpoint that writes an audit record per
/// poll, short enough that a job finishing feels immediate.
///
/// The base documents this constant with the first half of [`dispatch_tool_as`]'s doc comment
/// attached in front, so `cargo doc` renders a `u64` as "Dispatch, recording what the client said
/// it was". A move merged two doc comments and the constant inherited the wrong half, which left
/// `dispatch_tool_as` undocumented and this constant documented as a function. Split back.
const TASK_POLL_INTERVAL_MS: u64 = 1_000;

/// Whether this request may be answered with a task.
///
/// Three conditions, all required, and each rules out a different mistake. The revision must be
/// the one that has the extension, or the response would carry a shape the negotiated revision
/// never defined. The client must have declared it can survive a task, because the extension
/// inverts the usual flow and silence is a declaration of no optional capabilities rather than
/// an omission. And policy must name the tool, which is the operator's decision and defaults to
/// naming nothing.
fn may_answer_as_task(
    state: &AppState,
    protocol_version: &str,
    params: &Value,
    tool_name: &str,
) -> bool {
    if protocol_version != STATELESS_PROTOCOL_VERSION {
        return false;
    }
    if !state.policy().task_tools.contains(tool_name) {
        return false;
    }
    // The prefixed key is the only spelling this revision defines, and `parse_request_meta`
    // already required it to get here, so an unprefixed one is a client that did not declare
    // rather than a client to be understood anyway. Read through the constant so this cannot
    // drift from the parser.
    let capabilities = params
        .get("_meta")
        .and_then(|meta| meta.get(META_CLIENT_CAPABILITIES))
        .cloned()
        .unwrap_or_else(|| json!({}));
    nmcp_proto::tasks::client_declared(&capabilities)
}

/// Map a job's reported status onto a task state.
///
/// The boundary between completed and failed is a judgement, so it is written down rather than
/// left in the code's shape. A job that RAN and exited non-zero is `completed`: the task
/// produced the answer it was asked for, and that answer is a failing exit code, which the
/// tool result carries as `isError`. A job that never produced an answer at all, because it
/// could not start or ran out of time, is `failed`, and `FailedTask.error` is typed as a
/// JSON-RPC error rather than free text, so it is shaped as one.
fn task_state_from(report: &Value) -> TaskState {
    let status = report.get("status").and_then(Value::as_str).unwrap_or("");
    let exit_code = report.get("exit_code").and_then(Value::as_i64);
    match status {
        "queued" | "running" => TaskState::Working,
        "cancelled" => TaskState::Cancelled,
        "exited" => TaskState::Completed {
            result: json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(report)
                        .unwrap_or_else(|_| "{}".to_string()),
                }],
                "structuredContent": report.clone(),
                "isError": exit_code != Some(0),
            }),
        },
        // failed_to_start, timed_out, and anything a future status adds that is not one of the
        // above. Falling through to failed rather than to working is the fail-closed direction:
        // a client polling a task this server no longer understands should stop, not spin.
        other => TaskState::Failed {
            error: nmcp_proto::tasks::task_error(
                -32000,
                report
                    .get("error")
                    .and_then(Value::as_str)
                    .map_or_else(|| format!("job ended as '{other}'"), str::to_string),
            ),
        },
    }
}

/// Build a task handle from a job report, whether it came from a start or a status.
pub(crate) fn task_handle_from(report: &Value) -> Option<TaskHandle> {
    let task_id = report.get("job_id").and_then(Value::as_str)?.to_string();
    let started = report
        .get("started_unix_ms")
        .and_then(Value::as_u64)
        .map(u128::from);
    let last_updated = report
        .get("last_updated_unix_ms")
        .and_then(Value::as_u64)
        .map(u128::from);
    // A start report carries neither timestamp, because the job was created in the same breath
    // as the response. Now is the truthful answer for both in that case.
    let created_at = started.map_or_else(nmcp_proto::tasks::now, nmcp_proto::tasks::from_unix_ms);
    let last_updated_at = last_updated.map_or(created_at, nmcp_proto::tasks::from_unix_ms);
    Some(TaskHandle {
        task_id,
        state: task_state_from(report),
        status_message: report
            .get("summary")
            .and_then(Value::as_str)
            .map(str::to_string),
        created_at,
        last_updated_at,
        ttl_ms: report.get("timeout_ms").and_then(Value::as_u64),
        poll_interval_ms: Some(TASK_POLL_INTERVAL_MS),
    })
}

/// Dispatch a task method as the tool it already is, so governance is the tool's own.
///
/// This is what keeps `tasks/cancel` from being a cheaper `execute_cancel`. The policy check,
/// ABAC, HITL gate and audit record are the ones that tool already carries, and the audit trail
/// names the tool that ran rather than a synonym for it.
async fn dispatch_task_method(
    state: &AppState,
    tool: &str,
    task_id: &str,
    mcp_identity: Option<McpClientIdentity>,
    session_profile: Option<String>,
    client_info: Option<String>,
    peer: Option<String>,
) -> anyhow::Result<Value> {
    dispatch_tool_as(
        state,
        json!({ "name": tool, "arguments": { "job_id": task_id } }),
        None,
        mcp_identity,
        session_profile,
        client_info,
        peer,
    )
    .await
}

/// The `taskId` a tasks method names, or the error a client gets for omitting it.
fn task_id_param(params: &Value) -> Result<&str, &'static str> {
    params
        .get("taskId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or("tasks methods require a taskId")
}

/// Dispatch, recording what the client said it was.
///
/// Separate from [`dispatch_tool`] rather than a seventh parameter on it, so the callers that
/// have no client identity keep saying so by construction instead of passing `None`.
pub(crate) async fn dispatch_tool_as(
    state: &AppState,
    params: Value,
    session_id: Option<SessionId>,
    mcp_identity: Option<McpClientIdentity>,
    session_profile: Option<String>,
    client_info: Option<String>,
    peer: Option<String>,
) -> anyhow::Result<Value> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    // G3-15 AF-7. The credential path rides on the identity, so it cannot drift apart from
    // the agent_id it describes.
    let credential_path = mcp_identity
        .as_ref()
        .map(|identity| identity.credential_path);
    let ctx = CallContext::with_agent(
        session_id.as_ref().map(|s| s.as_str().to_string()),
        mcp_identity.map(|identity| identity.agent_id),
    )
    .with_profile(session_profile)
    .with_client_info(client_info)
    .with_provenance(peer, credential_path);
    let result = state.router.dispatch(name, args, ctx).await;
    Ok(result.into_dispatch_json())
}

// Tests ─────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "a test that cannot fail loudly reports nothing, and indexing IS the assertion"
    )]

    use super::*;
    use nmcp_policy::{GatewayProfile, McpClientCredential, PolicyConfig};
    use std::collections::BTreeMap;

    /// This module's production source: comments removed, and this test module removed too.
    ///
    /// Two exclusions, and both were learned rather than designed.
    ///
    /// The comment filter is the base's, and the reason is that a comment explaining a rule names
    /// the call the rule forbids, so a parser counting comments reports the defect it exists to
    /// catch.
    ///
    /// The test-module cut is this port's. The base keeps these tests in `lib.rs` and reads
    /// `mcp_http.rs`; here they are in the file they read, so **an assertion naming a forbidden
    /// string is itself an occurrence of it**. Three of these tests failed on their own text the
    /// first time they ran, which is the good failure: a source-coupled test that cannot see the
    /// difference between the code and the assertion about the code proves nothing.
    fn source() -> String {
        let production = include_str!("mcp_http.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("split always yields a first part")
            .to_string();
        production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn state_with(clients: Vec<McpClientCredential>, profiles: &[&str]) -> AppState {
        AppState::new(PolicyConfig {
            mcp_clients: clients,
            gateway_profiles: profiles
                .iter()
                .map(|name| ((*name).to_string(), GatewayProfile::default()))
                .collect::<BTreeMap<_, _>>(),
            ..PolicyConfig::default()
        })
        .expect("state")
    }

    fn credential(profile: Option<&str>) -> McpClientCredential {
        McpClientCredential {
            agent_id: "agent-alpha".into(),
            token_sha256: crate::admission::sha256_hex_for_tests("alpha"),
            profile: profile.map(str::to_string),
        }
    }

    fn headers_with_token() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            crate::admission::CLIENT_TOKEN_HEADER,
            "alpha".parse().unwrap(),
        );
        headers
    }

    // ── WD-2: the method table each lane serves ──────────────────────────────────────────

    /// WD-2's acceptance criterion: each lane's method table, asserted complete rather than
    /// merely present.
    ///
    /// NMCP-REF-001 rows D1 and D4 record that the two lanes answer different sets, and that the
    /// difference is essential rather than accidental: `tasks/*` exists only on the revision the
    /// POST lane can negotiate, and the WebSocket lane hardcodes a revision that does not have
    /// it. A test asserting each set is exactly what it should be is the thing that makes a
    /// future unification checkable, because it turns "the lanes differ" into a written-down
    /// difference somebody has to change on purpose.
    #[test]
    fn each_lane_answers_exactly_the_methods_the_divergence_table_records() {
        let code = source();

        // The POST lane's table, in the order it is written.
        let post_table = code
            .split("let response = match req.method.as_str() {")
            .nth(1)
            .expect("the POST method table");
        for method in [
            "initialize",
            "notifications/initialized",
            "tools/list",
            "server/discover",
            "tools/call",
            "tasks/get",
            "tasks/cancel",
            "tasks/update",
        ] {
            assert!(
                post_table.contains(&format!("\"{method}\"")),
                "the POST lane no longer answers {method}, which NMCP-REF-001 records it as \
                 answering"
            );
        }

        // The WebSocket lane's table. `tasks/*` is absent by construction, not by omission: this
        // lane hardcodes 2025-11-25, and that revision has no tasks extension. Answering them
        // here would teach a client something false about the revision it negotiated.
        let ws_lane = code
            .split("pub(crate) async fn handle_ws_message(")
            .nth(1)
            .expect("the WebSocket lane");
        // Bounded at the next item, because everything after this function is a different lane's
        // table or a helper, and an unbounded tail would let any later mention satisfy the
        // presence assertions above while hiding the absence assertions below.
        let ws_table = ws_lane
            .split("\n/// Dispatch a tool call with no client identity to record.")
            .next()
            .expect("the WebSocket lane ends");
        for method in [
            "initialize",
            "notifications/initialized",
            "tools/list",
            "server/discover",
            "tools/call",
        ] {
            assert!(
                ws_table.contains(&format!("\"{method}\"")),
                "the WebSocket lane no longer answers {method}"
            );
        }
        for absent in ["tasks/get", "tasks/cancel", "tasks/update"] {
            assert!(
                !ws_table.contains(&format!("\"{absent}\"")),
                "the WebSocket lane answers {absent}, which the revision it hardcodes does not \
                 define. Advertising a method the negotiated revision has no shape for is the \
                 dishonesty the supported-version list exists to prevent."
            );
        }
    }

    /// G6-11, ported and widened.
    ///
    /// The base's version counts unscoped `merged_tool_list(` calls, because that lane once
    /// enumerated every upstream for a profile-restricted session. Core's router takes a caller
    /// as well as a profile (RC-D8), so the same defect has a second spelling: a scoped call that
    /// passes `None` for the agent lists tools the caller's own allowlist forbids.
    #[test]
    fn every_request_lane_scopes_its_tool_list_to_both_the_profile_and_the_caller() {
        let code = source();
        let unscoped = code.match_indices("merged_tool_list(").count();
        let scoped = code.match_indices("merged_tool_list_for(").count();
        assert!(scoped > 0, "the parser lost the request lanes");
        assert_eq!(
            unscoped, 0,
            "a request lane calls merged_tool_list() without a profile. Every method here \
             answers a specific caller, so it must pass that session's scope: the unscoped list \
             is for readiness and doctor, which have no session to scope to."
        );
        // Per call site rather than by counting a second token anywhere in the file. The first
        // draft counted `identity.agent_id.as_str()` across the module and read six against four,
        // because the SSE lane and the connection handler both derive a `SessionOwner` from the
        // same expression. A count of one thing standing in for a property of another thing is
        // how a test passes for a reason it did not mean.
        for (at, _) in code.match_indices("merged_tool_list_for(") {
            let call = &code[at..(at + 200).min(code.len())];
            assert!(
                call.contains("agent_id"),
                "a scoped tool list was built without a caller. `list_for` applies \
                 CallerToolAllowlist unconditionally (RC-D8), so passing None lists tools the \
                 caller's own allowlist forbids, which is G6-8's defect one level down. At: {}",
                &call[..call.len().min(120)]
            );
        }
    }

    // ── WD-24: the SSE lane resolves a gateway profile ───────────────────────────────────

    /// WD-24, asserted per lane against the same credential.
    ///
    /// The credential is good on every lane. What it carries is a binding to a gateway profile
    /// this server does not have, which is a statement about the server's configuration rather
    /// than about the caller. Two lanes refuse it. The base's third admits it, and it is the lane
    /// that is on by default.
    #[tokio::test]
    async fn a_credential_bound_to_a_missing_profile_is_refused_on_every_lane() {
        // The profile is configured nowhere, so `session_profile` cannot honour the binding.
        let state = state_with(vec![credential(Some("reading"))], &[]);

        let (post_status, post_body) = mcp_post(
            axum::extract::State(state.clone()),
            headers_with_token(),
            None,
            Json(
                serde_json::from_value(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {}
                }))
                .unwrap(),
            ),
        )
        .await;
        assert_eq!(post_status, StatusCode::OK);
        assert_eq!(
            post_body.0["error"]["code"], -32003,
            "the POST lane must refuse a profile it cannot honour, as its own error code says"
        );

        let sse = mcp_get_sse(axum::extract::State(state), headers_with_token(), None)
            .await
            .into_response();
        assert_eq!(
            sse.status(),
            StatusCode::FORBIDDEN,
            "the SSE lane admitted a credential the other two refuse. It answers no scoped \
             method, so nothing downstream would have noticed: the refusal is the whole point of \
             resolving here."
        );
    }

    /// The same credential, with the profile configured, is admitted on both lanes.
    ///
    /// The negative control for the test above. Without it, refusing everything would pass.
    #[tokio::test]
    async fn the_same_credential_is_admitted_once_its_profile_exists() {
        let state = state_with(vec![credential(Some("reading"))], &["reading"]);

        let (post_status, post_body) = mcp_post(
            axum::extract::State(state.clone()),
            headers_with_token(),
            None,
            Json(
                serde_json::from_value(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {}
                }))
                .unwrap(),
            ),
        )
        .await;
        assert_eq!(post_status, StatusCode::OK);
        assert!(
            post_body.0.get("result").is_some(),
            "expected a result, got {}",
            post_body.0
        );

        let sse = mcp_get_sse(axum::extract::State(state), headers_with_token(), None)
            .await
            .into_response();
        assert_eq!(sse.status(), StatusCode::OK);
        assert!(sse.headers().contains_key("mcp-session-id"));
    }

    /// The WebSocket lane refuses before the upgrade rather than after it.
    ///
    /// Source-coupled because `WebSocketUpgrade` is an extractor a test cannot construct. The
    /// property is an ordering one and ordering is what the source shows: the profile check has
    /// to appear before `on_upgrade`, or a credential that cannot be honoured becomes an open
    /// socket that is then closed, which is a worse answer to the client and a real one to any
    /// connection counter.
    #[test]
    fn the_websocket_lane_refuses_an_unavailable_profile_before_the_upgrade() {
        let code = source();
        let lane = code
            .split("pub(crate) async fn mcp_websocket(")
            .nth(1)
            .expect("the WebSocket lane");
        let check = lane
            .find("session_profile_from_headers")
            .expect("the WebSocket lane resolves a profile");
        let upgrade = lane.find("on_upgrade").expect("the lane upgrades");
        assert!(
            check < upgrade,
            "the profile is resolved after the upgrade, so a credential that cannot be honoured \
             becomes an open socket first"
        );
    }

    // ── WD-D3: the socket re-authenticates ───────────────────────────────────────────────

    /// WD-D3, the ordering property, asserted where ordering lives.
    ///
    /// The behavioural half is below. This is the half a behavioural test cannot reach: that the
    /// call is inside the loop rather than before it. A socket that authenticates once and then
    /// serves forever passes every test that drives one message.
    #[test]
    fn the_websocket_loop_re_authenticates_inside_itself_rather_than_before_it() {
        let code = source();
        let connection = code
            .split("async fn handle_ws_connection(")
            .nth(1)
            .expect("the connection handler");
        let loop_at = connection
            .find("while let Some(Ok(msg)) = socket.recv().await")
            .expect("the message loop");
        let body = &connection[loop_at..];
        assert!(
            body.contains("authenticate_and_record"),
            "the message loop does not re-authenticate, so a credential revoked by a policy edit \
             keeps serving for the life of the socket. NMCP-SPEC-004 WD-D3."
        );
        assert!(
            body.contains("session_profile_from_headers"),
            "the message loop does not re-resolve the profile, so a profile the operator has \
             since changed keeps serving. WD-D3 covers both."
        );
    }

    /// The behavioural half: a credential removed from policy stops being accepted, through the
    /// shared handle the socket reads rather than a snapshot it captured.
    #[tokio::test]
    async fn a_credential_removed_from_policy_stops_being_accepted_without_a_restart() {
        let state = state_with(vec![credential(None)], &[]);
        let headers = headers_with_token();

        assert!(
            crate::admission::authenticate_and_record(&state, None, &headers)
                .await
                .expect("accepted while configured")
                .is_some()
        );

        // The edit a WD-D3 socket must observe: same state, new policy, no restart.
        state.replace_policy_for_tests(PolicyConfig {
            mcp_require_client_auth: true,
            ..PolicyConfig::default()
        });

        assert!(
            crate::admission::authenticate_and_record(&state, None, &headers)
                .await
                .is_err(),
            "the revoked credential is still accepted, so a live socket would still be serving it"
        );
    }

    // ── WD-25: two implemented, one withdrawn ────────────────────────────────────────────

    /// Every capability this lane advertises as true has a reachable implementation.
    ///
    /// WD-25's acceptance criterion. `cancellation_routing` is the one that is false, and it is
    /// false because nothing here routes a cancellation: the assertion pairs the flag with the
    /// absence, so flipping the flag without doing the work fails, and doing the work without
    /// flipping the flag fails too.
    #[test]
    fn the_welcome_frame_advertises_nothing_this_lane_cannot_do() {
        let state = AppState::new(PolicyConfig::default()).expect("state");
        let advertised = advertised_capabilities(&state);
        let code = source();

        assert!(
            !advertised.cancellation_routing,
            "cancellation routing is advertised. `CancellationRegistry` is named nowhere in this \
             module: no lane registers a token, nothing handles notifications/cancelled, and no \
             long-running handler polls one."
        );
        assert!(
            !code.contains("CancellationRegistry"),
            "this module now names CancellationRegistry, so the withdrawal above may be stale. \
             Implementing cancellation means flipping that flag in the same change."
        );

        assert!(
            advertised.in_memory_replay && advertised.redaction_pipeline,
            "both are advertised and both are backed by the same call"
        );
        assert!(
            code.contains(".emit("),
            "in-memory replay and the redaction pipeline are advertised and nothing emits. \
             `SessionRegistry::emit` is the only writer of the replay journal and the only caller \
             of the redactor, so without it replay returns empty and no live path redacts \
             anything."
        );
    }

    /// The journal is written, replayed to its owner, and redacted on the way in.
    ///
    /// One test rather than three because the three are one property: the journal is a retained
    /// copy of what this socket sent, so replay without redaction would create the exposure the
    /// redactor exists to prevent. Implementing them separately is what would have been wrong.
    #[test]
    fn an_emitted_response_replays_to_its_owner_with_secrets_removed() {
        let state = AppState::new(PolicyConfig::default()).expect("state");
        let owner = SessionOwner::from_agent(Some("agent-alpha"));
        let session_id = state
            .transport
            .create_session(owner.clone())
            .expect("session");
        let stream_id = state.transport.create_stream(&session_id).expect("stream");

        state
            .transport
            .emit(
                &session_id,
                &stream_id,
                WS_RESPONSE_EVENT,
                json!({"jsonrpc": "2.0", "id": 1, "result": {"access_token": "s3cret"}}),
            )
            .expect("emit");

        let replayed = state
            .transport
            .replay(
                &ResumeCursor {
                    session_id: session_id.clone(),
                    stream_id: stream_id.clone(),
                    after_event_id: EventId::new(0),
                },
                &owner,
            )
            .expect("replay");
        assert_eq!(replayed.len(), 1, "the journal was not written");
        assert_eq!(replayed[0].event_type, WS_RESPONSE_EVENT);
        assert_eq!(
            replayed[0].payload["result"]["access_token"], "[REDACTED]",
            "a token reached the replay journal in the clear. The journal is a retained copy of \
             every response, so implementing replay without redaction creates the exposure the \
             redactor exists to prevent."
        );

        // G3-16. A different caller replaying the same cursor is answered as if the session did
        // not exist, which is the same answer a session that does not exist gets.
        assert!(
            state
                .transport
                .replay(
                    &ResumeCursor {
                        session_id,
                        stream_id,
                        after_event_id: EventId::new(0),
                    },
                    &SessionOwner::from_agent(Some("agent-beta")),
                )
                .is_err()
        );
    }

    // ── The session lifecycle, directly ──────────────────────────────────────────────────

    /// A session this caller does not own is answered exactly as one that does not exist.
    #[test]
    fn a_session_another_caller_owns_is_indistinguishable_from_one_that_is_absent() {
        let state = AppState::new(PolicyConfig::default()).expect("state");
        let alpha = SessionOwner::from_agent(Some("agent-alpha"));
        let beta = SessionOwner::from_agent(Some("agent-beta"));
        let session_id = state.transport.create_session(alpha).expect("session");

        let stolen = sse_session(&state, Some(session_id), None, 0, &beta)
            .expect_err("another caller's session is refused");
        let absent = sse_session(
            &state,
            Some(SessionId::from_string("does-not-exist")),
            None,
            0,
            &beta,
        )
        .expect_err("a session that does not exist is refused");
        assert_eq!(
            stolen.status(),
            absent.status(),
            "the two answers differ, which hands an attacker a session-id oracle and is most of \
             the work of the attack this closes"
        );
        assert_eq!(stolen.status(), StatusCode::NOT_FOUND);
    }

    // ── Ported behavioural coverage for the WebSocket frame handler ──────────────────────

    #[tokio::test]
    async fn the_websocket_handler_answers_a_known_method_and_refuses_an_unknown_one() {
        let state = AppState::new(PolicyConfig::default()).expect("state");
        let session_id = state
            .transport
            .create_session(SessionOwner::from_agent(None))
            .expect("session");

        let listed = handle_ws_message(
            &state,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
            session_id.clone(),
            None,
            None,
            None,
        )
        .await;
        assert!(listed["result"]["tools"].is_array());

        let unknown = handle_ws_message(
            &state,
            r#"{"jsonrpc":"2.0","id":2,"method":"no/such/method","params":{}}"#,
            session_id.clone(),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(unknown["error"]["code"], -32601);

        let malformed = handle_ws_message(&state, "{not json", session_id, None, None, None).await;
        assert_eq!(malformed["error"]["code"], -32700);
    }

    // ── Protocol negotiation ─────────────────────────────────────────────────────────────

    /// WD-6. An unsupported revision is a 400 naming it, never a silent downgrade.
    #[tokio::test]
    async fn an_unsupported_protocol_revision_is_refused_rather_than_defaulted() {
        let state = AppState::new(PolicyConfig::default()).expect("state");
        let mut headers = HeaderMap::new();
        headers.insert("mcp-protocol-version", "1999-01-01".parse().unwrap());

        let (status, body) = mcp_post(
            axum::extract::State(state),
            headers,
            None,
            Json(
                serde_json::from_value(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {}
                }))
                .unwrap(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.0["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("1999-01-01")),
            "the refusal must name the revision it refused: {}",
            body.0
        );
    }

    /// The origin allowlist applies to both lanes, with the shapes each one has.
    #[tokio::test]
    async fn a_forbidden_origin_is_refused_on_both_lanes_in_each_lanes_own_shape() {
        let state = AppState::new(PolicyConfig::default()).expect("state");
        let mut headers = HeaderMap::new();
        headers.insert("origin", "https://not-allowed.example".parse().unwrap());

        // NMCP-REF-001 D9: the POST lane answers 200 with a JSON-RPC envelope and the SSE lane
        // answers 403 with a bare object. Preserved rather than normalised, because the desktop
        // connector reads the first shape and normalising would be a breaking change dressed as
        // a cleanup.
        let (status, body) = mcp_post(
            axum::extract::State(state.clone()),
            headers.clone(),
            None,
            Json(
                serde_json::from_value(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {}
                }))
                .unwrap(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.0["error"]["code"], -32001);

        let sse = mcp_get_sse(axum::extract::State(state), headers, None)
            .await
            .into_response();
        assert_eq!(sse.status(), StatusCode::FORBIDDEN);
    }
}
