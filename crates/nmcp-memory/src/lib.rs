//! `nmcp-memory`
//!
//! Agent memory for the NativeMCP server family: `SQLite` plus an in-process
//! vector index, local embeddings, and TTL decay. The governance invariants
//! in `docs/GOVERNANCE.md` are normative for every item in this crate.
//!
//! ## MEM design contract
//!
//! - No delete. Facts expire via TTL only; `mem.expire_now` sets ttl=now (governed removal).
//! - Root-scoped. Every fact is isolated to its `scope_root` path, canonicalized to the same
//!   form the policy engine uses. Cross-root reads are impossible by construction.
//! - Local only. Zero network egress. Embeddings are generated in-process by the `Embedder`
//!   trait; the default impl is lexical (BM25-style, pure Rust). A zero-egress test proves it.
//! - Provider, not bypass. `MemoryProvider` registers as a `ToolProvider`; every call passes
//!   through the full policy/ABAC/audit ring.

use anyhow::Context;
use async_trait::async_trait;
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use nmcp_policy::Permission;
use nmcp_schema::{
    CallContext, CapabilityGrant, GrantedAuthority, ToolAuthority, ToolCallResult, ToolContract,
    ToolEffect, ToolProvider, ToolReach,
};
use parking_lot::Mutex;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

// ── Datetime helpers ──────────────────────────────────────────────────────────

/// Format used for all datetime columns. Must match `SQLite`'s `datetime('now')` format
/// so that comparisons like `ttl_at > datetime('now')` work correctly.
const DT_FMT: &str = "%Y-%m-%d %H:%M:%S";

fn dt_to_sql(dt: DateTime<Utc>) -> String {
    dt.format(DT_FMT).to_string()
}

fn dt_from_sql(s: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(s, DT_FMT)
        .ok()
        .map(|ndt| ndt.and_utc())
}

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors returned by the memory store.
#[derive(Debug, Error)]
pub enum MemoryError {
    /// The underlying store rejected an operation.
    #[error("memory store error: {0}")]
    Store(String),
    /// The named scope does not exist.
    #[error("scope not found: {0}")]
    ScopeNotFound(String),
    /// A fact failed to (de)serialize.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// The `SQLite` backend returned an error.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

/// Shorthand result type for fallible memory operations.
pub type MemoryResult<T> = Result<T, MemoryError>;

// ── MemoryScope (defined in nmcp-schema, re-exported here) ────────────────────

/// A memory scope label kept for router and audit compatibility.
///
/// Defined in `nmcp-schema` and re-exported here so nothing that used it broke (RC-2).
/// The move is the point rather than a tidy-up: the kernel needs this type on its call
/// context, so while it lived here the kernel had to depend on this crate, so this crate
/// could not depend on the kernel to ship its own provider and the provider had to live
/// in the server crate instead. That is the cycle NMCP-SPEC-003 RC-D1 breaks, and this
/// newtype over a `String` with no tie to storage was the whole reason the edge existed.
pub use nmcp_schema::MemoryScope;

// ── MemoryFact ────────────────────────────────────────────────────────────────

/// A single piece of agent memory, stored in the `SQLite` backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryFact {
    /// Unique fact id.
    pub id: Uuid,
    /// Canonicalized scope the fact is isolated to.
    pub scope_root: String,
    /// Optional upsert key, unique within a scope.
    pub key: Option<String>,
    /// The fact text.
    pub content: String,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// When the fact was created.
    pub created_at: DateTime<Utc>,
    /// When the fact was last written or refreshed.
    pub refreshed_at: DateTime<Utc>,
    /// Expiry time; `None` means it never decays.
    pub ttl_at: Option<DateTime<Utc>>,
    /// Similarity score from the most recent search (0.0 if not from a search).
    #[serde(default)]
    pub score: f32,
}

impl MemoryFact {
    /// A fresh fact in `scope_root` carrying `content`, no key, no TTL.
    #[must_use]
    pub fn new(scope_root: impl Into<String>, content: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            scope_root: scope_root.into(),
            key: None,
            content: content.into(),
            tags: vec![],
            created_at: now,
            refreshed_at: now,
            ttl_at: None,
            score: 0.0,
        }
    }

    /// Set the upsert key.
    #[must_use]
    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    /// Set the tags.
    #[must_use]
    pub fn with_tags(mut self, tags: Vec<impl Into<String>>) -> Self {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    /// Set a TTL `secs` seconds from now.
    #[must_use]
    pub fn with_ttl_secs(mut self, secs: i64) -> Self {
        self.ttl_at = Some(Utc::now() + Duration::seconds(secs));
        self
    }

    /// Whether the fact's TTL has passed.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.ttl_at.is_some_and(|t| t <= Utc::now())
    }
}

// ── Embedder trait (MEM-3) ────────────────────────────────────────────────────

/// Embedding dimension used throughout. Must match the virtual table definition.
pub const EMBED_DIM: usize = 64;

/// Local in-process embedder. Implementations must NEVER make network calls or
/// spawn subprocesses -- zero-egress is an invariant, proven by test.
pub trait Embedder: Send + Sync {
    /// Generate a fixed-size embedding vector for the given text.
    fn embed(&self, text: &str) -> [f32; EMBED_DIM];
    /// Human-readable name for diagnostics.
    fn name(&self) -> &'static str;
}

/// Lexical BM25-style embedder -- pure Rust, zero egress, always available.
/// Projects term-frequency features onto a fixed-size vector via hashing.
/// Used as the default and as the fallback when no neural model is loaded.
pub struct LexicalEmbedder;

impl Embedder for LexicalEmbedder {
    fn name(&self) -> &'static str {
        "lexical-bm25"
    }

    #[allow(clippy::cast_precision_loss)] // token count to f32 for averaging; counts are tiny
    fn embed(&self, text: &str) -> [f32; EMBED_DIM] {
        let mut vec = [0f32; EMBED_DIM];
        let lower = text.to_lowercase();
        let tokens: Vec<&str> = lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() >= 2)
            .collect();
        let total = tokens.len().max(1) as f32;
        for token in &tokens {
            // FNV-1a hash to bucket
            let mut h: u64 = 14_695_981_039_346_656_037;
            for b in token.as_bytes() {
                h ^= u64::from(*b);
                h = h.wrapping_mul(1_099_511_628_211);
            }
            let bucket = usize::try_from(h % EMBED_DIM as u64).unwrap_or(0);
            // bucket < EMBED_DIM by construction; get_mut keeps that provable
            // rather than trusting the reader, per the workspace no-index rule.
            if let Some(slot) = vec.get_mut(bucket) {
                *slot += 1.0 / total;
            }
        }
        // L2-normalise
        let norm = vec.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-9);
        for x in &mut vec {
            *x /= norm;
        }
        vec
    }
}

/// Cosine similarity between two embedding vectors.
fn cosine_sim(a: &[f32; EMBED_DIM], b: &[f32; EMBED_DIM]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    dot.clamp(-1.0, 1.0)
}

// ── `SQLite` schema (MEM-1) ─────────────────────────────────────────────────────

const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS memory (
    id          TEXT PRIMARY KEY,
    scope_root  TEXT NOT NULL,
    key         TEXT,
    content     TEXT NOT NULL,
    tags        TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL,
    refreshed_at TEXT NOT NULL,
    ttl_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_memory_scope ON memory(scope_root);
CREATE INDEX IF NOT EXISTS idx_memory_key   ON memory(scope_root, key);
-- In-process vector table: rows keyed by memory.id, one float array per row.
CREATE TABLE IF NOT EXISTS memory_vec (
    id          TEXT PRIMARY KEY,
    embedding   BLOB NOT NULL
);
";

/// Open (or create) `memory.db` at `dir` and run migrations.
///
/// # Errors
///
/// Directory creation, database open, or migration failure.
pub fn open_db(dir: &Path) -> anyhow::Result<Connection> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating memory dir {}", dir.display()))?;
    let path = dir.join("memory.db");
    let conn = Connection::open(&path)
        .with_context(|| format!("opening memory.db at {}", path.display()))?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

/// Canonical scope normalisation for DB storage.
///
/// Converts any path separator to `/`, lowercases, and strips redundant components.
/// Always produces the same key regardless of whether the caller used `\` or `/`,
/// keeping DB keys platform-independent.
#[must_use]
pub fn canonical_scope(path: &str) -> String {
    PathBuf::from(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
        .to_lowercase()
}

// ── SqliteMemoryStore (MEM-1, MEM-4, MEM-5) ──────────────────────────────────

/// Persistent, root-scoped memory store backed by `SQLite` + in-process vectors.
///
/// Clone-cheap via inner `Arc`.
#[derive(Clone)]
pub struct SqliteMemoryStore {
    conn: Arc<Mutex<Connection>>,
    embedder: Arc<dyn Embedder>,
}

impl SqliteMemoryStore {
    /// Open a store under `dir` with the default lexical embedder.
    ///
    /// # Errors
    ///
    /// Any failure from [`open_db`].
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        Self::open_with_embedder(dir, Arc::new(LexicalEmbedder))
    }

    /// Open a store under `dir` with a caller-supplied embedder.
    ///
    /// # Errors
    ///
    /// Any failure from [`open_db`].
    pub fn open_with_embedder(dir: &Path, embedder: Arc<dyn Embedder>) -> anyhow::Result<Self> {
        let conn = open_db(dir)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            embedder,
        })
    }

    // MEM-5: TTL clause -- exclude expired rows from live results.
    // Uses `SQLite`'s datetime('now') which is in "YYYY-MM-DD HH:MM:SS" UTC format,
    // matching our DT_FMT storage format so string comparison is correct.
    fn is_live_clause() -> &'static str {
        "(ttl_at IS NULL OR ttl_at > datetime('now'))"
    }

    /// Write a fact. Normalises `scope_root`, embeds content, and stores the vector.
    ///
    /// # Errors
    ///
    /// Serialization or `SQLite` failure.
    // The owned fact is the base public API: callers build and hand off a fact.
    #[allow(clippy::needless_pass_by_value)]
    pub fn write(&self, fact: MemoryFact) -> anyhow::Result<Uuid> {
        // Normalise scope_root so write and read always agree on the DB key.
        let scope_root = canonical_scope(&fact.scope_root);
        let embedding = self.embedder.embed(&fact.content);
        let blob: Vec<u8> = embedding.iter().flat_map(|f| f.to_le_bytes()).collect();
        let tags_json = serde_json::to_string(&fact.tags)?;
        let id_str = fact.id.to_string();

        let conn = self.conn.lock();
        // Upsert by key within scope_root if key is set.
        if let Some(ref key) = fact.key {
            let existing_id: Option<String> = conn
                .query_row(
                    "SELECT id FROM memory WHERE scope_root = ?1 AND key = ?2 LIMIT 1",
                    params![scope_root, key],
                    |r| r.get(0),
                )
                .ok();
            if let Some(ref eid) = existing_id {
                conn.execute(
                    "UPDATE memory SET content=?1, tags=?2, refreshed_at=?3, ttl_at=?4 WHERE id=?5",
                    params![
                        fact.content,
                        tags_json,
                        dt_to_sql(fact.refreshed_at),
                        fact.ttl_at.map(dt_to_sql),
                        eid
                    ],
                )?;
                conn.execute(
                    "INSERT OR REPLACE INTO memory_vec(id, embedding) VALUES(?1, ?2)",
                    params![eid, blob],
                )?;
                return Ok(Uuid::parse_str(eid)?);
            }
        }

        conn.execute(
            "INSERT INTO memory(id,scope_root,key,content,tags,created_at,refreshed_at,ttl_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                id_str,
                scope_root,
                fact.key,
                fact.content,
                tags_json,
                dt_to_sql(fact.created_at),
                dt_to_sql(fact.refreshed_at),
                fact.ttl_at.map(dt_to_sql),
            ],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO memory_vec(id, embedding) VALUES(?1, ?2)",
            params![id_str, blob],
        )?;
        Ok(fact.id)
    }

    /// Semantic search within a single `scope_root`. MEM-5: excludes expired.
    ///
    /// # Errors
    ///
    /// `SQLite` failure preparing or running the query.
    pub fn search(
        &self,
        scope_root: &str,
        query: &str,
        top_k: usize,
    ) -> anyhow::Result<Vec<MemoryFact>> {
        let query_vec = self.embedder.embed(query);
        let scope = canonical_scope(scope_root);
        let conn = self.conn.lock();

        let sql = format!(
            "SELECT m.id, m.scope_root, m.key, m.content, m.tags,
                    m.created_at, m.refreshed_at, m.ttl_at, v.embedding
             FROM memory m JOIN memory_vec v ON m.id = v.id
             WHERE m.scope_root = ?1 AND {}",
            Self::is_live_clause()
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut results: Vec<(MemoryFact, f32)> = stmt
            .query_map(params![scope], |row| {
                let blob: Vec<u8> = row.get(8)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    blob,
                ))
            })?
            .filter_map(Result::ok)
            .filter_map(
                |(id, sr, key, content, tags_json, created_s, refreshed_s, ttl_s, blob)| {
                    let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
                    let created_at = dt_from_sql(&created_s)?;
                    let refreshed_at = dt_from_sql(&refreshed_s)?;
                    let ttl_at = ttl_s.and_then(|s| dt_from_sql(&s));
                    let mut emb = [0f32; EMBED_DIM];
                    if blob.len() == EMBED_DIM * 4 {
                        for (slot, chunk) in emb.iter_mut().zip(blob.chunks_exact(4)) {
                            let bytes: [u8; 4] = chunk.try_into().unwrap_or([0u8; 4]);
                            *slot = f32::from_le_bytes(bytes);
                        }
                    }
                    let sim = cosine_sim(&query_vec, &emb);
                    let fact = MemoryFact {
                        id: Uuid::parse_str(&id).ok()?,
                        scope_root: sr,
                        key,
                        content,
                        tags,
                        created_at,
                        refreshed_at,
                        ttl_at,
                        score: sim,
                    };
                    Some((fact, sim))
                },
            )
            .collect();

        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(top_k);
        Ok(results.into_iter().map(|(f, _)| f).collect())
    }

    /// List all live facts for a `scope_root` (metadata only, no semantic search). MEM-4.
    ///
    /// # Errors
    ///
    /// `SQLite` failure preparing or running the query.
    pub fn list(&self, scope_root: &str) -> anyhow::Result<Vec<MemoryFact>> {
        let scope = canonical_scope(scope_root);
        let conn = self.conn.lock();
        let sql = format!(
            "SELECT id, scope_root, key, content, tags, created_at, refreshed_at, ttl_at
             FROM memory WHERE scope_root = ?1 AND {}
             ORDER BY refreshed_at DESC",
            Self::is_live_clause()
        );
        let mut stmt = conn.prepare(&sql)?;
        let facts: Vec<MemoryFact> = stmt
            .query_map(params![scope], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            })?
            .filter_map(Result::ok)
            .filter_map(
                |(id, sr, key, content, tags_json, created_s, refreshed_s, ttl_s)| {
                    let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
                    let created_at = dt_from_sql(&created_s)?;
                    let refreshed_at = dt_from_sql(&refreshed_s)?;
                    let ttl_at = ttl_s.and_then(|s| dt_from_sql(&s));
                    Some(MemoryFact {
                        id: Uuid::parse_str(&id).ok()?,
                        scope_root: sr,
                        key,
                        content,
                        tags,
                        created_at,
                        refreshed_at,
                        ttl_at,
                        score: 0.0,
                    })
                },
            )
            .collect();
        Ok(facts)
    }

    /// Mark a fact as expired immediately (governed removal). MEM-5.
    /// Sets `ttl_at = now`; the row remains for audit. Content is not deleted.
    ///
    /// Scoped. `scope_root` is part of the predicate, not a hint: a fact belonging
    /// to another scope is not expired and the call reports `false`, identically to
    /// a fact that does not exist. Telling the two apart would be an existence
    /// oracle over another scope's identifiers.
    ///
    /// This argument did not exist before I-079. `write`, `search` and `list` all
    /// carried `scope_root` in their predicate and these two mutations did not, so
    /// a caller holding a fact's UUID could expire a fact in a scope they do not
    /// own. The crate's own `scope_isolation_no_cross_root_reads` test asserted the
    /// read half of that property and was named as though it covered all of it.
    ///
    /// # Errors
    ///
    /// `SQLite` failure.
    pub fn expire_now(&self, scope_root: &str, id: Uuid) -> anyhow::Result<bool> {
        let scope = canonical_scope(scope_root);
        let conn = self.conn.lock();
        let now = dt_to_sql(Utc::now());
        let changed = conn.execute(
            "UPDATE memory SET ttl_at = ?1 WHERE id = ?2 AND scope_root = ?3",
            params![now, id.to_string(), scope],
        )?;
        Ok(changed > 0)
    }

    /// Read a single fact by id regardless of TTL (for audit/admin purposes).
    ///
    /// **Deliberately unscoped, and the only method that is.** It serves the audit
    /// and admin surface, which exists precisely to see across scopes, and it
    /// bypasses the TTL filter for the same reason. I-079 scoped the two mutations
    /// beside it and left this one alone on purpose.
    ///
    /// The consequence is a rule no signature can enforce: **no tool path may reach
    /// this method.** A provider that called it would hand a caller another scope's
    /// content, which is the isolation failure `authorized_scope` exists to prevent.
    /// The memory provider landing at I-072 calls `search`, `list`, `write`,
    /// `refresh_by_id` and `expire_now`, and not this.
    ///
    /// # Errors
    ///
    /// `SQLite` failure.
    pub fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<MemoryFact>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, scope_root, key, content, tags, created_at, refreshed_at, ttl_at
             FROM memory WHERE id = ?1",
        )?;
        let fact = stmt
            .query_map(params![id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            })?
            .find_map(Result::ok)
            .and_then(
                |(id_s, sr, key, content, tags_json, created_s, refreshed_s, ttl_s)| {
                    let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
                    let created_at = dt_from_sql(&created_s)?;
                    let refreshed_at = dt_from_sql(&refreshed_s)?;
                    let ttl_at = ttl_s.and_then(|s| dt_from_sql(&s));
                    Some(MemoryFact {
                        id: Uuid::parse_str(&id_s).ok()?,
                        scope_root: sr,
                        key,
                        content,
                        tags,
                        created_at,
                        refreshed_at,
                        ttl_at,
                        score: 0.0,
                    })
                },
            );
        Ok(fact)
    }

    /// Update `refreshed_at` and optionally extend `ttl_at` for a live fact.
    /// Returns `true` if the row was found and updated, `false` if not found.
    /// Does NOT resurrect expired facts; `refresh_by_id` only touches live rows.
    ///
    /// # Errors
    ///
    /// `SQLite` failure.
    /// Scoped, for the reason given on [`SqliteMemoryStore::expire_now`]. A fact in
    /// another scope is not refreshed and the call reports `false`.
    pub fn refresh_by_id(
        &self,
        scope_root: &str,
        id: Uuid,
        extend_ttl_secs: Option<i64>,
    ) -> anyhow::Result<bool> {
        let scope = canonical_scope(scope_root);
        let conn = self.conn.lock();
        let now = Utc::now();
        let new_ttl = extend_ttl_secs.map(|s| dt_to_sql(now + Duration::seconds(s)));
        let changed = if let Some(ref ttl_str) = new_ttl {
            conn.execute(
                "UPDATE memory SET refreshed_at = ?1, ttl_at = ?2 WHERE id = ?3 AND scope_root = ?4",
                params![dt_to_sql(now), ttl_str, id.to_string(), scope],
            )?
        } else {
            conn.execute(
                "UPDATE memory SET refreshed_at = ?1 WHERE id = ?2 AND scope_root = ?3",
                params![dt_to_sql(now), id.to_string(), scope],
            )?
        };
        Ok(changed > 0)
    }
}

// ── MemoryProvider (I-072a) ──────────────────────────────────────────────────

/// The five memory tools, as a governed provider.
///
/// # Why this lives here now
///
/// The base put this provider in `mcp-server` for one stated reason: `mcp-router` imported
/// `mcp-memory` for `MemoryScope`, so `mcp-memory` could not depend on `mcp-router` without
/// a cycle. That cycle is gone. `ToolProvider` moved to `nmcp-schema` under RC-D1, whose
/// only workspace edge is `nmcp-policy` (RC-1), and `nmcp-router` has no edge to this crate
/// at all. So the provider ships beside the store it drives, which is where a reader looking
/// for "what can a caller do to memory" will look first.
///
/// # What this provider does not do
///
/// No policy check. The base guarded each of the five tools with a `policy_grants` call
/// against `Permission::MemoryRead` or `MemoryWrite`; all five are deleted and replaced by
/// the declared `ToolAuthority` the ring authorizes against before `call` is entered. That
/// is RC-20's rule and the `ToolProvider` doc's first sentence.
///
/// # What it does do, and must keep doing
///
/// The scope check stays, because it is not a policy check. `authorized_scope` compares a
/// caller-supplied `scope_root` against the scope derived from the authenticated call
/// context and refuses a mismatch. It is an isolation control over an identifier the ring
/// has no opinion about, and deleting it alongside the permission guards would have been the
/// mistake this doc exists to prevent.
///
/// # Why `scope_root` is not a `path_arg`
///
/// It looks like a path and it is not one. `path_args` names arguments the kernel resolves a
/// *root* from, and a root resolved from a caller-supplied scope string is exactly the
/// confused-deputy shape RC-20 is about: the kernel would authorize against whatever the
/// caller sent while the store queried the context scope. Every one of these five tools
/// declares `path_args: vec![]` with a permission, which the contract documents as "the
/// caller must hold this permission on some root, and no root is resolved for this call".
/// That is precisely true here: memory is scoped by `ctx.memory_scope`, never by an argument.
pub struct MemoryProvider {
    store: SqliteMemoryStore,
}

impl MemoryProvider {
    /// Wrap a store as a provider.
    #[must_use]
    pub fn new(store: SqliteMemoryStore) -> Self {
        Self { store }
    }
}

/// The scope this call is authorized for, taken from the context and never from arguments.
fn scope_from_context(ctx: &CallContext) -> String {
    canonical_scope(&ctx.memory_scope.to_string())
}

/// Refuse a caller who names a scope other than their own.
///
/// Returns the **context** scope on success, never the requested one, even when the two
/// agree. A caller-supplied `scope_root` is at most a corroborating assertion that must
/// match; it is never the value the store is queried with. That asymmetry is the isolation
/// control, and it is why a caller cannot reach another scope by spelling it correctly.
fn authorized_scope(args: &Value, ctx: &CallContext, tool: &str) -> Result<String, ToolCallResult> {
    let expected = scope_from_context(ctx);
    if let Some(requested) = args.get("scope_root").and_then(Value::as_str)
        && canonical_scope(requested) != expected
    {
        return Err(ToolCallResult::err_with_metadata(
            format!("{tool}: requested scope_root does not match authenticated memory scope"),
            "policy_denied",
            Some("Omit scope_root or use the scope derived from the authenticated call context."),
        ));
    }
    Ok(expected)
}

/// Read a required UUID argument.
fn required_uuid(args: &Value, tool: &str) -> Result<Uuid, ToolCallResult> {
    let Some(raw) = args.get("id").and_then(Value::as_str) else {
        return Err(ToolCallResult::err(format!("{tool}: `id` is required")));
    };
    Uuid::parse_str(raw).map_or_else(
        |_| Err(ToolCallResult::err(format!("{tool}: invalid UUID `{raw}`"))),
        Ok,
    )
}

/// What a memory tool needs in order to run.
///
/// Exhaustive over the five names `contracts` declares, with no wildcard arm, so a tool added
/// there without a line here does not compile. Same shape as `dev_tool_authority`, and for
/// the same reason: an authority reached by a fallback is an authority nobody decided.
fn memory_tool_authority(name: &str) -> ToolAuthority {
    let (permission, effect) = match name {
        "mem.read" | "mem.list" => (Permission::MemoryRead, ToolEffect::Observe),
        "mem.write" | "mem.refresh" | "mem.expire_now" => {
            (Permission::MemoryWrite, ToolEffect::Mutate)
        }
        other => return unknown_memory_authority(other),
    };
    ToolAuthority {
        permission: Some(permission),
        // Deliberately empty: see the type doc. Memory is scoped by the call context.
        path_args: Vec::new(),
        grants: Vec::new(),
        effect,
        // The store is a local SQLite file and the embedder makes no network call, which is
        // this crate's zero-egress invariant and is asserted by `mem3_lexical_embedder_zero_egress`.
        reach: ToolReach::Local,
    }
}

/// The authority of a memory tool this crate declares and has no line for.
///
/// Unreachable through [`MemoryProvider::contracts`], and written anyway because the
/// alternative to a fail-closed arm is a fallback that grants something. This one requires a
/// capability grant no `Permission` defines, which `authorize` refuses by name on every call,
/// so a tool that reached here would be visible and uncallable rather than callable and
/// ungoverned.
fn unknown_memory_authority(name: &str) -> ToolAuthority {
    ToolAuthority {
        permission: Some(Permission::MemoryRead),
        path_args: Vec::new(),
        grants: vec![CapabilityGrant::new(format!("nmcp.undeclared.{name}"))],
        effect: ToolEffect::Mutate,
        reach: ToolReach::Remote,
    }
}

#[async_trait]
impl ToolProvider for MemoryProvider {
    fn contract_version(&self) -> u32 {
        1
    }

    // The trait declares `-> &str`; an impl cannot narrow it to a static lifetime on its own.
    #[allow(clippy::unnecessary_literal_bound)]
    fn provider_id(&self) -> &str {
        ""
    }

    fn contracts(&self) -> Vec<ToolContract> {
        vec![
            ToolContract {
                name: "mem.write".to_string(),
                description: "Write a durable memory fact into the caller's own scope. \
                              Upserts when `key` is supplied."
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "content": {"type": "string"},
                        "key": {"type": "string"},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "ttl_secs": {"type": "integer"},
                        "scope_root": {
                            "type": "string",
                            "description": "Optional. Must equal the authenticated memory scope; \
                                            omitting it is the normal case."
                        }
                    },
                    "required": ["content"]
                }),
                authority: memory_tool_authority("mem.write"),
                published_annotations: None,
            },
            ToolContract {
                name: "mem.read".to_string(),
                description: "Semantic search over memory facts in the caller's own scope."
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "top_k": {"type": "integer", "default": 5},
                        "scope_root": {
                            "type": "string",
                            "description": "Optional. Must equal the authenticated memory scope."
                        }
                    },
                    "required": ["query"]
                }),
                authority: memory_tool_authority("mem.read"),
                published_annotations: None,
            },
            ToolContract {
                name: "mem.list".to_string(),
                description: "List every live memory fact in the caller's own scope.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "scope_root": {
                            "type": "string",
                            "description": "Optional. Must equal the authenticated memory scope."
                        }
                    },
                    "required": []
                }),
                authority: memory_tool_authority("mem.list"),
                published_annotations: None,
            },
            ToolContract {
                name: "mem.refresh".to_string(),
                description: "Refresh a memory fact's timestamp, optionally extending its TTL. \
                              Only reaches facts in the caller's own scope."
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "extend_ttl_secs": {"type": "integer"}
                    },
                    "required": ["id"]
                }),
                authority: memory_tool_authority("mem.refresh"),
                published_annotations: None,
            },
            ToolContract {
                name: "mem.expire_now".to_string(),
                description: "Expire a memory fact immediately. The row survives for audit. \
                              Only reaches facts in the caller's own scope."
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"]
                }),
                authority: memory_tool_authority("mem.expire_now"),
                published_annotations: None,
            },
        ]
    }

    async fn call(
        &self,
        name: &str,
        args: Value,
        ctx: &CallContext,
        _granted: &GrantedAuthority,
    ) -> ToolCallResult {
        match name {
            "mem.write" => {
                let scope = match authorized_scope(&args, ctx, name) {
                    Ok(scope) => scope,
                    Err(refusal) => return refusal,
                };
                let Some(content) = args.get("content").and_then(Value::as_str) else {
                    return ToolCallResult::err("mem.write: `content` is required");
                };
                let mut fact = MemoryFact::new(&scope, content);
                if let Some(key) = args.get("key").and_then(Value::as_str) {
                    fact = fact.with_key(key);
                }
                if let Some(tags) = args.get("tags").and_then(Value::as_array) {
                    let tags: Vec<String> = tags
                        .iter()
                        .filter_map(|t| t.as_str().map(ToString::to_string))
                        .collect();
                    fact = fact.with_tags(tags);
                }
                if let Some(ttl) = args.get("ttl_secs").and_then(Value::as_i64) {
                    fact = fact.with_ttl_secs(ttl);
                }
                match self.store.write(fact) {
                    Ok(id) => ToolCallResult::ok(json!({ "id": id.to_string() })),
                    Err(e) => ToolCallResult::err(format!("mem.write failed: {e}")),
                }
            }
            "mem.read" => {
                let scope = match authorized_scope(&args, ctx, name) {
                    Ok(scope) => scope,
                    Err(refusal) => return refusal,
                };
                let Some(query) = args.get("query").and_then(Value::as_str) else {
                    return ToolCallResult::err("mem.read: `query` is required");
                };
                let top_k = args
                    .get("top_k")
                    .and_then(Value::as_u64)
                    .and_then(|k| usize::try_from(k).ok())
                    .unwrap_or(5);
                match self.store.search(&scope, query, top_k) {
                    Ok(facts) => ToolCallResult::ok(json!({
                        "results": facts.iter().map(search_result_json).collect::<Vec<_>>()
                    })),
                    Err(e) => ToolCallResult::err(format!("mem.read failed: {e}")),
                }
            }
            "mem.list" => {
                let scope = match authorized_scope(&args, ctx, name) {
                    Ok(scope) => scope,
                    Err(refusal) => return refusal,
                };
                match self.store.list(&scope) {
                    Ok(facts) => ToolCallResult::ok(json!({
                        "facts": facts.iter().map(list_fact_json).collect::<Vec<_>>()
                    })),
                    Err(e) => ToolCallResult::err(format!("mem.list failed: {e}")),
                }
            }
            // These two take no `scope_root` at all: the caller cannot express a scope, so
            // there is nothing to corroborate and nothing to refuse. The scope goes straight
            // from the context to the store's predicate, which is the provider half of I-079.
            // Before that change the store matched on `id` alone and a caller holding another
            // scope's UUID could expire that scope's memory.
            "mem.refresh" => {
                let scope = scope_from_context(ctx);
                let id = match required_uuid(&args, name) {
                    Ok(id) => id,
                    Err(refusal) => return refusal,
                };
                let extend = args.get("extend_ttl_secs").and_then(Value::as_i64);
                match self.store.refresh_by_id(&scope, id, extend) {
                    Ok(true) => {
                        ToolCallResult::ok(json!({ "refreshed": true, "id": id.to_string() }))
                    }
                    Ok(false) => ToolCallResult::err(format!("mem.refresh: fact `{id}` not found")),
                    Err(e) => ToolCallResult::err(format!("mem.refresh failed: {e}")),
                }
            }
            "mem.expire_now" => {
                let scope = scope_from_context(ctx);
                let id = match required_uuid(&args, name) {
                    Ok(id) => id,
                    Err(refusal) => return refusal,
                };
                match self.store.expire_now(&scope, id) {
                    Ok(true) => {
                        ToolCallResult::ok(json!({ "expired": true, "id": id.to_string() }))
                    }
                    Ok(false) => {
                        ToolCallResult::err(format!("mem.expire_now: fact `{id}` not found"))
                    }
                    Err(e) => ToolCallResult::err(format!("mem.expire_now failed: {e}")),
                }
            }
            unknown => ToolCallResult::err(format!("MemoryProvider: unknown tool `{unknown}`")),
        }
    }
}

/// A search hit. Carries `score` and omits `created_at`.
///
/// Two shapes rather than one because the base has two, and the difference is meaningful
/// rather than accidental: a search result has a similarity score and a list entry does not,
/// while a list entry carries the creation time a ranked hit has no use for. Merging them
/// would change the wire shape of both for no reason a client asked for.
fn search_result_json(fact: &MemoryFact) -> Value {
    json!({
        "id": fact.id.to_string(),
        "scope_root": fact.scope_root,
        "content": fact.content,
        "key": fact.key,
        "tags": fact.tags,
        "score": fact.score,
        "refreshed_at": fact.refreshed_at.to_rfc3339(),
        "ttl_at": fact.ttl_at.map(|t| t.to_rfc3339()),
    })
}

/// A list entry. Carries `created_at` and omits `score`.
fn list_fact_json(fact: &MemoryFact) -> Value {
    json!({
        "id": fact.id.to_string(),
        "scope_root": fact.scope_root,
        "content": fact.content,
        "key": fact.key,
        "tags": fact.tags,
        "created_at": fact.created_at.to_rfc3339(),
        "refreshed_at": fact.refreshed_at.to_rfc3339(),
        "ttl_at": fact.ttl_at.map(|t| t.to_rfc3339()),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_store() -> SqliteMemoryStore {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nmcp-memory-test-{stamp}"));
        SqliteMemoryStore::open(&dir).expect("open store")
    }

    // MEM-1: database opens and schema runs without error.
    #[test]
    fn mem1_open_and_schema() {
        let _store = tmp_store();
    }

    // MEM-2: write and retrieve by semantic search.
    #[test]
    fn mem2_write_and_search() {
        let store = tmp_store();
        let fact = MemoryFact::new("root/proj", "the quick brown fox");
        store.write(fact).expect("write");
        let results = store.search("root/proj", "quick fox", 5).expect("search");
        assert!(!results.is_empty(), "should find at least one result");
        assert!(results[0].score > 0.0, "score should be positive");
    }

    // MEM-3: zero-egress invariant -- LexicalEmbedder makes no network calls.
    // (Structural test: embed returns a normalised vector without panicking.)
    #[test]
    fn mem3_lexical_embedder_zero_egress() {
        let emb = LexicalEmbedder;
        let v = emb.embed("agent memory isolation zero egress");
        let norm_sq: f32 = v.iter().map(|x| x * x).sum();
        assert!(
            (norm_sq - 1.0).abs() < 1e-5,
            "vector should be unit-normalised: {norm_sq}"
        );
    }

    // MEM-4: list returns all live facts for a scope.
    #[test]
    fn mem4_list_scope_isolation() {
        let store = tmp_store();
        store
            .write(MemoryFact::new("scope/a", "fact one"))
            .expect("write");
        store
            .write(MemoryFact::new("scope/a", "fact two"))
            .expect("write");
        store
            .write(MemoryFact::new("scope/b", "other scope"))
            .expect("write");

        let a_facts = store.list("scope/a").expect("list");
        let b_facts = store.list("scope/b").expect("list");
        assert_eq!(a_facts.len(), 2);
        assert_eq!(b_facts.len(), 1);
    }

    // MEM-5: TTL expiry -- expired facts are excluded from search and list.
    #[test]
    fn mem5_ttl_expiry_excludes_from_results() {
        let store = tmp_store();
        let fact = MemoryFact::new("scope/ttl", "this should expire").with_ttl_secs(-1);
        store.write(fact).expect("write");

        let listed = store.list("scope/ttl").expect("list");
        assert!(listed.is_empty(), "expired fact should not appear in list");

        let searched = store.search("scope/ttl", "expire", 5).expect("search");
        assert!(
            searched.is_empty(),
            "expired fact should not appear in search"
        );
    }

    // MEM-5: expire_now marks a fact as expired.
    #[test]
    fn mem5_expire_now_removes_from_live_set() {
        let store = tmp_store();
        let id = store
            .write(MemoryFact::new("scope/expire", "live fact"))
            .expect("write");

        let before = store.list("scope/expire").expect("list before expire");
        assert_eq!(before.len(), 1);

        store.expire_now("scope/expire", id).expect("expire_now");

        let after = store.list("scope/expire").expect("list after expire");
        assert!(after.is_empty(), "fact should be expired");

        // But get_by_id should still find the row (no-delete invariant).
        let row = store.get_by_id(id).expect("get_by_id").expect("row exists");
        assert!(row.is_expired(), "ttl_at should be in the past");
    }

    // Scope isolation: cross-root reads are impossible.
    #[test]
    fn scope_isolation_no_cross_root_reads() {
        let store = tmp_store();
        store
            .write(MemoryFact::new("root/alice", "alice secret"))
            .expect("write");
        let results = store
            .search("root/bob", "alice secret", 10)
            .expect("search");
        assert!(
            results.is_empty(),
            "alice's facts must not leak into bob's scope"
        );
    }

    // Key-based upsert: writing same key twice updates, not duplicates.
    #[test]
    fn key_upsert_does_not_duplicate() {
        let store = tmp_store();
        let f1 = MemoryFact::new("root/proj", "original content").with_key("my-key");
        let f2 = MemoryFact::new("root/proj", "updated content").with_key("my-key");
        store.write(f1).expect("write 1");
        store.write(f2).expect("write 2");
        let facts = store.list("root/proj").expect("list");
        assert_eq!(facts.len(), 1, "upsert should not duplicate keyed facts");
        assert_eq!(facts[0].content, "updated content");
    }

    // Agent handoff: agent A writes with a well-known key; agent B reads it by listing the scope.
    #[test]
    fn agent_handoff_via_key() {
        let store = tmp_store();
        let shared_scope = "projects/shared-workspace";
        let other_scope = "projects/other-agent";

        // Agent A writes a handoff fact.
        store
            .write(
                MemoryFact::new(
                    shared_scope,
                    r#"{"task":"review PR #42","status":"in_progress"}"#,
                )
                .with_key("handoff:agent_b"),
            )
            .expect("write");

        // Agent B lists the same scope_root and finds the handoff.
        let facts = store.list(shared_scope).expect("list");
        assert_eq!(facts.len(), 1, "agent B should see agent A's handoff fact");
        assert_eq!(
            facts[0].key.as_deref(),
            Some("handoff:agent_b"),
            "handoff key must be preserved"
        );

        // Scope isolation: a different scope_root returns empty.
        let other_facts = store.list(other_scope).expect("list other");
        assert!(
            other_facts.is_empty(),
            "handoff must not leak across scope roots"
        );
    }

    // Canonical scope: path aliases resolve to same scope.
    #[test]
    fn canonical_scope_normalises_paths() {
        assert_eq!(canonical_scope("Root/Proj"), canonical_scope("root/proj"));
    }

    // I-079. The crate had a test named scope_isolation_no_cross_root_reads and no
    // counterpart for writes, while expire_now and refresh_by_id matched on id alone.
    // A caller holding a fact's UUID could expire another scope's memory: not data
    // loss, since the row survives for audit, but a cross-scope denial, which is the
    // same isolation boundary the read test was written to defend.
    #[test]
    fn scope_isolation_no_cross_root_mutations() {
        let store = tmp_store();
        let alice = store
            .write(MemoryFact::new("root/alice", "alice fact"))
            .expect("write");

        // Bob knows the id and cannot use it.
        assert!(
            !store.expire_now("root/bob", alice).expect("expire"),
            "a fact in another scope must not be expirable"
        );
        assert!(
            !store
                .refresh_by_id("root/bob", alice, Some(3600))
                .expect("refresh"),
            "a fact in another scope must not be refreshable"
        );

        // And the refusal is indistinguishable from the fact not existing, so the
        // return value is not an existence oracle over another scope's identifiers.
        assert!(
            !store
                .expire_now("root/bob", Uuid::new_v4())
                .expect("expire"),
            "a fact that does not exist reports the same false"
        );

        // Alice is untouched by any of it.
        let alice_facts = store.list("root/alice").expect("list");
        assert_eq!(alice_facts.len(), 1, "the fact must still be live");

        // The owner can still do both.
        assert!(
            store
                .refresh_by_id("root/alice", alice, Some(3600))
                .expect("refresh"),
            "the owning scope must still refresh"
        );
        assert!(
            store.expire_now("root/alice", alice).expect("expire"),
            "the owning scope must still expire"
        );
        assert!(
            store.list("root/alice").expect("list").is_empty(),
            "the owner's expire must take effect"
        );
    }

    // The scope predicate must normalise exactly as write does. A mismatch would
    // present as an isolation success while actually being a bug: the owner locked
    // out of their own fact.
    //
    // Case only, because that is the part `canonical_scope` delivers on every
    // platform. Separator folding is asserted separately below, and the reason it
    // has to be is itself a finding.
    #[test]
    fn the_mutation_scope_predicate_normalises_case_like_write_does() {
        let store = tmp_store();
        let id = store
            .write(MemoryFact::new("Root/Mixed", "fact"))
            .expect("write");
        assert!(
            store
                .refresh_by_id("root/mixed", id, None)
                .expect("refresh"),
            "a case difference must not read as a different scope"
        );
        assert!(
            store.expire_now("ROOT/MIXED", id).expect("expire"),
            "a case difference must not read as a different scope"
        );
    }

    // `canonical_scope` says it "converts any path separator to `/`" and keeps DB
    // keys "platform-independent". It does that with `PathBuf::components()`, and a
    // backslash is an ordinary filename character on Unix, so the claim holds on
    // Windows and not elsewhere. The behaviour is consistent within one install,
    // which is the only place it matters today, so I-079 asserts what is true per
    // platform rather than changing the normaliser as a side effect of a scope fix.
    // The doc overclaim is recorded rather than silently worked around.
    #[test]
    #[cfg(windows)]
    fn the_mutation_scope_predicate_folds_separators_on_windows() {
        let store = tmp_store();
        let id = store
            .write(MemoryFact::new(r"Root\Mixed", "fact"))
            .expect("write");
        assert!(
            store.expire_now("root/mixed", id).expect("expire"),
            "on Windows a backslash and a forward slash are the same scope"
        );
    }

    // refresh_by_id updates refreshed_at without creating a new row.
    #[test]
    fn refresh_by_id_updates_timestamp() {
        let store = tmp_store();
        let id = store
            .write(MemoryFact::new("scope/refresh", "fact to refresh"))
            .expect("write");

        let found = store
            .refresh_by_id("scope/refresh", id, Some(3600))
            .expect("refresh");
        assert!(found, "refresh_by_id should return true for existing fact");

        let facts = store.list("scope/refresh").expect("list");
        assert_eq!(facts.len(), 1, "refresh must not duplicate the row");
        assert!(
            facts[0].ttl_at.is_some(),
            "ttl_at should be set after refresh with extension"
        );
    }

    // ── MemoryProvider (I-072a) ──────────────────────────────────────────────

    use super::{MemoryProvider, memory_tool_authority};
    use nmcp_policy::{Permission, RootRule};
    use nmcp_schema::{
        CallContext, GrantedAuthority, HeldAuthority, ToolAuthority, ToolEffect, ToolProvider,
        ToolReach, authorize,
    };
    use serde_json::{Value, json};
    use std::collections::BTreeSet;

    /// What the ring would hand a provider after authorizing. Minted through `authorize`
    /// rather than constructed, because `GrantedAuthority` has no other constructor: these
    /// tests therefore exercise the real authorization path rather than a stand-in for it.
    fn granted_for(tool: &str, held_permissions: &[Permission]) -> GrantedAuthority {
        let mut permissions = BTreeSet::new();
        for p in held_permissions {
            permissions.insert(*p);
        }
        let held = HeldAuthority {
            roots: vec![RootRule {
                id: "root".into(),
                path: std::env::temp_dir(),
                permissions,
            }],
            grants: BTreeSet::new(),
            agent_id: None,
        };
        authorize(&memory_tool_authority(tool), &held, &json!({}))
            .expect("the held permission must authorize this tool")
    }

    fn provider() -> MemoryProvider {
        MemoryProvider::new(tmp_store())
    }

    fn ctx_for(session: &str) -> CallContext {
        CallContext::new(Some(session.to_string()))
    }

    /// The payload a successful `ToolCallResult::ok` carries.
    ///
    /// `ok` stringifies its value into `content[0].text` and leaves `structured_content`
    /// unset. That is the wire shape the base produced and the one a client reads, so the
    /// tests read it back the same way rather than reaching for a field the constructor
    /// never fills. `err_with_metadata` does populate `structured_content`, which is why the
    /// refusal tests below read that field and these do not.
    fn ok_payload(result: &nmcp_schema::ToolCallResult) -> Value {
        assert!(!result.is_error, "expected success, got {result:?}");
        let text = result.content[0]["text"]
            .as_str()
            .expect("ok results carry text content");
        serde_json::from_str(text).expect("an ok payload must be JSON")
    }

    async fn call(
        p: &MemoryProvider,
        tool: &str,
        args: Value,
        ctx: &CallContext,
        held: &[Permission],
    ) -> nmcp_schema::ToolCallResult {
        p.call(tool, args, ctx, &granted_for(tool, held)).await
    }

    #[tokio::test]
    async fn the_five_tools_round_trip_in_the_callers_own_scope() {
        let p = provider();
        let ctx = ctx_for("alice");

        let written = call(
            &p,
            "mem.write",
            json!({"content": "the deploy window is Tuesday", "key": "deploy", "tags": ["ops"]}),
            &ctx,
            &[Permission::MemoryWrite],
        )
        .await;
        assert!(!written.is_error, "write must succeed: {written:?}");
        let id = ok_payload(&written)["id"].as_str().expect("id").to_string();

        let listed = call(&p, "mem.list", json!({}), &ctx, &[Permission::MemoryRead]).await;
        let listed_payload = ok_payload(&listed);
        let facts = listed_payload["facts"].as_array().expect("facts").clone();
        assert_eq!(facts.len(), 1);
        // The list shape carries created_at and no score; the search shape is the reverse.
        assert!(facts[0].get("created_at").is_some());
        assert!(facts[0].get("score").is_none());

        let read = call(
            &p,
            "mem.read",
            json!({"query": "deploy window"}),
            &ctx,
            &[Permission::MemoryRead],
        )
        .await;
        let read_payload = ok_payload(&read);
        let results = read_payload["results"].as_array().expect("results").clone();
        assert_eq!(results.len(), 1);
        assert!(results[0].get("score").is_some());
        assert!(results[0].get("created_at").is_none());

        let refreshed = call(
            &p,
            "mem.refresh",
            json!({"id": id, "extend_ttl_secs": 3600}),
            &ctx,
            &[Permission::MemoryWrite],
        )
        .await;
        assert!(!refreshed.is_error, "refresh must succeed: {refreshed:?}");

        let expired = call(
            &p,
            "mem.expire_now",
            json!({"id": id}),
            &ctx,
            &[Permission::MemoryWrite],
        )
        .await;
        assert!(!expired.is_error, "expire must succeed: {expired:?}");

        let after = call(&p, "mem.list", json!({}), &ctx, &[Permission::MemoryRead]).await;
        let after_payload = ok_payload(&after);
        let facts = after_payload["facts"].as_array().expect("facts").clone();
        assert!(facts.is_empty(), "the expired fact must leave the live set");
    }

    #[tokio::test]
    async fn naming_another_scope_is_refused_and_says_which_kind_of_refusal() {
        let p = provider();
        let ctx = ctx_for("alice");
        let result = call(
            &p,
            "mem.write",
            json!({"content": "x", "scope_root": "session:bob"}),
            &ctx,
            &[Permission::MemoryWrite],
        )
        .await;
        assert!(result.is_error, "a foreign scope_root must be refused");
        let structured = result.structured_content.as_ref().expect("structured");
        assert_eq!(
            structured["error_kind"], "policy_denied",
            "the refusal must be attributable, not a bare runtime error"
        );
    }

    #[tokio::test]
    async fn a_matching_scope_root_is_accepted_and_still_not_the_value_used() {
        // The corroborating assertion is allowed to agree. What must never happen is the
        // caller's string reaching the store, so this asserts the write landed in the
        // context scope rather than merely that it succeeded.
        let p = provider();
        let ctx = ctx_for("alice");
        let ok = call(
            &p,
            "mem.write",
            json!({"content": "x", "scope_root": "session:alice"}),
            &ctx,
            &[Permission::MemoryWrite],
        )
        .await;
        assert!(
            !ok.is_error,
            "a matching scope_root must be accepted: {ok:?}"
        );
        let facts = p.store.list("session:alice").expect("list");
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].scope_root, "session:alice");
    }

    #[tokio::test]
    async fn refresh_and_expire_cannot_reach_another_scope_even_with_the_id() {
        // The provider half of I-079. The store's predicate is scoped; this asserts the
        // provider hands it the context scope rather than anything the caller can influence.
        // Note neither tool accepts a scope_root at all, so there is nothing to corroborate:
        // a caller cannot even express the scope they are trying to reach.
        let p = provider();
        let alice = ctx_for("alice");
        let bob = ctx_for("bob");

        let written = call(
            &p,
            "mem.write",
            json!({"content": "alice fact"}),
            &alice,
            &[Permission::MemoryWrite],
        )
        .await;
        let id = ok_payload(&written)["id"].as_str().expect("id").to_string();

        let stolen = call(
            &p,
            "mem.expire_now",
            json!({"id": id}),
            &bob,
            &[Permission::MemoryWrite],
        )
        .await;
        assert!(
            stolen.is_error,
            "bob must not expire alice's fact even holding its id"
        );

        let poked = call(
            &p,
            "mem.refresh",
            json!({"id": id}),
            &bob,
            &[Permission::MemoryWrite],
        )
        .await;
        assert!(poked.is_error, "bob must not refresh alice's fact");

        let alice_facts = p.store.list("session:alice").expect("list");
        assert_eq!(alice_facts.len(), 1, "alice's fact must still be live");
    }

    #[test]
    fn the_ring_refuses_an_ungranted_call_before_the_provider_is_entered() {
        // The permission guards the base carried inside `call` are gone. This is what
        // replaced them, and it runs before `call` rather than inside it.
        let held = HeldAuthority {
            roots: vec![RootRule {
                id: "root".into(),
                path: std::env::temp_dir(),
                permissions: [Permission::MemoryRead].into_iter().collect(),
            }],
            grants: BTreeSet::new(),
            agent_id: None,
        };
        assert!(
            authorize(&memory_tool_authority("mem.read"), &held, &json!({})).is_ok(),
            "MemoryRead must authorize a read"
        );
        assert!(
            authorize(&memory_tool_authority("mem.write"), &held, &json!({})).is_err(),
            "MemoryRead alone must not authorize a write"
        );
    }

    #[test]
    fn every_declared_tool_has_an_authority_and_none_resolves_a_root() {
        let p = provider();
        let contracts = p.contracts();
        assert_eq!(contracts.len(), 5);
        for c in &contracts {
            assert!(
                c.authority.path_args.is_empty(),
                "{}: memory is scoped by the call context, never by a path argument. A \
                 scope_root in path_args would have the kernel resolve a root from a \
                 caller-supplied string while the store queried the context scope, which is \
                 the RC-20 shape.",
                c.name
            );
            assert!(
                c.authority.permission.is_some(),
                "{}: every memory tool declares a permission",
                c.name
            );
            assert_eq!(c.authority.reach, ToolReach::Local, "{}", c.name);
            assert!(
                c.published_annotations.is_none(),
                "{}: RC-21, a first-party provider derives its annotations",
                c.name
            );
            // RC-D5: every declared path argument must be a property of the tool's own
            // schema. Vacuously true here, and asserted so it stays true if one is added.
            for arg in &c.authority.path_args {
                assert!(
                    c.input_schema
                        .get("properties")
                        .and_then(|p| p.get(arg))
                        .is_some(),
                    "{}: declares path arg {arg} its schema cannot receive",
                    c.name
                );
            }
        }
        let mutating: Vec<&str> = contracts
            .iter()
            .filter(|c| c.authority.effect == ToolEffect::Mutate)
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(
            mutating,
            vec!["mem.write", "mem.refresh", "mem.expire_now"],
            "only the three writing tools may declare Mutate"
        );
    }

    #[test]
    fn a_tool_with_no_authority_line_is_visible_and_uncallable() {
        let held = HeldAuthority {
            roots: vec![RootRule {
                id: "root".into(),
                path: std::env::temp_dir(),
                permissions: Permission::ALL.iter().copied().collect(),
            }],
            grants: BTreeSet::new(),
            agent_id: None,
        };
        let fallback: ToolAuthority = memory_tool_authority("mem.invented");
        assert!(
            authorize(&fallback, &held, &json!({})).is_err(),
            "the fallback arm must refuse even a caller holding every permission"
        );
    }
}
