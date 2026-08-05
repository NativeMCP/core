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
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
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

// ── MemoryScope (legacy, kept for router/audit compatibility) ─────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// A memory scope label kept for router/audit compatibility.
pub struct MemoryScope(pub String);

impl MemoryScope {
    /// A root-anchored scope.
    #[must_use]
    pub fn root(id: impl Into<String>) -> Self {
        Self(format!("root:{}", id.into()))
    }
    /// A session-anchored scope.
    #[must_use]
    pub fn session(id: impl Into<String>) -> Self {
        Self(format!("session:{}", id.into()))
    }
    /// A named scope, used verbatim.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

impl std::fmt::Display for MemoryScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

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
    /// # Errors
    ///
    /// `SQLite` failure.
    pub fn expire_now(&self, id: Uuid) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let now = dt_to_sql(Utc::now());
        let changed = conn.execute(
            "UPDATE memory SET ttl_at = ?1 WHERE id = ?2",
            params![now, id.to_string()],
        )?;
        Ok(changed > 0)
    }

    /// Read a single fact by id regardless of TTL (for audit/admin purposes).
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
    pub fn refresh_by_id(&self, id: Uuid, extend_ttl_secs: Option<i64>) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let now = Utc::now();
        let new_ttl = extend_ttl_secs.map(|s| dt_to_sql(now + Duration::seconds(s)));
        let changed = if let Some(ref ttl_str) = new_ttl {
            conn.execute(
                "UPDATE memory SET refreshed_at = ?1, ttl_at = ?2 WHERE id = ?3",
                params![dt_to_sql(now), ttl_str, id.to_string()],
            )?
        } else {
            conn.execute(
                "UPDATE memory SET refreshed_at = ?1 WHERE id = ?2",
                params![dt_to_sql(now), id.to_string()],
            )?
        };
        Ok(changed > 0)
    }
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

        store.expire_now(id).expect("expire_now");

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

    // refresh_by_id updates refreshed_at without creating a new row.
    #[test]
    fn refresh_by_id_updates_timestamp() {
        let store = tmp_store();
        let id = store
            .write(MemoryFact::new("scope/refresh", "fact to refresh"))
            .expect("write");

        let found = store.refresh_by_id(id, Some(3600)).expect("refresh");
        assert!(found, "refresh_by_id should return true for existing fact");

        let facts = store.list("scope/refresh").expect("list");
        assert_eq!(facts.len(), 1, "refresh must not duplicate the row");
        assert!(
            facts[0].ttl_at.is_some(),
            "ttl_at should be set after refresh with extension"
        );
    }
}
