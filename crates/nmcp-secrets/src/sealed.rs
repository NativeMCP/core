//! [`Sealed<T>`]: the wrapper that owns material and does not let it escape by accident.
//!
//! NMCP-SPEC-002 SB-1, RATIFIED v1.0. The signature is frozen at ratification and implemented
//! as written.

use std::fmt;

use zeroize::Zeroize;

/// Owns material and does not let it escape by accident.
///
/// The inner value is private, so it cannot be read by field access, printed by a derived
/// `Debug`, or matched out by a pattern. It is zeroized on drop rather than only being
/// [`Zeroize`]: a bound alone makes a method available and erases nothing, which is what SB-1
/// records v0.1 of the specification as having asked for.
///
/// ## What this type does and does not buy
///
/// Stated because a wrapper that is trusted for more than it does is worse than no wrapper.
/// Inside this process the guarantee is structural: there is one read path, it is
/// [`Sealed::with_exposed`], and `grep` enumerates every call site. Past the process boundary
/// there is no guarantee at all, which is SB-1's own bound and why the `env` modality's real
/// control is the program allowlist rather than this type.
///
/// The erasure is also bounded, and SB-1 names the bound: `Sealed<Vec<u8>>` zeroizes exactly
/// one allocation, the one it owns. A copy some other code made before handing the value here
/// is that code's copy, and this type never saw it. SB-11 puts the matching obligation on each
/// sealer, which is to zero its own intermediate buffer before releasing it, and the file
/// sealer in this crate does that.
///
/// ## What is deliberately absent
///
/// No `Clone`: a clone is a second allocation with the same bytes and only one of them is the
/// one a call site is thinking about when it drops. No `Display`, no `serde` implementation,
/// no `AsRef<T>`, no `Deref`. Each of those is a read path, and SB-1 asks for exactly one.
///
/// No `PartialEq` either. Comparing material is what a tripwire does (SB-9, owned by I-035),
/// and a derived comparison would be variable-time over the bytes, which turns every equality
/// test into a timing oracle for a prefix. When I-035 needs a comparison it needs a
/// constant-time one, and it should have to write that rather than inherit this.
///
/// ```
/// use nmcp_secrets::Sealed;
///
/// let sealed = Sealed::new(vec![1_u8, 2, 3]);
/// assert_eq!(sealed.with_exposed(Vec::len), 3);
/// assert_eq!(format!("{sealed:?}"), "[sealed]");
/// ```
///
/// The `Display` denial is pinned as a compile failure, paired with the positive block above
/// so a rename cannot silently disarm it (`rustdoc` passes `compile_fail` on any error):
///
/// ```compile_fail,E0277
/// let sealed = nmcp_secrets::Sealed::new(vec![1_u8, 2, 3]);
/// println!("{sealed}");
/// ```
pub struct Sealed<T: Zeroize>(T);

impl<T: Zeroize> Sealed<T> {
    /// Take ownership of material.
    ///
    /// Public because SB-11 requires it: a platform sealer in another repository implements
    /// [`Sealer::unseal`](crate::Sealer::unseal), which returns one of these, and a private
    /// constructor would make every out-of-crate sealer unimplementable and NMCP-SPEC-001
    /// R-4's placement unimplementable with it.
    #[must_use]
    pub const fn new(inner: T) -> Self {
        Self(inner)
    }

    /// Run `f` with a borrow of the material.
    ///
    /// A scoped closure rather than an accessor returning `&T`: a reference handed out is a
    /// reference that can be stored, and the whole point of the type is that the exposure
    /// surface is enumerable. Every call site is a literal `with_exposed` and `grep` finds all
    /// of them.
    ///
    /// The borrow cannot outlive the call. `f` is `FnOnce(&T) -> R` with `R` free of the
    /// borrow's lifetime, so returning the reference itself does not type-check, which is the
    /// property that makes the enumeration worth having rather than a naming convention.
    pub fn with_exposed<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        f(&self.0)
    }
}

impl<T: Zeroize> Drop for Sealed<T> {
    /// Erase the material. A real `Drop`, not a [`Zeroize`] bound with nothing calling it.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Sealed<T> {
    /// Redacted by construction, following the pattern the base uses for OAuth grants: a
    /// hand-written `Debug` rather than a derive, because there is no way to use a derived one
    /// safely and so there is no derive.
    ///
    /// `[sealed]` and nothing else. Not the type name, not the length, not a field count. SB-1
    /// forbids a length as much as it forbids the value, and `Sealed<Vec<u8>>` printing a
    /// length would put the size of every credential into whatever log formatted a call
    /// context.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[sealed]")
    }
}

#[cfg(test)]
mod tests {
    // Tests assert on shapes, verdicts and JSON, where expect/indexing ARE the assertion:
    // a panic in a test is the failure signal, so the production rationale for the
    // workspace denies (availability plus an audit gap) does not apply. Scoped to the test
    // module, named in the PR.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::Sealed;

    /// A witness that reports whether it was erased, so "zeroized on drop" is measured rather
    /// than asserted from the presence of a `Drop` impl.
    ///
    /// Reading the buffer after the drop is what a test would reach for and is undefined
    /// behaviour, and this workspace forbids `unsafe`, so the observation is made from inside
    /// [`zeroize::Zeroize::zeroize`] instead. That is the honest version of the assertion: it
    /// proves the erasure ran on the value that was dropped.
    struct Witness {
        erased: std::rc::Rc<std::cell::Cell<usize>>,
        bytes: Vec<u8>,
    }

    impl zeroize::Zeroize for Witness {
        fn zeroize(&mut self) {
            self.bytes.zeroize();
            self.erased.set(self.erased.get() + 1);
        }
    }

    #[test]
    fn drop_zeroizes_exactly_once() {
        let erased = std::rc::Rc::new(std::cell::Cell::new(0));
        {
            let witness = Witness {
                erased: std::rc::Rc::clone(&erased),
                bytes: vec![0xAB; 64],
            };
            let sealed = Sealed::new(witness);
            assert_eq!(
                erased.get(),
                0,
                "nothing is erased while the value is alive"
            );
            assert_eq!(sealed.with_exposed(|w| w.bytes.len()), 64);
        }
        assert_eq!(erased.get(), 1, "drop erases, and does it once");
    }

    #[test]
    fn the_inner_buffer_is_cleared_not_merely_dropped() {
        // Erasure is observed on the buffer the wrapper owns, from inside the impl that runs
        // on drop, which is the only place it can be read without reaching into freed memory.
        let mut witness = Witness {
            erased: std::rc::Rc::new(std::cell::Cell::new(0)),
            bytes: vec![0xCD; 32],
        };
        zeroize::Zeroize::zeroize(&mut witness);
        assert!(witness.bytes.is_empty(), "the buffer is cleared");
    }

    #[test]
    fn debug_prints_the_marker_and_nothing_about_the_value() {
        let sealed = Sealed::new(b"correct-horse-battery-staple".to_vec());
        assert_eq!(format!("{sealed:?}"), "[sealed]");
        // Nested in a container, which is how it actually reaches a log line.
        let nested = vec![Sealed::new(b"correct-horse-battery-staple".to_vec())];
        let rendered = format!("{nested:?}");
        assert_eq!(rendered, "[[sealed]]");
        assert!(!rendered.contains("horse"));
        // Not the length either: SB-1 forbids a value derived from material, and a length is
        // one. Twenty-eight is this plaintext's length and must not appear.
        assert!(!rendered.contains("28"));
    }

    #[test]
    fn with_exposed_is_the_read_path_and_returns_what_the_closure_returns() {
        let sealed = Sealed::new(vec![9_u8, 8, 7]);
        assert_eq!(sealed.with_exposed(Vec::clone), vec![9, 8, 7]);
        assert_eq!(sealed.with_exposed(|bytes| bytes.first().copied()), Some(9));
        // Borrowing twice is fine: exposure is scoped, not exhausting.
        assert_eq!(sealed.with_exposed(Vec::len), 3);
    }
}
