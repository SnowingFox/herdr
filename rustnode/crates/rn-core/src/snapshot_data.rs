//! State a snapshot must carry across the blob, and the load that puts it back.
//!
//! # Why this is needed at all
//!
//! `CreateBlob` runs `SerializedHandleChecker::CheckGlobalAndEternalHandles` and
//! aborts on every `v8::Global` that is neither reachable from a serialised
//! context nor from a serialised embedder object. A binding keeps
//! `v8::Global` handles to objects its namespace published — the fs
//! `kUsePromises` sentinel, the diagnostics-channel subscriber array, the icu
//! converter template, the `linkNativeChannel` callback — and none of those are
//! reachable from the context, so the build aborts.
//!
//! [`crate::snapshot_drain`] drops handles that are pure caches of something the
//! blob already contains. That is wrong for these: the object *is* the binding's
//! identity. Dropping the fs sentinel would produce a blob where every
//! `openFileHandle(path, flags, mode, kUsePromises)` silently takes the callback
//! path, because `is_use_promises` would no longer recognise the property it is
//! handed. A build must never report success while that changes.
//!
//! # What Node does
//!
//! Node does not re-mint these. `SnapshotCreator::AddData` attaches each
//! per-isolate primitive to the blob and `GetDataFromSnapshotOnce` reads it back
//! by index on load, which is what `PER_ISOLATE_SYMBOL_PROPERTIES` in
//! `src/env_properties.h` is for: `IsolateData::Deserialize` iterates the same
//! list and repopulates every field from the blob. The identity is *carried*, not
//! rebuilt, and it is the same object on both sides of the load.
//!
//! This module is that mechanism. A crate registers a provider, the build attaches
//! what the provider hands it, and the load gives it back.
//!
//! # Why indices are reproducible
//!
//! `add_context_data` returns the index the data is stored at, and
//! `get_context_data_from_snapshot_once` needs that index to read it back. Nothing
//! ties the two indices together across processes, so the providers are kept in a
//! `BTreeMap` keyed by name and both walks visit them in that order. Two processes
//! running the same binary therefore agree on the numbering without either side
//! recording it — and a provider that is registered on only one side would shift
//! every later index, which is why both lists are walked in the same order rather
//! than one being recorded by the other: a provider that is registered on only one
//! side shifts every later index, and a restore that cannot find its data reports
//! that rather than silently leaving a binding empty.

use std::cell::RefCell;
use std::collections::BTreeMap;

use rn_v8_sys::v8;

/// One crate's contribution to the blob.
pub struct Provider {
    /// Builds the value to store.
    ///
    /// `v8::undefined` means this realm produced nothing for this provider, which
    /// is not an error — a namespace that was never installed has nothing to
    /// carry. It must still return *something*, because [`attach_all`] gives every
    /// provider an index whether or not it has data: a provider that skipped its
    /// index would renumber every later one, and the load side has no way to know
    /// that happened.
    pub attach: for<'s, 'i> fn(
        &mut v8::PinScope<'s, 'i>,
        v8::Local<'s, v8::Context>,
    ) -> v8::Local<'s, v8::Data>,
    /// Puts a value the load retrieved back where the crate reads it from.
    pub restore:
        for<'s, 'i> fn(&mut v8::PinScope<'s, 'i>, v8::Local<'s, v8::Data>) -> Result<(), String>,
}

thread_local! {
    /// Providers keyed by name, so both walks agree on the order and therefore on
    /// the indices.
    static PROVIDERS: RefCell<BTreeMap<&'static str, Provider>> = const { RefCell::new(BTreeMap::new()) };
}

/// Registers `crate_name`'s contribution to the blob.
///
/// Called from the CLI's one-time setup, like [`crate::snapshot_drain::register`]:
/// the provider has to exist whether or not the namespace installed, because a
/// provider that only appears on the build side would renumber every later entry.
pub fn register(
    crate_name: &'static str,
    attach: for<'s, 'i> fn(
        &mut v8::PinScope<'s, 'i>,
        v8::Local<'s, v8::Context>,
    ) -> v8::Local<'s, v8::Data>,
    restore: for<'s, 'i> fn(
        &mut v8::PinScope<'s, 'i>,
        v8::Local<'s, v8::Data>,
    ) -> Result<(), String>,
) {
    PROVIDERS.with(|providers| {
        providers
            .borrow_mut()
            .insert(crate_name, Provider { attach, restore });
    });
}

/// Attaches every registered provider's value to the snapshot being built.
///
/// Takes the creator isolate rather than a scope because `add_context_data` is an
/// `Isolate` method and needs `&mut Isolate`; the value each provider hands back
/// is created inside `scope`, which is borrowed from that same isolate.
///
/// Returns how many values were attached, for the build to report.
pub fn attach_all<'s, 'i>(
    scope: &mut v8::PinScope<'s, 'i>,
    context: v8::Local<'s, v8::Context>,
) -> usize {
    let providers: Vec<(&'static str, Provider)> = PROVIDERS.with(|providers| {
        providers
            .borrow()
            .iter()
            .map(|(name, provider)| {
                (
                    *name,
                    Provider {
                        attach: provider.attach,
                        restore: provider.restore,
                    },
                )
            })
            .collect()
    });
    let mut attached = 0;
    for (name, provider) in providers {
        let data = (provider.attach)(scope, context);
        // Reached through `AsMut<Isolate>` on the scope: the scope was taken from
        // this isolate, so the two cannot disagree, and the borrow ends before the
        // next provider creates another value.
        let isolate: &mut v8::Isolate = (*scope).as_mut();
        let index = isolate.add_context_data(context, data);
        tracing::debug!(provider = name, index, "attached snapshot data");
        attached += 1;
    }
    attached
}

/// Puts back everything the blob carried.
///
/// The caller must have entered the context the indices are relative to — the one
/// `Context::from_snapshot` instantiated — because
/// `get_context_data_from_snapshot_once` reads the current context from the scope.
///
/// # Why this has no caller in this tree yet
///
/// `--snapshot-blob` is parsed (`args::Options::snapshot_blob`) but no run ever
/// reads it: this build has no blob *load* path, so a process cannot be started
/// from one. This function is the load half that path needs, and it is written now
/// because a build that attaches data without a documented way to read it back
/// would be inventing a format nobody can consume. It is exercised by
/// `rn-v8-sys`'s `attached_data_is_serialisable_while_a_global_still_roots_it`,
/// which builds a blob and reads a value back by index across two isolates.
///
/// Restoring is deliberately *not* wrapped in a fallback: a provider that cannot
/// accept what the blob carried means the two sides disagree, and continuing would
/// leave a binding with nothing in it — the silent-degradation case a snapshot must
/// never produce.
pub fn restore_all(scope: &mut v8::PinScope<'_, '_>) -> Result<usize, String> {
    let providers: Vec<(&'static str, Provider)> = PROVIDERS.with(|providers| {
        providers
            .borrow()
            .iter()
            .map(|(name, provider)| {
                (
                    *name,
                    Provider {
                        attach: provider.attach,
                        restore: provider.restore,
                    },
                )
            })
            .collect()
    });
    let mut restored = 0;
    for (name, provider) in providers {
        let Ok(data) = scope.get_context_data_from_snapshot_once::<v8::Data>(restored) else {
            return Err(format!(
                "the blob carries no data at index {restored}, so {name} cannot be restored — \
                 the build and load providers disagree about their order"
            ));
        };
        (provider.restore)(scope, data)
            .map_err(|reason| format!("cannot restore {name} from the blob: {reason}"))?;
        restored += 1;
    }
    Ok(restored)
}

/// How many providers are registered. Tests read it; a build reports it.
pub fn provider_count() -> usize {
    PROVIDERS.with(|providers| providers.borrow().len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attach_nothing<'s, 'i>(
        scope: &mut v8::PinScope<'s, 'i>,
        _context: v8::Local<'s, v8::Context>,
    ) -> v8::Local<'s, v8::Data> {
        v8::undefined(scope).into()
    }

    fn restore_nothing<'s, 'i>(
        _scope: &mut v8::PinScope<'s, 'i>,
        _data: v8::Local<'s, v8::Data>,
    ) -> Result<(), String> {
        Ok(())
    }

    /// The registry keeps one entry per name, so running the install path twice
    /// per process cannot renumber the blob.
    #[test]
    fn registering_twice_replaces_one_entry() {
        register("probe-a", attach_nothing, restore_nothing);
        let before = provider_count();
        register("probe-a", attach_nothing, restore_nothing);
        assert_eq!(provider_count(), before, "a repeated name replaces");
        register("probe-b", attach_nothing, restore_nothing);
        assert_eq!(provider_count(), before + 1, "a new name adds one");
    }
}
