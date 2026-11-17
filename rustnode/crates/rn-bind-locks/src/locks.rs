//! The Web Locks algorithm from `src/node_locks.cc`, with no V8 in it.
//!
//! `lib/internal/locks.js` is Node's own file and already implements the Web
//! Locks *interface*: option conversion, the abort-signal path, the diagnostics
//! channels, `Lock` objects. What it delegates to the binding is the *algorithm*
//! from <https://w3c.github.io/web-locks/#algorithms> over a queue of requests
//! shared by every environment in the process.
//!
//! That split is why this module knows nothing about promises. A request and a
//! granted lock are identified by a numeric id, and everything the binding layer
//! has to do with a promise is expressed as a [`Plan`] it executes on the thread
//! that owns the environment. Two rules follow from that:
//!
//! * **A promise may only be settled on its own environment's thread.** Node can
//!   reject a stolen lock's `released` promise from the thief's thread because
//!   every environment there lives in one isolate. Here each environment has its
//!   own isolate, so a theft records the owed rejection under the *owner's* id in
//!   [`Manager::owed`] and wakes that environment; the owner performs it on its
//!   next pass.
//! * **Nothing here may re-enter JavaScript.** No method calls back out, so the
//!   caller can hold the process-wide mutex for the whole decision and then run
//!   the V8 half with the mutex released. That is what keeps a user callback that
//!   itself calls `navigator.locks.request` from deadlocking on its own manager.
//!
//! # Faithful to Node, including the parts that look like bugs
//!
//! `src/node_locks.cc` leaves a lock held when the user callback throws
//! synchronously — `ProcessQueue` stores the lock and then returns from the
//! `TryCatchScope` without unwinding it — and the published oracle does the same.
//! Measured, not inferred:
//!
//! ```text
//! $ node -e 'await navigator.locks.request("x", () => { throw new Error() })'
//! held after sync throw: [{"name":"x","mode":"exclusive","clientId":"node-…"}]
//! ```
//!
//! So [`Manager::grant`] inserts the lock before the caller runs the callback, and
//! a throw leaves it there. Matching an observable behaviour beats matching an
//! intention.

use std::collections::{HashMap, HashSet};

/// Identifies one environment: a thread that hosts a realm.
///
/// Node's equivalent is the `Environment*` pointer. A number is used here so the
/// manager stays testable without an isolate; the mapping from it to a real wake
/// token belongs to the binding layer.
pub type EnvId = u64;

/// A lock resource name as a DOMString, kept as UTF-16 code units.
///
/// Node stores `std::u16string` for the same reason: a `String` is not valid
/// UTF-16, so comparing names through a UTF-8 round trip would make two different
/// names compare equal.
pub type Name = Vec<u16>;

/// `Lock::Mode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Shared,
    Exclusive,
}

/// One queued request: `LockRequest` in `src/node_locks.h`.
#[derive(Clone, Debug)]
pub struct Request {
    /// What the binding layer holds the request's promise and callback under.
    ///
    /// A granted lock keeps the same id, so a lock is always found under the id
    /// its request was queued with.
    pub id: u64,
    pub env: EnvId,
    pub name: Name,
    pub mode: Mode,
    pub client_id: String,
    pub steal: bool,
    pub if_available: bool,
}

/// One granted lock: `Lock` in `src/node_locks.h`.
#[derive(Clone, Debug)]
pub struct Lock {
    pub id: u64,
    pub env: EnvId,
    pub name: Name,
    pub mode: Mode,
    pub client_id: String,
    /// Set when another request stole this lock.
    ///
    /// Its `released` promise was already rejected, so settling the user's
    /// callback must not settle it a second time.
    pub stolen: bool,
}

/// What one pass over the queue decided.
#[derive(Debug)]
pub enum Step {
    /// An `ifAvailable` request whose resource is busy: the callback runs with
    /// `null` and no lock is taken.
    Miss(Request),
    /// A request that can run now.
    ///
    /// The lock is already in the held set, because Node stores it before
    /// invoking the callback and so a synchronous throw leaves it held.
    Grant(Box<Granted>),
}

/// The granted half of [`Step::Grant`].
#[derive(Debug)]
pub struct Granted {
    pub request: Request,
    pub lock: Lock,
}

/// The work one [`Manager::process`] pass hands back to the binding layer.
#[derive(Debug, Default)]
pub struct Plan {
    pub step: Option<Step>,
    /// Ids of this environment's locks that were stolen: their `released` promise
    /// must be rejected. Each is reported exactly once.
    ///
    /// Ids rather than locks because the victim's entry may already have left the
    /// held set — any other environment's pass drops a stolen lock it does not own
    /// — while the promise that has to be rejected still belongs to the victim's
    /// slot table.
    pub reject: Vec<u64>,
    /// Other environments to wake, each at most once.
    ///
    /// Only an environment with a request that can make progress is woken. That
    /// restriction is the anti-livelock rule from `ProcessQueue`: waking every
    /// blocked environment would let two of them wake each other forever.
    pub wake: Vec<EnvId>,
}

/// The process-wide lock state.
#[derive(Default)]
pub struct Manager {
    /// Granted locks per resource name, oldest first.
    held: HashMap<Name, Vec<Lock>>,
    /// Pending requests, front first. A `steal` request is pushed to the front so
    /// it is considered before everything already queued.
    queue: Vec<Request>,
    /// Stolen locks whose owner has not been told yet.
    owed: HashMap<EnvId, Vec<u64>>,
    /// Every currently-stolen lock id.
    ///
    /// It has to outlive the held entry: the user callback that settles later
    /// still asks whether its lock was stolen, and `ReleaseLock` may already have
    /// dropped the entry.
    stolen: HashSet<u64>,
}

impl Manager {
    /// Queues `request`, at the front when it steals.
    ///
    /// `LockManager::Request` does the same: `emplace_front` for a steal request
    /// and `push_back` otherwise.
    pub fn enqueue(&mut self, request: Request) {
        if request.steal {
            self.queue.insert(0, request);
        } else {
            self.queue.push(request);
        }
    }

    /// Runs one pass of `ProcessQueue` for `env`.
    ///
    /// Performs at most one grant or miss, like one iteration of Node's
    /// `while (true)`: after a grant the caller runs the user callback, and that
    /// callback may settle synchronously, which is why the loop lives in the
    /// binding layer.
    pub fn process(&mut self, env: EnvId) -> Plan {
        // `ProcessQueue` starts every iteration with `CleanupStolenLocks(env)`,
        // so a lock stolen from somebody else is dropped by whoever looks next.
        self.cleanup_stolen_locks(env);

        let mut plan = Plan {
            reject: self.take_owed(env),
            ..Plan::default()
        };

        // The earliest pending request per resource, as an index in `queue`.
        let mut first_seen: HashMap<Name, usize> = HashMap::new();

        let mut index = 0;
        while index < self.queue.len() {
            let (name, mode, owner, steal, if_available) = {
                let request = &self.queue[index];
                (
                    request.name.clone(),
                    request.mode,
                    request.env,
                    request.steal,
                    request.if_available,
                )
            };

            let first = *first_seen.entry(name.clone()).or_insert(index);
            // An exclusive request is incompatible with everything, so a later
            // request waits behind it; two shared requests are compatible.
            let waits = first != index
                && (mode == Mode::Exclusive || self.queue[first].mode == Mode::Exclusive);
            let grantable = !waits && self.is_grantable(&name, mode, steal);

            if owner != env {
                // Another environment's request. Wake it only when it could make
                // progress right now; a blocked environment woken for no reason
                // would wake this one in turn and the two would spin.
                if grantable || if_available {
                    push_unique(&mut plan.wake, owner);
                }
                index += 1;
                continue;
            }

            if !grantable {
                if if_available {
                    plan.step = Some(Step::Miss(self.queue.remove(index)));
                    return plan;
                }
                index += 1;
                continue;
            }

            let request = self.queue.remove(index);
            let lock = self.grant(&request, &mut plan);
            plan.step = Some(Step::Grant(Box::new(Granted { request, lock })));
            return plan;
        }

        plan
    }

    /// `IsGrantable`.
    fn is_grantable(&self, name: &Name, mode: Mode, steal: bool) -> bool {
        // Steal requests bypass every normal granting rule.
        if steal {
            return true;
        }
        let Some(held) = self.held.get(name) else {
            return true;
        };
        match mode {
            // An exclusive request cannot coexist with any existing lock.
            Mode::Exclusive => false,
            Mode::Shared => held.iter().all(|lock| lock.mode == Mode::Shared),
        }
    }

    /// Records the granted lock and, for a steal, marks what it took.
    fn grant(&mut self, request: &Request, plan: &mut Plan) -> Lock {
        if request.steal {
            let mut emptied = false;
            if let Some(existing) = self.held.get_mut(&request.name) {
                for lock in existing.iter_mut() {
                    lock.stolen = true;
                    self.stolen.insert(lock.id);
                    if lock.env == request.env {
                        plan.reject.push(lock.id);
                    } else {
                        self.owed.entry(lock.env).or_default().push(lock.id);
                        push_unique(&mut plan.wake, lock.env);
                    }
                }
                // Node removes the thief's own locks immediately; the other
                // owners drop their entry on release.
                existing.retain(|lock| lock.env != request.env);
                emptied = existing.is_empty();
            }
            if emptied {
                self.held.remove(&request.name);
            }
        }

        let lock = Lock {
            id: request.id,
            env: request.env,
            name: request.name.clone(),
            mode: request.mode,
            client_id: request.client_id.clone(),
            stolen: false,
        };
        self.held
            .entry(request.name.clone())
            .or_default()
            .push(lock.clone());
        lock
    }

    /// Drops locks stolen from environments other than `env`.
    ///
    /// `CleanupStolenLocks` skips a stolen lock whose owner *is* `env`: that owner
    /// still holds it and removes the entry through its own release path, which is
    /// why [`Manager::release_and_report_stolen`] consults a flag that outlives
    /// the entry.
    fn cleanup_stolen_locks(&mut self, env: EnvId) {
        let mut emptied = Vec::new();
        for (name, locks) in self.held.iter_mut() {
            locks.retain(|lock| !(lock.stolen && lock.env != env));
            if locks.is_empty() {
                emptied.push(name.clone());
            }
        }
        for name in emptied {
            self.held.remove(&name);
        }
    }

    /// Takes the rejections owed to `env`.
    ///
    /// The ids are handed over whether or not the lock is still in the held set:
    /// another environment's `cleanup_stolen_locks` may have dropped the entry
    /// already, and the victim's promise still has to be rejected.
    fn take_owed(&mut self, env: EnvId) -> Vec<u64> {
        self.owed.remove(&env).unwrap_or_default()
    }

    /// Removes a granted lock and reports whether it had been stolen.
    ///
    /// `true` means the lock's `released` promise was already rejected by the
    /// theft, so the caller must not settle it again. This is
    /// `ReleaseLock` plus `Lock::is_stolen`, in one call so the two cannot
    /// disagree.
    pub fn release_and_report_stolen(&mut self, id: u64) -> bool {
        let mut emptied = None;
        for (name, locks) in self.held.iter_mut() {
            if let Some(position) = locks.iter().position(|lock| lock.id == id) {
                locks.remove(position);
                if locks.is_empty() {
                    emptied = Some(name.clone());
                }
                break;
            }
        }
        if let Some(name) = emptied {
            self.held.remove(&name);
        }
        self.stolen.remove(&id)
    }

    /// The locks `env` holds, oldest first.
    pub fn held_by(&self, env: EnvId) -> Vec<Lock> {
        let mut locks: Vec<Lock> = self
            .held
            .values()
            .flatten()
            .filter(|lock| lock.env == env)
            .cloned()
            .collect();
        locks.sort_by_key(|lock| lock.id);
        locks
    }

    /// The requests `env` is waiting on, in queue order.
    pub fn pending_by(&self, env: EnvId) -> Vec<Request> {
        self.queue
            .iter()
            .filter(|request| request.env == env)
            .cloned()
            .collect()
    }

    /// Drops everything belonging to `env`, returning the environments that may
    /// now be able to make progress.
    ///
    /// `CleanupEnvironment`. Node wakes nobody here; waking is the one place this
    /// deliberately does more, because an environment that died holding a lock
    /// would otherwise leave every waiter parked until an unrelated lock of theirs
    /// was released — or forever, if it had none.
    pub fn cleanup_env(&mut self, env: EnvId) -> Vec<EnvId> {
        let mut emptied = Vec::new();
        let mut released = Vec::new();
        for (name, locks) in self.held.iter_mut() {
            locks.retain(|lock| {
                if lock.env == env {
                    released.push(lock.id);
                    false
                } else {
                    true
                }
            });
            if locks.is_empty() {
                emptied.push(name.clone());
            }
        }
        // The ids of this environment's locks leave the stolen set with them, or a
        // create/terminate loop would grow it by one id per stolen lock.
        for id in released {
            self.stolen.remove(&id);
        }
        for name in emptied {
            self.held.remove(&name);
        }
        self.queue.retain(|request| request.env != env);
        self.owed.remove(&env);

        let mut wake = Vec::new();
        for request in &self.queue {
            push_unique(&mut wake, request.env);
        }
        wake
    }

    /// How many requests are queued. Tests and diagnostics.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// How many locks are granted. Tests and diagnostics.
    pub fn granted(&self) -> usize {
        self.held.values().map(Vec::len).sum()
    }
}

fn push_unique(list: &mut Vec<EnvId>, env: EnvId) {
    if !list.contains(&env) {
        list.push(env);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: u64, env: EnvId, name: &str, mode: Mode) -> Request {
        Request {
            id,
            env,
            name: name.encode_utf16().collect(),
            mode,
            client_id: format!("client-{env}"),
            steal: false,
            if_available: false,
        }
    }

    /// The granted id, or 0 for a miss, or `None` for no decision.
    fn decided(plan: &Plan) -> Option<(u64, bool)> {
        match plan.step.as_ref()? {
            Step::Grant(granted) => {
                assert_eq!(granted.request.id, granted.lock.id);
                Some((granted.lock.id, true))
            }
            Step::Miss(request) => Some((request.id, false)),
        }
    }

    #[test]
    fn an_uncontended_request_is_granted_immediately() {
        let mut manager = Manager::default();
        manager.enqueue(request(1, 1, "a", Mode::Exclusive));
        let plan = manager.process(1);
        assert_eq!(decided(&plan), Some((1, true)));
        assert!(plan.wake.is_empty());
        assert!(plan.reject.is_empty());
        assert_eq!(manager.granted(), 1);
        assert_eq!(manager.queued(), 0);
    }

    #[test]
    fn a_second_exclusive_request_waits_for_the_first() {
        let mut manager = Manager::default();
        manager.enqueue(request(1, 1, "a", Mode::Exclusive));
        assert_eq!(decided(&manager.process(1)), Some((1, true)));

        manager.enqueue(request(2, 1, "a", Mode::Exclusive));
        assert_eq!(decided(&manager.process(1)), None);
        assert_eq!(manager.queued(), 1);

        // Releasing the first is what lets the second through.
        assert!(!manager.release_and_report_stolen(1));
        assert_eq!(decided(&manager.process(1)), Some((2, true)));
    }

    #[test]
    fn shared_requests_coexist_and_block_an_exclusive_one() {
        let mut manager = Manager::default();
        manager.enqueue(request(1, 1, "a", Mode::Shared));
        manager.enqueue(request(2, 1, "a", Mode::Shared));
        assert_eq!(decided(&manager.process(1)), Some((1, true)));
        assert_eq!(decided(&manager.process(1)), Some((2, true)));

        manager.enqueue(request(3, 1, "a", Mode::Exclusive));
        assert_eq!(decided(&manager.process(1)), None);
        assert_eq!(manager.granted(), 2);
    }

    #[test]
    fn a_later_shared_request_waits_behind_an_earlier_exclusive_one() {
        // The queue is FIFO per resource, so a shared request queued behind a
        // blocked exclusive one must not jump it even when every *held* lock is
        // shared.
        let mut manager = Manager::default();
        manager.enqueue(request(1, 1, "a", Mode::Shared));
        assert_eq!(decided(&manager.process(1)), Some((1, true)));
        manager.enqueue(request(2, 2, "a", Mode::Exclusive));
        manager.enqueue(request(3, 1, "a", Mode::Shared));

        assert_eq!(decided(&manager.process(1)), None);
        // Neither environment can progress while the shared lock is held, so
        // nothing is woken.
        let plan = manager.process(2);
        assert!(plan.wake.is_empty());
        assert_eq!(decided(&plan), None);

        assert!(!manager.release_and_report_stolen(1));
        // Environment 1 now hands the resource to environment 2's earlier request.
        let plan = manager.process(1);
        assert_eq!(decided(&plan), None);
        assert_eq!(plan.wake, vec![2]);
        assert_eq!(decided(&manager.process(2)), Some((2, true)));
        // Environment 1's own shared request still waits behind that exclusive
        // one, which is the FIFO rule this test is about.
        assert_eq!(decided(&manager.process(1)), None);
        assert!(!manager.release_and_report_stolen(2));
        assert_eq!(decided(&manager.process(1)), Some((3, true)));
    }

    #[test]
    fn if_available_misses_instead_of_queueing() {
        let mut manager = Manager::default();
        manager.enqueue(request(1, 1, "a", Mode::Exclusive));
        assert_eq!(decided(&manager.process(1)), Some((1, true)));

        let mut second = request(2, 1, "a", Mode::Shared);
        second.if_available = true;
        manager.enqueue(second);
        assert_eq!(decided(&manager.process(1)), Some((2, false)));
        // A miss never takes the lock and never leaves a queue entry behind.
        assert_eq!(manager.granted(), 1);
        assert_eq!(manager.queued(), 0);
    }

    #[test]
    fn if_available_on_a_free_resource_is_granted() {
        let mut manager = Manager::default();
        let mut only = request(1, 1, "a", Mode::Exclusive);
        only.if_available = true;
        manager.enqueue(only);
        assert_eq!(decided(&manager.process(1)), Some((1, true)));
    }

    #[test]
    fn steal_marks_the_holder_and_the_holder_is_told_once() {
        let mut manager = Manager::default();
        manager.enqueue(request(1, 1, "a", Mode::Exclusive));
        assert_eq!(decided(&manager.process(1)), Some((1, true)));

        let mut thief = request(2, 2, "a", Mode::Exclusive);
        thief.steal = true;
        manager.enqueue(thief);

        // The victim is woken and told on its next pass, not inline.
        let plan = manager.process(1);
        assert_eq!(decided(&plan), None);
        assert_eq!(plan.wake, vec![2]);
        assert!(plan.reject.is_empty());

        let plan = manager.process(2);
        assert_eq!(decided(&plan), Some((2, true)));
        assert_eq!(plan.wake, vec![1]);

        let plan = manager.process(1);
        assert_eq!(plan.reject, vec![1]);
        // Delivered exactly once.
        assert!(manager.process(1).reject.is_empty());
        // And the victim's own settling must not settle `released` again.
        assert!(manager.release_and_report_stolen(1));
    }

    #[test]
    fn steal_within_one_environment_rejects_immediately() {
        let mut manager = Manager::default();
        manager.enqueue(request(1, 1, "a", Mode::Exclusive));
        assert_eq!(decided(&manager.process(1)), Some((1, true)));

        let mut thief = request(2, 1, "a", Mode::Exclusive);
        thief.steal = true;
        manager.enqueue(thief);
        let plan = manager.process(1);
        assert_eq!(decided(&plan), Some((2, true)));
        assert_eq!(plan.reject, vec![1]);
        // Same environment: nothing to wake.
        assert!(plan.wake.is_empty());
        assert_eq!(manager.granted(), 1);
        assert!(manager.release_and_report_stolen(1));
    }

    #[test]
    fn a_steal_request_goes_to_the_front_of_the_queue() {
        let mut manager = Manager::default();
        manager.enqueue(request(1, 1, "a", Mode::Exclusive));
        assert_eq!(decided(&manager.process(1)), Some((1, true)));
        manager.enqueue(request(2, 2, "a", Mode::Exclusive));
        manager.enqueue(request(3, 3, "a", Mode::Exclusive));

        let mut thief = request(4, 3, "a", Mode::Exclusive);
        thief.steal = true;
        manager.enqueue(thief);

        // Environment 3 sees its own steal request before its ordinary one.
        let plan = manager.process(3);
        assert_eq!(decided(&plan), Some((4, true)));
        assert_eq!(manager.pending_by(3).len(), 1);
    }

    #[test]
    fn a_miss_scan_skips_other_environments_and_wakes_them() {
        let mut manager = Manager::default();
        manager.enqueue(request(1, 1, "a", Mode::Exclusive));
        assert_eq!(decided(&manager.process(1)), Some((1, true)));

        let mut other = request(2, 2, "a", Mode::Exclusive);
        other.if_available = true;
        manager.enqueue(other);

        // Environment 1's pass notices environment 2 can progress with a miss.
        let plan = manager.process(1);
        assert_eq!(plan.wake, vec![2]);
        assert_eq!(decided(&manager.process(2)), Some((2, false)));
    }

    #[test]
    fn a_blocked_environment_is_never_woken_for_nothing() {
        // The livelock guard: two environments queued behind a third's lock must
        // not wake each other.
        let mut manager = Manager::default();
        manager.enqueue(request(1, 1, "a", Mode::Exclusive));
        assert_eq!(decided(&manager.process(1)), Some((1, true)));
        manager.enqueue(request(2, 2, "a", Mode::Exclusive));
        manager.enqueue(request(3, 3, "a", Mode::Exclusive));

        assert!(manager.process(1).wake.is_empty());
        assert!(manager.process(2).wake.is_empty());
        assert!(manager.process(3).wake.is_empty());
    }

    #[test]
    fn cleanup_drops_both_held_locks_and_pending_requests() {
        let mut manager = Manager::default();
        manager.enqueue(request(1, 1, "a", Mode::Exclusive));
        assert_eq!(decided(&manager.process(1)), Some((1, true)));
        manager.enqueue(request(2, 2, "a", Mode::Exclusive));

        assert_eq!(manager.cleanup_env(1), vec![2]);
        assert_eq!(manager.granted(), 0);
        assert_eq!(manager.queued(), 1);

        // The waiter is now first in the queue and is granted on its own pass.
        assert_eq!(decided(&manager.process(2)), Some((2, true)));
    }

    #[test]
    fn cleanup_of_an_environment_that_held_nothing_reports_no_waiter() {
        let mut manager = Manager::default();
        manager.enqueue(request(1, 1, "a", Mode::Exclusive));
        assert_eq!(decided(&manager.process(1)), Some((1, true)));
        assert!(manager.cleanup_env(7).is_empty());
        assert_eq!(manager.granted(), 1);
    }

    #[test]
    fn query_reports_only_the_asking_environment() {
        let mut manager = Manager::default();
        manager.enqueue(request(1, 1, "a", Mode::Shared));
        manager.enqueue(request(2, 2, "a", Mode::Shared));
        assert_eq!(decided(&manager.process(1)), Some((1, true)));
        assert_eq!(decided(&manager.process(2)), Some((2, true)));
        manager.enqueue(request(3, 1, "b", Mode::Exclusive));

        assert_eq!(manager.held_by(1).len(), 1);
        assert_eq!(manager.held_by(2).len(), 1);
        assert_eq!(manager.pending_by(1).len(), 1);
        assert!(manager.pending_by(2).is_empty());
    }

    #[test]
    fn resources_are_independent() {
        let mut manager = Manager::default();
        manager.enqueue(request(1, 1, "a", Mode::Exclusive));
        manager.enqueue(request(2, 1, "b", Mode::Exclusive));
        assert_eq!(decided(&manager.process(1)), Some((1, true)));
        assert_eq!(decided(&manager.process(1)), Some((2, true)));
        assert_eq!(manager.granted(), 2);
    }

    #[test]
    fn names_compare_as_utf16_not_as_display_text() {
        // Two names a lossy UTF-8 round trip would collapse have to stay
        // distinct, because the JavaScript side compares strings exactly.
        let mut manager = Manager::default();
        let mut first = request(1, 1, "a", Mode::Exclusive);
        first.name = vec![0x61, 0xd800];
        let mut second = request(2, 1, "a", Mode::Exclusive);
        second.name = vec![0x61, 0xfffd];
        manager.enqueue(first);
        manager.enqueue(second);
        assert_eq!(decided(&manager.process(1)), Some((1, true)));
        assert_eq!(decided(&manager.process(1)), Some((2, true)));
    }
}
