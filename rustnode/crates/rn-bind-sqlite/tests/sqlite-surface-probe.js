'use strict';
//
// Prints one line of JSON describing the observable `node:sqlite` surface.
//
// It runs unchanged under the pinned Node oracle and under rustnode, so every
// assertion in `tests/differential.rs` and `tests/surface.rs` is a comparison
// between two real runtimes rather than between rustnode and a table someone
// typed. Values are read exactly the way Node's own tests read them —
// `db.limits.length` as a plain property access — because the defect this file
// was written for made the property *look* right to `typeof` while being a dead
// snapshot.
//
// Deliberately not included: anything that depends on `backup`, which rustnode
// declares deferred. Its absence is asserted separately instead of being folded
// into a general "surface matches" claim.

const sqlite = require('node:sqlite');

const LIMIT_NAMES = [
  'length', 'sqlLength', 'column', 'exprDepth', 'compoundSelect', 'vdbeOp',
  'functionArg', 'attach', 'likePatternLength', 'variableNumber', 'triggerDepth',
];

// The five names `lib/sqlite.js` destructures. `constants` is an object, not a
// class, and `backup` is a function rustnode defers.
const CLASS_NAMES = ['Database', 'DatabaseSync', 'Statement', 'StatementSync', 'Session'];

function describe(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (descriptor === undefined) return null;
  return {
    get: typeof descriptor.get,
    set: typeof descriptor.set,
    valueType: 'value' in descriptor ? typeof descriptor.value : 'absent',
    writable: descriptor.writable,
    enumerable: descriptor.enumerable,
    configurable: descriptor.configurable,
  };
}

function accessors(object, names) {
  const out = {};
  for (const name of names) out[name] = describe(object, name);
  return out;
}

const out = {};

out.exports = Object.keys(sqlite).sort();
out.aliases = {
  database: sqlite.Database === sqlite.DatabaseSync,
  statement: sqlite.Statement === sqlite.StatementSync,
};

const db = new sqlite.DatabaseSync(':memory:');
const statement = db.prepare('SELECT 1 AS one');
const statement2 = db.prepare('SELECT 2 AS two');
const session = db.createSession();
const tagStore = db.createTagStore();
const tagStore2 = db.createTagStore();
const iterator = db.prepare('SELECT 1 AS one').iterate();
const iterator2 = db.prepare('SELECT 2 AS two').iterate();

// --- 1. limits values. Every one must be a number, and the numbers must be
// --- SQLite's, so they are compared element by element rather than counted.
out.limits = {};
out.limits.types = {};
for (const name of LIMIT_NAMES) {
  out.limits[name] = db.limits[name];
  out.limits.types[name] = typeof db.limits[name];
}
out.limits.keys = Object.keys(db.limits);
out.limits.ownNames = Object.getOwnPropertyNames(db.limits);
out.limits.protoNames = Object.getOwnPropertyNames(Object.getPrototypeOf(db.limits));
out.limits.sameObjectOnEveryRead = db.limits === db.limits;
out.limits.sharedPrototypeAcrossDatabases =
  Object.getPrototypeOf(new sqlite.DatabaseSync(':memory:').limits) ===
  Object.getPrototypeOf(db.limits);

// --- 2. limits membership is an accessor view, not a data snapshot. A fresh
// --- database is used so nothing has been read yet at descriptor time.
{
  const fresh = new sqlite.DatabaseSync(':memory:');
  out.limits.memberDescriptors = accessors(fresh.limits, LIMIT_NAMES);
}
{
  const live = new sqlite.DatabaseSync(':memory:');
  const limits = live.limits;
  // The member must survive `delete`. Node has no own property to remove, so the
  // interceptor answers again on the next read; a data property disappears.
  out.limits.deleteReturn = delete limits.length;
  out.limits.hasOwnAfterDelete = Object.hasOwn(limits, 'length');
  out.limits.valueAfterDelete = limits.length;
  // It must also refuse replacement. Node installs no definer and answers
  // `DontDelete` from its query handler, so this throws.
  let redefine;
  try {
    Object.defineProperty(limits, 'length', {
      value: 424242, writable: true, enumerable: true, configurable: true,
    });
    redefine = 'redefined:' + limits.length;
  } catch (error) {
    redefine = 'throw:' + (error.constructor && error.constructor.name);
  }
  out.limits.redefine = redefine;
}
{
  // A write must reach the connection, not just the object.
  const live = new sqlite.DatabaseSync(':memory:');
  live.limits.attach = 0;
  out.limits.writeReadBack = live.limits.attach;
  try {
    live.exec("ATTACH ':memory:' AS aux1");
    out.limits.writeReachesConnection = 'attached';
  } catch (error) {
    out.limits.writeReachesConnection = 'error:' + error.code;
  }
  const live2 = new sqlite.DatabaseSync(':memory:');
  live2.limits.variableNumber = 5;
  try {
    live2.prepare('SELECT ?1,?2,?3,?4,?5,?6');
    out.limits.writeReachesPrepare = 'prepared';
  } catch (error) {
    out.limits.writeReachesPrepare = 'error:' + error.code;
  }
}
{
  const validating = new sqlite.DatabaseSync(':memory:');
  const attempt = (value) => {
    try {
      validating.limits.length = value;
      return 'ok:' + validating.limits.length;
    } catch (error) {
      return 'throw:' + error.code;
    }
  };
  out.limits.setString = attempt('x');
  out.limits.setFloat = attempt(1.5);
  out.limits.setNegative = attempt(-1);
}
{
  // An unknown name is an ordinary property: the interceptor reports "not
  // intercepted" and default handling takes over.
  const permissive = new sqlite.DatabaseSync(':memory:');
  out.limits.unknownBeforeSet = permissive.limits.nope;
  permissive.limits.nope = 3;
  out.limits.unknownAfterSet = permissive.limits.nope;
}

// --- 3. Where each class accessor lives and what kind of property it is.
//
// Node installs these with `SetSideEffectFreeGetter`, which puts them on the
// *instance* template. That is observable: `Object.keys(db)` is
// `['isOpen', 'isTransaction', 'limits']` and the prototype has none of them.
out.instances = {
  database: {
    ownNames: Object.getOwnPropertyNames(db).sort(),
    accessors: accessors(db, ['isOpen', 'isTransaction', 'limits']),
  },
  statement: {
    ownNames: Object.getOwnPropertyNames(statement).sort(),
    accessors: accessors(statement, ['sourceSQL', 'expandedSQL']),
  },
  tagStore: {
    ownNames: Object.getOwnPropertyNames(tagStore).sort(),
    accessors: accessors(tagStore, ['size', 'capacity', 'db']),
  },
};
out.prototypes = {
  database: Object.getOwnPropertyNames(sqlite.DatabaseSync.prototype),
  statement: Object.getOwnPropertyNames(sqlite.StatementSync.prototype),
  session: Object.getOwnPropertyNames(sqlite.Session.prototype),
  tagStore: Object.getOwnPropertyNames(Object.getPrototypeOf(tagStore)),
  databaseHasLimits: Object.prototype.hasOwnProperty.call(
    sqlite.DatabaseSync.prototype, 'limits'),
};

// --- 4. instanceof and prototype identity for every exported class.
out.instanceof = {};
for (const name of CLASS_NAMES) {
  const constructor = sqlite[name];
  out.instanceof[name] = {
    database: db instanceof constructor,
    statement: statement instanceof constructor,
    statement2: statement2 instanceof constructor,
    session: session instanceof constructor,
    tagStore: tagStore instanceof constructor,
  };
}
out.prototypeIdentity = {
  database: Object.getPrototypeOf(db) === sqlite.DatabaseSync.prototype,
  statement: Object.getPrototypeOf(statement) === sqlite.StatementSync.prototype,
  session: Object.getPrototypeOf(session) === sqlite.Session.prototype,
  statementsSharePrototype:
    Object.getPrototypeOf(statement) === Object.getPrototypeOf(statement2),
  tagStoresSharePrototype:
    Object.getPrototypeOf(tagStore) === Object.getPrototypeOf(tagStore2),
};
// --- the statement iterator, which is a real class `new` reaches and whose
// --- prototype chain runs through the global `Iterator.prototype`.
{
  const prototype = Object.getPrototypeOf(iterator);
  const parent = Object.getPrototypeOf(prototype);
  out.iterator = {
    prototypeOwnNames: Object.getOwnPropertyNames(prototype),
    constructorName: prototype.constructor && prototype.constructor.name,
    parentIsGlobalIteratorPrototype:
      typeof Iterator !== 'undefined' && parent === Iterator.prototype,
    prototypesShared:
      Object.getPrototypeOf(iterator) === Object.getPrototypeOf(iterator2),
    constructorsShared: iterator.constructor === iterator2.constructor,
    nextType: typeof iterator.next,
    returnType: typeof iterator.return,
  };
  try {
    new (prototype.constructor)();
    out.iterator.construct = 'constructed';
  } catch (error) {
    out.iterator.construct = error.code || (error.constructor && error.constructor.name);
  }
}

out.constructorIdentity = {
  database: db.constructor === sqlite.DatabaseSync,
  statement: statement.constructor === sqlite.StatementSync,
  session: session.constructor === sqlite.Session,
  tagStoreName: tagStore.constructor && tagStore.constructor.name,
  statementName: statement.constructor && statement.constructor.name,
  databaseName: db.constructor && db.constructor.name,
  iteratorName: iterator.constructor && iterator.constructor.name,
};

// --- 5. `new` on a runtime-only class still throws, now that instances are
// --- allocated from the very template that throws.
out.construct = {};
for (const name of ['Statement', 'StatementSync', 'Session']) {
  try {
    new sqlite[name]();
    out.construct[name] = 'constructed';
  } catch (error) {
    out.construct[name] = error.code || (error.constructor && error.constructor.name);
  }
}

process.stdout.write(JSON.stringify(out) + '\n');
