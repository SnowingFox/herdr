// The same queries `tests/parity.rs` runs against the Rust binding, run against
// a real `node`. Kept as a file rather than an inline `-e` string so both sides
// are readable side by side and a change to one is obvious in review.
//
// The fixture tree is built by the Rust test in the current working directory
// as `fx/`, which is why every path here is relative to `process.cwd()`.
const { internalBinding } = require('internal/test/binding');
const binding = internalBinding('modules');

const root = process.cwd() + '/fx';
const out = {};

const guard = (fn) => {
  try {
    const value = fn();
    return value === undefined ? '__undefined__' : value;
  } catch (error) {
    return 'THREW:' + error.code;
  }
};

const norm = (value) => Array.isArray(value)
  ? { array: Array.from(value.slice(0, 6), (item) => item === undefined ? '__undefined__' : item) }
  : value;

out.read_plain = norm(guard(() => binding.readPackageJSON(root + '/plain/package.json')));
out.read_modtype = norm(guard(() => binding.readPackageJSON(root + '/modtype/package.json')));
out.read_malformed = norm(guard(() => binding.readPackageJSON(root + '/malformed/package.json')));
out.read_absent = norm(guard(() => binding.readPackageJSON(root + '/nope/package.json')));
out.read_exports = norm(guard(() => binding.readPackageJSON(root + '/scope/node_modules/pkg/package.json')));
out.scope_plain = norm(guard(() => binding.getPackageScopeConfig('file://' + root + '/plain/lib/x.js')));
out.scope_pkg = norm(guard(() => binding.getPackageScopeConfig('file://' + root + '/scope/node_modules/pkg/lib/x.js')));
out.scope_malformed = norm(guard(() => binding.getPackageScopeConfig('file://' + root + '/malformed/x.js')));
out.type_plain = norm(guard(() => binding.getPackageType('file://' + root + '/plain/x.js')));
out.type_modtype = norm(guard(() => binding.getPackageType('file://' + root + '/modtype/x.js')));
out.type_bad_url = norm(guard(() => binding.getPackageType('https://example.com/x.js')));
out.nearest_type_inner_trailing = norm(guard(() => binding.getNearestParentPackageJSONType(root + '/nearest-sub/a/')));
out.nearest_type_inner_file = norm(guard(() => binding.getNearestParentPackageJSONType(root + '/nearest-sub/a/x.js')));
out.nearest_type_nm = norm(guard(() => binding.getNearestParentPackageJSONType(root + '/inmod/node_modules/pkg/sub/x.js')));
out.nearest_type_parent = norm(guard(() => binding.getNearestParentPackageJSONType(root + '/parent/sub/deep/x.js')));
out.nearest_type_none = norm(guard(() => binding.getNearestParentPackageJSONType('/tmp/parity-nowhere/x.js')));

process.stdout.write(JSON.stringify(out));
