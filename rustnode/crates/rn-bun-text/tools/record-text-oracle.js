// Generates `tests/data/text-oracle.json` from a real Bun binary.
//
// Every case is measured, never invented: the file this writes is Bun's own
// answer for each input, and `tests/text_parity.rs` compares the Rust against it.
// Regenerate with:
//
//     bun tests/record-text-oracle.js > tests/data/text-oracle.json
//
// The inputs are chosen to cover what the implementation can get wrong rather
// than to be exhaustive: multi-byte and combining characters for the width and
// slicing paths, truncated escapes for `stripANSI`, and the per-line
// open/close asymmetry for `wrapAnsi`.

'use strict';

const Bun_ = globalThis.Bun;

const widthInputs = [
  ['abc'], ['héllo'], ['日本語'], ['日'], ['🙂'], ['👨‍👩‍👧‍👦'], ['a\u0301'], ['ｆｕｌｌ'],
  ['±'], ['→'], ['\t'], [''], ['\x1b[31mred\x1b[0m'], ['\u001b[31m日\u001b[0m'],
  ['\u001b[31me\u0301\u001b[0m'], ['👨‍👩‍👧‍👦'], ['🇯🇵'], ['🇯'], ['1️⃣'], ['❤️'], ['❤'],
  ['👍🏽'], ['🏳️‍🌈'], ['🏴󠁧󠁢󠁳󠁣󠁴󠁿'], ['한'], ['हिन्दी'], ['ไทย'], ['مرحبا'], ['שלום'],
  ['☺'], ['☺️'], ['™️'], ['a\u200db'], ['\u0301'], ['\uFE0F'], ['\u200D'],
  ['日本a語🙂'], ['e\u0301\u0302\u0303'], ['\u00AD'], ['\u200B'], ['\uFEFF'],
  ['\r\n'], ['\u0000'], ['\u007F'], ['\u0085'], ['\u00A0'], ['\u200A'],
  ['ｱ'], ['Ａ'], ['─'], ['○'], ['Ω'],
];

const escapeCases = ['\x1b[31mred\x1b[0m', '\x1b[1;4mx\x1b[0m',
  '\x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\', '\x1b[38;5;196mx\x1b[0m',
  '\x1b[38;2;255;0;0mx\x1b[0m', '\x1b[2Ax', '', 'a\x1bb', '\x1b[31',
  '\x1b[1m\x1b[31mab\x1b[0m\x1b[32mcd\x1b[0m', '\x1b[31ma\u0301\u{1F1EF}\u{1F1F5}\x1b[0m',
  '\x1b[1mé日本語\x1b[0m', 'plain', '\x1b[31m', '\x9b31mx', 'a\x9bb', '\x1b(Ba',
  '\x1b]0;title\x07after', '\x1b[0m', '\x1b[m'];

const wrapCases = [
  ['the quick brown fox jumps', 10, {}],
  ['1234567890', 10, {}],
  ['abcdefghijklmnop', 5, {}],
  ['abcdefghij', 3, { hard: true }],
  ['a\nb', 10, {}],
  ['', 10, {}],
  ['abc', 0, {}],
  ['abc', -1, {}],
  ['\x1b[31mred green blue\x1b[0m', 5, {}],
  ['hello   ', 10, {}],
  ['   hello', 10, {}],
  ['   hello', 10, { trim: false }],
  ['a b c d', 3, {}],
  ['aa bb cc', 5, {}],
  ['abcdefghijklmnop', 5, { hard: true }],
  ['12345', 5, {}],
  ['a', 1, {}],
  [' ', 5, {}],
  ['   ', 5, {}],
  ['a\tb', 5, {}],
  ['the quick brown fox', 8, { wordWrap: false }],
  ['a\r\nb', 5, {}],
  ['a\rb', 5, {}],
  ['日本語', 2, {}],
  ['日本語', 4, {}],
  ['日本語', 2, { hard: true }],
  ['🙂🙂🙂', 2, {}],
  ['\x1b[1m\x1b[31mab cd ef\x1b[0m', 2, {}],
  ['\x1b[41mab cd\x1b[0m', 2, {}],
  ['ab cd', 2, {}],
  ['\x1b[0mab cd\x1b[0m', 2, {}],
  ['\x1b[99mab cd\x1b[0m', 2, {}],
  ['a\u0301b c', 2, {}],
  ['abc def', 2.7, {}],
  ['\x1b[31mabcdef\x1b[0m', 3, { hard: true }],
  ['a\n\nb', 5, {}],
  ['a\n', 5, {}],
  ['a  b', 5, {}],
  ['a  b', 2, {}],
  ['±±±', 2, {}],
  ['±±±', 2, { ambiguousIsNarrow: false }],
];

const sliceCases = [
  ['abcdef', 1, 3],
  ['\x1b[31mabcdef\x1b[0m', 1, 3],
  ['\x1b[31mabcdef\x1b[0m', 0, 6],
  ['\x1b[31mabcdef\x1b[0m', 0, null],
  ['\x1b[31mabcdef\x1b[0m', -2, null],
  ['\x1b[31mabcdef\x1b[0m', 0, 0],
  ['\x1b[31mabcdef\x1b[0m', 0, 10],
  ['\x1b[31mabcdef\x1b[0m', 10, null],
  ['abcdef', -10, null],
  ['日本語', 0, 2],
  ['日本語', 1, 3],
  ['日本語', 1, 2],
  ['🙂🙂', 0, 2],
  ['🙂🙂', 1, 3],
  ['a\u0301bc', 0, 1],
  ['a\u0301bc', 1, 3],
  ['é日本語x', 0, 3],
  ['é日本語x', 1, 5],
  ['\x1b[1mabcdef\x1b[0m', 2, 4],
  ['\x1b[1m\x1b[31mabcdef\x1b[0m', 2, 4],
  ['\x1b[41mabcdef\x1b[0m', 2, 4],
  ['\x1b[31mabc\x1b[0mdef', 1, 5],
  ['\x1b[31mabc', 0, 3],
  ['\x1b[1mab\x1b[4mcd\x1b[0mef', 0, 4],
  ['abcdef', 4, 2],
  ['abcdef', 3, 3],
  ['abcdef', 1.7, 3.2],
  ['abcdef', 2, null],
  ['\x1b[31mabcdef\x1b[0m', 2, null],
  ['\x1b[31m\x1b[0m', 0, 1],
  ['abcdef', null, null],
];

const escapeInputs = ['<>&"\'`', 'a & b', "'", '`', '<b>', '', 'plain text', '日本語 <b>'];

// `wrapAnsi`/`sliceAnsi` are called with an explicit `null` end meaning "absent",
// so the recorder passes `undefined` for it to keep Bun's default.
const omit = Symbol('omit');

function record(value) {
  if (value === omit || value === null) return undefined;
  return value;
}

const out = {
  stringWidth: [],
  stripANSI: [],
  wrapAnsi: [],
  sliceAnsi: [],
  escapeHTML: [],
};

for (const [text] of widthInputs) {
  for (const countAnsi of [false, true]) {
    for (const wide of [false, true]) {
      for (const perCodePoint of [false, true]) {
        const width = Bun_.stringWidth(text, {
          countAnsiEscapeCodes: countAnsi,
          ambiguousIsNarrow: !wide,
          perCodePoint,
        });
        out.stringWidth.push([text, countAnsi, wide, perCodePoint, width]);
      }
    }
  }
}

for (const text of escapeCases) {
  out.stripANSI.push([text, Bun_.stripANSI(text)]);
}

for (const [text, columns, options] of wrapCases) {
  const result = Bun_.wrapAnsi(text, columns, options);
  out.wrapAnsi.push([text, columns, result, !!options.hard, options.wordWrap !== false, options.trim !== false]);
}

for (const [text, start, end] of sliceCases) {
  const args = [text, start === null ? undefined : start];
  if (end !== null) args.push(end);
  const result = Bun_.sliceAnsi(...args);
  out.sliceAnsi.push([text, start === null ? 0 : start, end === null ? null : end, result]);
}

for (const text of escapeInputs) {
  out.escapeHTML.push([text, Bun_.escapeHTML(text)]);
}

process.stdout.write(JSON.stringify(out, null, 1) + '\n');
