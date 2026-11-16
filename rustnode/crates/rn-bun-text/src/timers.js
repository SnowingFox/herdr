'use strict';

// `Bun.sleep`, in JavaScript because it needs a real timer.
//
// `sleep` returns a promise that settles on the event loop. Building that from
// Rust would mean constructing a `Promise` by hand, extracting its `resolve` and
// handing it to `setTimeout` across native frames; here it is the language's own
// `new Promise`. The measured contract:
//
//   sleep(number | Date)              resolves after the delay
//   sleep(NaN)                        resolves at once (Bun treats NaN as 0)
//   sleep(-5)                         resolves at once
//   sleep(Date in the past)           resolves at once
//   sleep("10" | 10n | null | {})     TypeError, NO code
//                                     "sleep expects a number (milliseconds)"
//
// `Date` is accepted and means "not before this instant", not "wait this many
// milliseconds".

(function installSleep() {
  'use strict';

  function sleep(milliseconds) {
    let delay;
    if (typeof milliseconds === 'number') {
      // A `NaN` delay is Bun's zero, not an error: `Bun.sleep(NaN)` resolves in
      // about a millisecond.
      delay = milliseconds !== milliseconds ? 0 : milliseconds;
    } else if (milliseconds instanceof Date) {
      const target = milliseconds.getTime();
      delay = target !== target ? 0 : target - Date.now();
    } else {
      const error = new TypeError('sleep expects a number (milliseconds)');
      // Deliberately no `code`: this is the one argument error in the group
      // that carries none, and it is measured.
      throw error;
    }
    if (delay < 0) delay = 0;
    return new Promise((resolve) => {
      setTimeout(resolve, delay);
    });
  }

  return { sleep };
});
