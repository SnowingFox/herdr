#!/usr/bin/env bash
# Meta-check for the opt-in controls in `tools/`.
#
#   ./tools/controls.test.sh          # self-test, then every control it owns
#   ./tools/controls.test.sh <path>   # only that file, no self-test
#
# Every control here is opt-in: each builds the CLI or drives a real Node surface,
# so running them in the gate would add minutes to every commit. Opt-in rots, and
# this repository has paid for it twice. `tools/regen-bindings.test.sh` went
# unexecuted for its whole life before it was wired into `tools/check.sh`, and
# `cipher-negative-control.sh` shipped while documenting `exit 2` on a build
# failure but actually exiting 1, because its `exit 2` sat inside
# `output="$(build_and_run ...)"`, where an exit ends only the subshell and the
# script fell through to its `status=1` path.
#
# So this asserts the properties that make a control worth running. None of them
# execute the control, which is what keeps the check cheap enough for the gate:
#
#   1. it is executable and parses (`bash -n`);
#   2. it distinguishes success from failure by *exit status* -- a zero-valued
#      exit path and a non-zero one both exist, and no failure path exits 0;
#   3. no `exit` that decides the verdict is trapped in a subshell.
#
# (3) is the assertion that catches the cipher defect and its whole class: a
# function whose body calls `exit` reports its own status only when it runs in the
# main shell. Called from `$( )`, a pipeline, or a `( )` group, the subshell dies
# and the caller carries on to a status that means something else.
#
# A `# Exit codes:` header, when present, is reconciled against the exits that
# exist, so a documented code no path can produce is a failure rather than prose.
#
# The self-test exists because a checker that cannot fail is the very defect it
# guards: it runs the analysis over fixtures that are the defect shapes, and
# requires each one to be rejected.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check_sh="$here/check.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

failures=0
checks=0
# Counters for the file currently under assertion. They are kept apart from the
# run totals so that the self-test can assert a fixture is rejected without the
# rejection counting as a failure of this check.
afail=0
acheck=0
ok() { printf 'ok   %s\n' "$1"; acheck=$((acheck + 1)); }
no() { printf 'FAIL %s\n' "$1"; afail=$((afail + 1)); acheck=$((acheck + 1)); }

# Writes a copy of a script with everything that is not shell code blanked out,
# one output line per input line so reported line numbers stay true.
#
# Two regions have to go or the analysis reads data as code:
#
#   * single-quoted text, which in these scripts holds embedded JavaScript
#     (`process.exit(1)`) and `trap '... exit 1' EXIT`, a trap that runs at exit
#     time rather than on a verdict path;
#   * here-document bodies, which are only shell when the delimiter is unquoted.
#     The `<<'JS'` bodies in cipher-negative-control.sh and
#     negative-control-zstd.sh are JavaScript, and reading a `process.exit` there
#     as a shell exit would invent a verdict path.
#
# Double quotes are kept rather than blanked: `output="$( ... )"` is the exact bug
# being guarded against, and the substitution inside the quotes still runs. What
# does get blanked inside them is ordinary text, so `echo "it exits 1"` cannot
# look like an exit statement.
shell_view() {
  awk '
    # A heredoc body is not shell when its delimiter is quoted, which is how every
    # heredoc in these controls is written.
    tag != "" {
      if ($0 == tag) { tag = "" }
      printf "\n"
      next
    }
    {
      line = $0
      out = ""
      i = 1
      n = length(line)
      while (i <= n) {
        c = substr(line, i, 1)

        if (state == "sq") {
          # Shell single quotes do not nest and are not escaped; only a closing
          # quote ends one.
          if (c == Q) state = pop()
          out = out " "
          i++
          continue
        }
        if (com) { out = out " "; i++; continue }
        if (state == "dq") {
          if (c == "\\") { out = out "  "; i += 2; continue }
          if (c == "\"") { state = pop(); out = out " "; i++; continue }
          # Only a substitution runs inside double quotes. It is copied through
          # with its body. `$name` and `$?` are copied too, so that
          # `exit "$status"` still reads as an exit carrying a variable.
          if (c == "$" && substr(line, i + 1, 1) == "(") {
            push(state); state = "sub"; depth = 1
            out = out "$("; i += 2
            continue
          }
          if (c == "$") {
            if (substr(line, i + 1, 1) == "?") { out = out "$?"; i += 2; continue }
            if (substr(line, i + 1, 1) == "{") {
              j = i + 2
              while (j <= n && substr(line, j, 1) != "}") j++
              out = out substr(line, i, j - i + 1)
              i = j + 1
              continue
            }
            if (substr(line, i + 1, 1) ~ /[A-Za-z_]/) {
              j = i + 1
              while (j <= n && substr(line, j, 1) ~ /[A-Za-z0-9_]/) j++
              out = out substr(line, i, j - i)
              i = j
              continue
            }
          }
          out = out " "
          i++
          continue
        }

        # normal and sub share their quoting rules; sub only tracks depth, so that
        # the closing paren returns to whatever quoted context it opened inside.
        if (state == "sub") {
          if (c == "(") depth++
          else if (c == ")") {
            depth--
            if (depth == 0) { state = pop(); out = out ")"; i++; continue }
          }
        }
        if (c == "\\") { out = out "  "; i += 2; continue }
        if (c == "$" && substr(line, i + 1, 1) == "(") {
          push(state); state = "sub"; depth = 1
          out = out "$("; i += 2
          continue
        }
        if (c == Q) { push(state); state = "sq"; out = out " "; i++; continue }
        if (c == "\"") { push(state); state = "dq"; out = out " "; i++; continue }
        # `#` starts a comment only at the start of a word, so `${#a[@]}` and
        # `${v#x}` stay code. A comment is a flag rather than a stack entry
        # because nothing inside one can change quoting context.
        if (c == "#" && (i == 1 || substr(line, i - 1, 1) ~ /[[:space:]();&|]/)) {
          com = 1
          out = out " "
          i++
          continue
        }
        out = out c
        i++
      }
      com = 0
      # The `<<` survives the lexer only when it is code, so a heredoc mentioned
      # in prose cannot swallow the rest of the file.
      #
      # This must fire inside a command substitution too. `script="$(cat <<JS`
      # opens a heredoc while the lexer is in the substitution state, and testing
      # only the top-level state left the whole JavaScript body -- including its
      # closing delimiter -- being scanned as shell. That made
      # negative-control-napi-threadsafe.sh look like it had no zero-valued exit
      # at all, because the `exit 0` past the heredoc was swallowed with it.
      if ((state == "n" || state == "sub") && index(out, "<<") > 0) {
        d = out
        sub(/^.*<</, "<<", d)
        # `<<<` is a here-string, not a heredoc: it has no body and no delimiter.
        if (d !~ /^<<</ && match(d, /^<<-?[[:space:]]*[\047"]?[A-Za-z_][A-Za-z0-9_]*/)) {
          tag = substr(d, RSTART, RLENGTH)
          sub(/^<<-?[[:space:]]*/, "", tag)
          gsub(/[\047"]/, "", tag)
        }
      }
      printf "%s\n", out
    }
    # The enclosing depth travels with the state: a substitution that closes
    # inside another must not leave the outer depth at zero, or the next `)` ends
    # a substitution that never opened.
    function push(s) { sp++; stack[sp] = s; dstack[sp] = depth }
    function pop() { depth = dstack[sp]; return sp > 0 ? stack[sp--] : "n" }
    BEGIN { Q = sprintf("%c", 39); state = "n"; sp = 0; stack[0] = "n"
            dstack[0] = 0; depth = 0; com = 0; tag = "" }
  ' "$1"
}

# Prints "<line>\t<kind>\t<value>" for every `exit` that could set the verdict.
# The match needs a statement boundary before `exit`, so `process.exit(1)` and
# `exitCode` cannot satisfy it. Kinds:
#
#   lit   a literal code
#   var   a variable, resolved by codes_for_var
#   last  no argument, or `$?`: forwards the previous status and so cannot itself
#         distinguish success from failure
exit_statements() {
  awk '
    {
      line = $0
      while (match(line, /(^|[;{(]|&&|\|\||then|else|do)[[:space:]]*exit([[:space:]]|;|$)/)) {
        head = substr(line, RSTART, RLENGTH)
        rest = substr(line, RSTART + RLENGTH)
        sub(/^.*exit/, "", head)
        # The argument ends at a statement separator. `exit "$status"` keeps its
        # variable name because the lexer has already reduced the quotes.
        arg = head rest
        sub(/[;&|].*$/, "", arg)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", arg)
        if (arg ~ /^[0-9]+$/) { print FNR "\tlit\t" arg }
        else if (arg == "$?") { print FNR "\tlast\t" }
        else if (arg ~ /^\$?\{?[A-Za-z_][A-Za-z0-9_]*\}?$/) {
          gsub(/[${}]/, "", arg); sub(/^\$/, "", arg); print FNR "\tvar\t" arg
        } else print FNR "\tlast\t"
        line = rest
      }
    }
  ' "$1"
}

# Codes a variable can hold: its literal assignments, plus every `return N` when
# it is ever assigned from `$?`. Three controls report a helper's verdict with
# `status=$?` then `exit "$status"`, so resolving only literal assignments would
# miss their failure path.
#
# Both questions are answered over the whole file rather than line by line: the
# helper that produces the status is defined *above* the assignment, so a single
# forward pass would only see returns that happen to come later.
codes_for_var() {
  awk -v v="$1" '
    { lines[FNR] = $0; n = FNR }
    END {
      for (i = 1; i <= n; i++)
        if (lines[i] ~ ("(^|[^[:alnum:]_])" v "=\\$\\?([^[:alnum:]_]|$)")) saw_q = 1
      for (i = 1; i <= n; i++) {
        if (match(lines[i], "(^|[^[:alnum:]_])" v "=[0-9]+([^[:alnum:]_]|$)")) {
          s = substr(lines[i], RSTART, RLENGTH)
          sub(/^[^=]*=/, "", s)
          sub(/[^0-9].*$/, "", s)
          print s
        }
        if (saw_q && match(lines[i], "(^|[;{(]|&&|then|else|do|[[:space:]])return[[:space:]]+[0-9]+([[:space:]]|;|$)")) {
          s = substr(lines[i], RSTART, RLENGTH)
          sub(/^.*return[[:space:]]+/, "", s)
          sub(/[^0-9].*$/, "", s)
          print s
        }
      }
    }
  ' "$2"
}

# Function names whose body calls `exit` in the main shell.
#
# Each line is tested separately: a collected body cannot be scanned with one `~`
# because awk anchors `^` to the start of the whole string rather than to each
# newline, so a multi-line body would never match. A one-line body (`f() { exit 1; }`)
# is handled on the same line as the header, since that is how a compact control
# usually writes a guard.
functions_that_exit() {
  awk '
    !in_body && /^[A-Za-z_][A-Za-z0-9_]*\(\)[[:space:]]*\{(.*)\}[[:space:]]*$/ {
      name = $0
      sub(/\(\).*/, "", name)
      body = $0
      sub(/^[^{]*\{/, "", body)
      if (body ~ /(^|[;{(]|&&|\|\||then|else|do)[[:space:]]*exit([[:space:]]|;|$)/) print name
      next
    }
    !in_body && /^[A-Za-z_][A-Za-z0-9_]*\(\)[[:space:]]*\{?[[:space:]]*$/ {
      name = $0
      sub(/\(\).*/, "", name)
      in_body = 1
      exits = 0
      next
    }
    in_body {
      if ($0 ~ /(^|[;{(]|&&|\|\||then|else|do)[[:space:]]*exit([[:space:]]|;|$)/) exits = 1
      if ($0 ~ /^\}/) {
        if (exits) print name
        in_body = 0
      }
    }
  ' "$1"
}

# Prints the line number when `fn` is invoked somewhere its `exit` cannot reach
# the caller. Three shapes swallow it, and every one runs the call in a subshell:
# inside `$( )` or backticks, as a non-final element of a pipeline whose status
# therefore comes from another command, and inside an explicit `( )` group.
#
# Two things this deliberately does not flag, because in both the `exit` really
# does set the script's status:
#
#   * `[ cond ] || fail "msg"` and `cmd && fail "msg"` at the top level. `||` and
#     `&&` are control operators, not pipes: `fail` runs in the main shell, so its
#     `exit 1` is the script's status. A first version of this scanner set `pipe`
#     on the second character of a doubled operator and reported these as
#     swallowed, which is a false positive on the most common shape in these
#     controls.
#   * a call that is the *last* element of a pipeline, `x | fail`. Nothing follows
#     to mask its status, so the exit still propagates.
#
# The call site is found by walking the line rather than by regex, because
# `out="$(f "$x")"`, `x=$(a; f)` and `if f; then` all contain the name while only
# some of them are the defect.
subshell_invocation() {
  awk -v fn="$1" '
    {
      line = $0
      n = length(line)

      # The first place the function is invoked as a command word. The prefix has
      # to allow shell keywords: `if ! build ...` is a command position, and it is
      # how a swallowed call usually reads.
      callpos = 0
      for (i = 1; i <= n; i++) {
        if (i > 1 && substr(line, i - 1, 1) ~ /[[:alnum:]_]/) continue
        if (substr(line, i, length(fn)) != fn) continue
        if (substr(line, i + length(fn), 1) ~ /[[:alnum:]_]/) continue
        before = substr(line, 1, i - 1)
        sub(/[[:space:]]+$/, "", before)
        if (before == "" || before ~ /(^|[;{}(&|]|if|then|else|elif|do|while|until|!|&&|\|\|)[[:space:]]*$/) {
          callpos = i
          break
        }
      }
      if (callpos == 0) next

      # Region state *before* the call. `||` and `&&` are consumed as a pair so
      # the second character is not read as a pipe; without that, every
      # `cond || fail` in the tree looked like a swallowed exit.
      depth = 0; pipe_before = 0; tick = 0
      for (i = 1; i < callpos; i++) {
        c = substr(line, i, 1)
        if (tick) { if (c == "`") tick = 0; continue }
        if (c == "`") { tick = 1; continue }
        if (c == "\\") { i++; continue }
        if (c == "|") {
          if (substr(line, i + 1, 1) == "|") { i++; continue }
          pipe_before = 1
          continue
        }
        if (c == "&") {
          if (substr(line, i + 1, 1) == "&") { i++; continue }
          pipe_before = 1
          continue
        }
        if (c == "$" && substr(line, i + 1, 1) == "(") { depth++; i++; continue }
        if (c == "(") depth++
        else if (c == ")") { if (depth > 0) depth-- }
      }

      # Region state *after* the call. A pipe here means the call is not the last
      # element, so its exit cannot be the status of the whole pipeline. A pipe
      # that only leads to another element is what matters; `;` ends the statement.
      tail = substr(line, callpos + length(fn))
      sub(/;.*$/, "", tail)
      pipe_after = (tail ~ /[^|]\|[^|]/ || tail ~ /(^|[^|])\|[[:space:]]*$/)

      if (depth > 0 || tick || pipe_before || pipe_after) print FNR
    }
  ' "$2"
}

# Codes named by a `# Exit codes:` comment. The paragraph is read until the first
# non-comment line, because these headers wrap.
documented_codes() {
  awk '
    found {
      if ($0 !~ /^[[:space:]]*#/) exit
      text = text " " $0
      next
    }
    /^[[:space:]]*#[[:space:]]*Exit codes?:/ { found = 1; text = $0; next }
    END { n = split(text, w, /[^0-9]+/); for (i = 1; i <= n; i++) if (w[i] != "") print w[i] }
  ' "$1"
}

# Prints "<line>\t<code>\t<polarity>" for every literal `exit`, where polarity is
# what the message on that path says the exit means.
#
# This separates "has a non-zero exit somewhere" from "the failure path is the one
# with the non-zero exit". The difference matters: a control can keep a usage-error
# `exit 2` that satisfies every count-based check while its actual failure path
# prints `FAIL: ...` and exits 0, which is the cipher defect with the numbers
# still looking right.
#
# It reads the *original* source, not the lexed view. The lexer blanks quoted text
# precisely because it is data, but the verdict words live in exactly that text
# (`echo "PASS: ..."`), so classifying from the view would see the bare function
# name `fail` on a guard line and miss the `PASS` it is guarding. Only the string
# literals of `echo`/`printf` lines are read, which is where the words that matter
# actually are; a call like `fail "no shell"` contributes nothing, because the
# function name is not a message.
#
# The message belonging to an exit is the nearest `echo`/`printf` above it at the
# same or deeper indentation. Nearest, not "everything in the block": walking the
# whole block reaches the previous statement's message, and `[ x ] || fail ...`
# above a `echo "PASS"` is a different statement whose word `fail` says nothing
# about the exit below it.
exit_polarity() {
  awk '
    { line[FNR] = $0; total = FNR }
    END {
      for (i = 1; i <= total; i++) {
        L = line[i]
        if (L !~ /(^|[;{(]|&&|\|\||then|else|do)[[:space:]]*exit[[:space:]]+[0-9]+([[:space:]]|;|$)/) continue
        code = L
        sub(/^.*exit[[:space:]]+/, "", code)
        sub(/[^0-9].*$/, "", code)

        match(L, /^[[:space:]]*/)
        ind = RLENGTH

        msg = ""
        for (j = i - 1; j >= 1 && j >= i - 8; j--) {
          M = line[j]
          if (M ~ /^[[:space:]]*$/) break
          match(M, /^[[:space:]]*/)
          if (RLENGTH < ind) break
          if (M !~ /(^|[^[:alnum:]_])(echo|printf)([[:space:]]|$)/) continue
          # The literal argument only: everything inside the first pair of quotes.
          if (match(M, /\047[^\047]*\047/) || match(M, /"[^"]*"/)) {
            msg = tolower(substr(M, RSTART + 1, RLENGTH - 2))
            break
          }
        }
        if (msg == "") continue

        fail = (msg ~ /(^|[^a-z])(fail|failed|failure|unexpected|abort|aborted|misbehav|refus)/)
        succ = (msg ~ /(^|[^a-z])(pass|passed|ok)([^a-z]|$)/)
        if (fail && !succ) print i "\t" code "\tfail"
        else if (succ && !fail) print i "\t" code "\tpass"
      }
    }
  ' "$1"
}

# Runs every assertion for one file and returns 0 when all of them held.
assert_control() {
  local path="$1"
  local name view lineno kind value codes c hit fn swallowed missing documented
  local success failure_list unresolved failure_codes
  name="$(basename "$path")"
  view="$tmp/$name.view"
  shell_view "$path" >"$view"

  afail=0
  acheck=0

  if [ ! -x "$path" ]; then
    no "$name is executable"
  else
    ok "$name is executable"
  fi

  if ! err="$(bash -n "$path" 2>&1)"; then
    no "$name parses: $err"
    return 1
  fi
  ok "$name parses"

  success=0
  failure_list=""
  unresolved=""
  while IFS=$'\t' read -r lineno kind value; do
    [ -n "${lineno:-}" ] || continue
    case "$kind" in
      lit)
        if [ "$value" -eq 0 ]; then success=1; else failure_list="$failure_list $value"; fi
        ;;
      var)
        codes="$(codes_for_var "$value" "$view" | sort -u)"
        if [ -z "$codes" ]; then
          unresolved="$unresolved line $lineno (\$$value)"
          continue
        fi
        for c in $codes; do
          if [ "$c" -eq 0 ]; then success=1; else failure_list="$failure_list $c"; fi
        done
        ;;
    esac
  done < <(exit_statements "$view")

  # Falling off the end reports the last command's status, which means 0 only when
  # `set -e` guarantees every command before it succeeded. Three controls here
  # deliberately run `set -uo pipefail` with no `-e` so they can evaluate a failing
  # arm rather than abort on it, and for those the distinction is load-bearing.
  if [ "$success" -eq 0 ] && grep -qE '^[[:space:]]*set[[:space:]]+-[a-zA-Z]*e' "$view"; then
    if ! grep -vE '^[[:space:]]*(#|$)' "$view" | tail -1 |
         grep -qE '(^|[;{(]|&&|\|\||then|else|do)[[:space:]]*exit'; then
      success=1
    fi
  fi

  failure_codes="$(printf '%s\n' $failure_list | sort -u | tr '\n' ' ' | sed 's/^ *//; s/ *$//')"

  if [ "$success" -eq 1 ]; then
    ok "$name has a zero-valued exit path"
  else
    no "$name has no zero-valued exit path, so success is signalled by printing rather than by status"
  fi

  if [ -z "$failure_codes" ]; then
    no "$name has no non-zero exit path, so it cannot report a failed control"
  elif printf '%s\n' $failure_codes | grep -qx 0; then
    no "$name exits 0 on a failure path as well as on its success path"
  else
    ok "$name distinguishes success (0) from failure ($failure_codes)"
  fi

  if [ -n "$unresolved" ]; then
    no "$name exits with a variable that is never assigned a literal code or a function return:$unresolved"
  fi

  # The defect this check exists for: an `exit` that ends only a subshell.
  swallowed=""
  while IFS= read -r fn; do
    [ -n "$fn" ] || continue
    # An awk failure must not read as "no swallowed exit": swallowing it here
    # would turn a broken scanner into a clean bill of health, which is the same
    # class of defect as the controls this file guards.
    if ! hit="$(subshell_invocation "$fn" "$view")"; then
      no "$name: the subshell scanner failed on $fn; no verdict"
      continue
    fi
    if [ -n "$hit" ]; then
      swallowed="$swallowed $fn (line $hit)"
    fi
  done < <(functions_that_exit "$view")
  if [ -n "$swallowed" ]; then
    no "$name calls an exiting function inside a subshell, where its exit cannot set the verdict:$swallowed"
  else
    ok "$name has no exit swallowed by a subshell"
  fi

  # The polarity of the literal exits: a failure path must not exit 0, and a
  # success path must not exit non-zero. This is what count-based checks miss.
  local p_line p_code p_kind polarity_bad=""
  while IFS=$'\t' read -r p_line p_code p_kind; do
    [ -n "${p_line:-}" ] || continue
    if [ "$p_kind" = fail ] && [ "$p_code" -eq 0 ]; then
      polarity_bad="$polarity_bad line $p_line (failure path exits 0)"
    elif [ "$p_kind" = pass ] && [ "$p_code" -ne 0 ]; then
      polarity_bad="$polarity_bad line $p_line (success path exits $p_code)"
    fi
  done < <(exit_polarity "$path")
  if [ -n "$polarity_bad" ]; then
    no "$name has an exit whose code contradicts the message on its path:$polarity_bad"
  else
    ok "$name exit codes agree with the messages on their paths"
  fi

  # A header that promises a code no path produces is how the cipher control read
  # as correct while reporting the wrong status.
  documented="$(documented_codes "$path" | sort -u | tr '\n' ' ' | sed 's/^ *//; s/ *$//')"
  if [ -n "$documented" ]; then
    missing=""
    for c in $documented; do
      if [ "$c" -eq 0 ]; then
        [ "$success" -eq 1 ] || missing="$missing 0"
      else
        printf '%s\n' $failure_codes | grep -qx "$c" || missing="$missing $c"
      fi
    done
    if [ -n "$missing" ]; then
      no "$name documents exit code(s) no path produces:$missing"
    else
      ok "$name documents only codes it can produce: $documented"
    fi
  fi

  [ "$afail" -eq 0 ]
}

# Merges the counters of the file just asserted into the run totals. Kept separate
# from assert_control so the self-test can run a fixture, read its verdict, and
# not have that fixture's expected failures counted against this check.
record() {
  checks=$((checks + acheck))
  failures=$((failures + afail))
}

# Which scripts this check owns.
#
# There is no hand-maintained list, because forgetting to add a new control is the
# failure being fixed. A script is included when its name says it is a control
# (`*control*.sh`) or when `check.sh` does not invoke it, which is what "opt-in"
# means here: a script that runs in the gate cannot rot unnoticed, so it is out of
# scope.
#
# `run-node-tests.sh` is excluded by name. It is the harness driver rather than a
# control: it runs a selection of Node's suite and prints a table, and has no
# pass/fail verdict of its own to check.
select_controls() {
  local path base
  for path in "$here"/*.sh; do
    [ -e "$path" ] || continue
    base="$(basename "$path")"
    case "$base" in
      # check.sh is the gate itself. It necessarily mentions its own name in its
      # usage header, so the "not referenced by check.sh" rule would otherwise
      # include it by luck rather than by intent.
      check.sh | run-node-tests.sh | *.test.sh) continue ;;
      *control*) printf '%s\n' "$path"; continue ;;
    esac
    if [ -f "$check_sh" ] && ! grep -qF "$base" "$check_sh"; then
      printf '%s\n' "$path"
    fi
  done
}

# Fixtures that are the defect shapes, so the analysis above is proven to reject
# them instead of merely printing ok. Named after the shape, not the file.
self_test() {
  local dir="$tmp/fixtures"
  mkdir -p "$dir"

  # A control that is correct: a helper that only `return`s, called from a
  # substitution, and both verdicts reaching a distinct exit code.
  cat >"$dir/ok-control.sh" <<'SH'
#!/usr/bin/env bash
# Exit codes: 0 pass, 2 usage
set -euo pipefail
run() { if [ -z "$1" ]; then return 3; fi; echo "ran $1"; return 0; }
if ! out="$(run "${1:-}")"; then
  echo "usage: $0 <arg>" >&2
  exit 2
fi
echo "$out"
echo "PASS"
exit 0
SH

  # The shape that most often appears in these controls, and the one a pipe bug
  # turns into a false positive: a guard whose failure branch is `|| fail`, and a
  # guard whose failure branch is `cond && fail`. `||` and `&&` are control
  # operators, not pipes, so `fail` runs in the main shell and its `exit 1` is
  # the script's status. Every assertion a call site makes must therefore be
  # checked with the call in *both* the `||` and the `&&` position.
  cat >"$dir/or-guard-control.sh" <<'SH'
#!/usr/bin/env bash
# Exit codes: 0 pass, 1 fail
set -euo pipefail
fail() {
  printf 'RESULT: FAIL — %s\n' "$1"
  exit 1
}
[ -x /bin/sh ] || fail "no shell"
[ -x /nonexistent ] && fail "this must not be reached"
echo "PASS: the guards held"
exit 0
SH

  # The heredoc-in-a-substitution shape. `script="$(cat <<JS` opens the heredoc
  # while the lexer is inside `$( )`, and a scanner that only looks for heredocs
  # at the top level goes on reading the JavaScript body as shell. Here the body
  # contains nothing that resembles an exit, so the only effect is that the
  # `exit 0` after the closing delimiter must still be found.
  cat >"$dir/heredoc-in-substitution-control.sh" <<'SH'
#!/usr/bin/env bash
# Exit codes: 0 pass, 2 usage
set -euo pipefail
case "${1:-}" in
  run) ;;
  *) echo "usage: $0 run" >&2; exit 2 ;;
esac
script="$(cat <<JS
const assert = require('assert');
assert.strictEqual(1, 1);
JS
)"
[ -n "$script" ] || { echo "FAIL: empty script" >&2; exit 1; }
echo "PASS: the generated script was read"
exit 0
SH

  # The cipher shape, reduced: a helper that calls `exit`, invoked in a command
  # substitution. The exit kills only the subshell, so the caller decides.
  cat >"$dir/cmdsub-control.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
build() { exit 3; }
if ! out="$(build)"; then
  exit 1
fi
echo "$out"
echo "PASS"
exit 0
SH

  # The same exit, discarded into a pipeline. `| tee` is the usual form.
  cat >"$dir/pipeline-control.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
build() { exit 3; }
if ! build | tee /dev/null; then
  exit 1
fi
echo "PASS"
exit 0
SH

  # The same exit, inside an explicit subshell group.
  cat >"$dir/subshell-control.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
build() { exit 3; }
if ! ( build ); then
  exit 1
fi
echo "PASS"
exit 0
SH

  # Success signalled by printing. No `set -e`, so falling off the end reports the
  # last command's status rather than a verdict.
  cat >"$dir/print-only-control.sh" <<'SH'
#!/usr/bin/env bash
set -uo pipefail
if [ $# -eq 0 ]; then
  echo "usage: $0 <arg>" >&2
  exit 2
fi
echo "PASS: the control behaved as required"
SH

  # A control that cannot fail.
  cat >"$dir/always-zero-control.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
echo "PASS: nothing was actually measured"
exit 0
SH

  # A header promising a code no path produces, which is the cipher defect in its
  # cheapest form.
  cat >"$dir/doc-mismatch-control.sh" <<'SH'
#!/usr/bin/env bash
# Exit codes: 0 pass, 1 fail, 2 usage
set -euo pipefail
if [ "${1:-}" = "bad" ]; then
  echo "FAIL" >&2
  exit 1
fi
echo "PASS"
exit 0
SH

  # A failure path that exits 0 while a usage error keeps a non-zero code in the
  # file. Every count-based question has the right answer here -- there is a zero
  # exit, there is a non-zero exit, and they differ -- so only the polarity of the
  # messages catches it. This is the shape the real cipher control nearly had.
  cat >"$dir/failure-exits-zero-control.sh" <<'SH'
#!/usr/bin/env bash
# Exit codes: 0 pass, 1 fail, 2 usage
set -uo pipefail
case "${1:-}" in
  before | after) ;;
  *) echo "usage: $0 before|after" >&2; exit 2 ;;
esac
if [ "${1:-}" = "before" ]; then
  echo "FAIL: the control did not behave"
  exit 0
fi
echo "PASS: the control behaved"
exit 0
SH

  chmod +x "$dir"/*.sh
  # A control that is not executable cannot be run at all.
  cp "$dir/ok-control.sh" "$dir/not-executable-control.sh"
  chmod -x "$dir/not-executable-control.sh"

  local case expected
  for case in ok:pass or-guard:pass heredoc-in-substitution:pass \
              cmdsub:fail pipeline:fail subshell:fail print-only:fail \
              always-zero:fail doc-mismatch:fail failure-exits-zero:fail \
              not-executable:fail; do
    expected="${case#*:}"
    case="${case%%:*}"
    path="$dir/$case-control.sh"
    # The status is captured first: `if assert_control ...` runs the function in
    # the condition, and `record` there would set counters in a subshell that
    # discards them.
    local status=0
    assert_control "$path" >"$dir/$case.log" 2>&1 || status=$?
    # The fixture's own assertions are the input to this verdict, not failures of
    # this check: a rejected fixture is a success here. Only the verdict below is
    # counted.
    afail=0
    acheck=0
    if [ "$status" -eq 0 ]; then
      if [ "$expected" = pass ]; then
        ok "self-test: a correct control is accepted"
      else
        no "self-test: the $case shape was accepted"
      fi
    else
      if [ "$expected" = fail ]; then
        ok "self-test: the $case shape is rejected"
      else
        no "self-test: a correct control was rejected"
        sed 's/^/     /' "$dir/$case.log"
      fi
    fi
    record
  done
}

if [ "$#" -gt 0 ]; then
  for path in "$@"; do
    assert_control "$path" || true
    record
  done
else
  self_test

  controls=()
  while IFS= read -r path; do controls+=("$path"); done < <(select_controls)

  # A selection that matched nothing would make every assertion below vacuous,
  # which is the same shape as an audit that compared a value to itself.
  if [ "${#controls[@]}" -eq 0 ]; then
    echo "no controls selected; the selection rule is broken and this check has verified nothing" >&2
    exit 1
  fi

  for path in "${controls[@]}"; do
    assert_control "$path" || true
    record
  done
  printf 'checked %d control(s): %s\n' "${#controls[@]}" \
    "$(printf '%s\n' "${controls[@]}" | xargs -n1 basename | tr '\n' ' ' | sed 's/ *$//')"
fi

if [ "$failures" -ne 0 ]; then
  printf '\n%d of %d assertion(s) failed\n' "$failures" "$checks" >&2
  exit 1
fi
printf '\nall %d assertions passed\n' "$checks"
