"""Java/JVM build checks for viporlab repos (Dagger module).

Language-specific module per the TrueNorth per-language-module decision.
Mirrors dagger-checks-c@v1.1.2: declared hooks, build matrix, TRUENORTH
result contract — but stages are Maven-shaped and the artifact gate looks
for built JARs instead of ELF binaries. Entirely inside a pinned toolchain
container (no runner labels, no host toolchain — FR-73/FR-7/NFR-4).

Toolchain: maven:3.9-eclipse-temurin-<JAVA_VERSION> (default 21) + a shared
/root/.m2/repository cache volume so dependency downloads happen once across
runs AND across matrix variants (cache contract P3). Gradle is NOT in the
image: a gradle repo must declare its own build hook and is rejected with
status no_toolchain on the legacy path.

Build contract — DECLARED HOOKS (the preferred control surface): declare
explicit command lines in the repo's own .github/truenorth.yaml:

    build:
      module: github.com/snoby-demo-org/dagger-checks-java@v1.0.0
      hooks:
        resolve: mvn -B -ntp dependency:go-offline   # optional
        build:   mvn -B -ntp package                 # optional

The module self-reads hooks from the mounted source (no workflow changes;
values are single-line commands, no inline comments, run via bash -c in
/src). DECLARED MODE: only the declared stages run, in resolve->build order.
LEGACY (no hooks declared): pom.xml present -> `mvn -B -ntp package`;
build.gradle present -> status no_toolchain; neither -> status no_pom.

The check FAILS on any stage failure or when no JAR artifact
(target/*.jar, maxdepth 3, >1KB) is found -> status no_jar. Warnings are
counted from the build log ([WARNING] lines) and reported; they do not
fail. On failure the module raises RuntimeError with the failing stage's
last 60 log lines; the TRUENORTH_RESULT line is emitted on PASS only.

Result contract (FR-7), emitted as "TRUENORTH_RESULT: {json}":
  {"check":"build","tool":"maven@maven:3.9-eclipse-temurin-<jdk>",
   "status":"pass|fail",
   "failed_stage":null|"resolve"|"build",
   "warnings":N,"binary":"<jar path> (<size> bytes)"}
Internal status strings (resolve_failed etc.) appear only in console
[build] lines, not in the payload.

Matrix (mirrors dagger-checks-c@v1.1.2): the reusable workflow
(truenorth-v2.1+) parses checks.build.matrix (mapping form, {id: {env, hooks}})
and fans ONE runner pod per id, calling build(--variant=<id>) in parallel.
The variant's env is exported before the hook chain; its hooks override the
base hooks per slot; the payload gains "variant": "<id>". Env key
JAVA_VERSION selects the toolchain image (e.g. 17 vs 21). No matrix: block
= single implicit variant. Unknown variant -> hard error naming the
declared ids. The check fails if ANY variant job fails (workflow-level
aggregation, truenorth_report.py).

Run: dagger call --mod github.com/snoby-demo-org/dagger-checks-java build --source=.
"""

import json

import dagger
from dagger import dag, function, object_type

DEFAULT_JDK = "21"

BUILD_SCRIPT = r"""
set -u
cd /src
STATUS=ok
STAGE=resolve
log() { echo "[build] $*"; }

{
  log "toolchain: $(mvn -v 2>/dev/null | head -1 || echo 'maven missing')"

  HOOKS_DECLARED=""
  if [ -n "${TN_HOOK_RESOLVE:-}" ] || [ -n "${TN_HOOK_BUILD:-}" ]; then
    HOOKS_DECLARED=1
    log "declared hooks mode (presence-detection ignored)"
    if [ "$STATUS" = ok ] && [ -n "${TN_HOOK_RESOLVE:-}" ]; then
      STAGE=resolve
      log "stage=resolve (declared)"
      bash -c "$TN_HOOK_RESOLVE" > /tmp/build.log 2>&1 || STATUS="resolve_failed"
    fi
    if [ "$STATUS" = ok ] && [ -n "${TN_HOOK_BUILD:-}" ]; then
      STAGE=build
      log "stage=build (declared)"
      bash -c "$TN_HOOK_BUILD" > /tmp/build.log 2>&1 || STATUS="build_failed"
    fi
  elif [ "$STATUS" = ok ]; then
    if [ -f ./pom.xml ]; then
      STAGE=build
      log "stage=build (default: mvn -B -ntp package)"
      mvn -B -ntp package > /tmp/build.log 2>&1 || STATUS="build_failed"
    elif [ -f ./build.gradle ] || [ -f ./build.gradle.kts ]; then
      STATUS="no_toolchain"
      STAGE=build
      log "gradle project but the checks-java toolchain image ships maven only"
      log "declare a build hook, e.g. build: ./gradlew --no-daemon build"
      echo "gradle projects must declare a build hook; the checks-java toolchain image ships maven only" > /tmp/build.log
    else
      STATUS="no_pom"
      STAGE=build
      log "no pom.xml, build.gradle, or declared hooks -> nothing to build"
    fi
  fi

  if [ "$STATUS" = ok ]; then
    JAR=""
    for c in $(find /src -maxdepth 3 -type f -name '*.jar' -path '*/target/*' -size +1k 2>/dev/null | sort); do
      JAR="$c"; break
    done
    if [ -n "$JAR" ]; then
      SIZE=$(ls -l "$JAR" | awk '{print $5}')
      log "jar: $JAR ($SIZE bytes)"
      echo "$JAR" > /tmp/jar.txt
      echo "$SIZE" > /tmp/jarsize.txt
    else
      STATUS="no_jar"
    fi
  fi

  WARN=$(grep -c '\[WARNING\]' /tmp/build.log 2>/dev/null); WARN=${WARN%%$'\n'*}; WARN=${WARN:-0}
  ERRS=$(grep -c '\[ERROR\]' /tmp/build.log 2>/dev/null); ERRS=${ERRS%%$'\n'*}; ERRS=${ERRS:-0}
  printf '{"status":"%s","failed_stage":"%s","warnings":%s,"errors":%s}\n' \
    "$STATUS" "$STAGE" "$WARN" "$ERRS" > /tmp/jbuild_status.json
  log "status=$STATUS stage=$STAGE warnings=$WARN errors=$ERRS"
} > /tmp/jbuild_console.log 2>&1
exit 0
"""


_HOOK_KEYS = ("resolve", "build")


def _parse_hooks(text: str) -> dict[str, str]:
    """Extract build.hooks.{resolve,build} from truenorth.yaml.

    Minimal line-based parse of our own template-controlled schema (the
    module runtime has no pyyaml): a top-level `build:` block, an indented
    `hooks:` mapping inside it, single-line `key: value` entries. Values are
    used verbatim (outer quotes stripped); unknown keys are ignored.
    """
    hooks: dict[str, str] = {}
    top = None          # current top-level key
    seen_build = False  # a build: key seen inside the current top-level block
    seen_matrix = False # matrix: seen -> base hooks block closed forever
                        # (variant hooks only exist UNDER matrix ids)
    in_hooks = False
    hooks_indent = -1
    leaf_indent = -1    # indent of the first captured leaf; later leaves must
                        # match it exactly, so deeper-nested sections (a
                        # variant's hooks: leaves) can never be absorbed here
    for ln in text.splitlines():
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        indent = len(ln) - len(ln.lstrip())
        stripped = ln.strip()
        if indent == 0:
            key0, _, val0 = stripped.partition(":")
            key0 = key0.strip()
            val0 = val0.strip()
            top = key0
            # a top-level build: block counts as "seen build" too
            seen_build = key0 == "build" and not val0
            seen_matrix = False
            in_hooks = False
            continue
        if ":" not in stripped:
            continue
        key, _, val = stripped.partition(":")
        key = key.strip()
        val = val.strip()
        # hooks may live under a top-level build: block or under checks: -> build:
        if top not in ("checks", "build"):
            continue
        if key == "build" and not val:
            seen_build = True
            seen_matrix = False
            in_hooks = False
            continue
        if key == "matrix" and not val and seen_build:
            seen_matrix = True
            in_hooks = False
            continue
        if key == "hooks" and not val and seen_build and not seen_matrix and not in_hooks:
            in_hooks = True
            hooks_indent = indent
            leaf_indent = -1
            continue
        if in_hooks:
            # hook leaves: same indent as the first leaf, non-empty value.
            # Anything else — dedent to a sibling section, an empty-val header
            # (a nested matrix:/hooks:), an indent jump — closes the block.
            if (val and indent > hooks_indent
                    and (leaf_indent == -1 or indent == leaf_indent)):
                if key in _HOOK_KEYS:
                    hooks[key] = _strip_outer_quotes(val)
                if leaf_indent == -1:
                    leaf_indent = indent
                continue
            in_hooks = False
    return hooks


def _strip_outer_quotes(val: str) -> str:
    """Strip a fully-quoted wrapper only ("..."/'...') — never naive
    both-ends stripping (values like mvn -Dfoo="$(nproc)")."""
    if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
        return val[1:-1]
    return val


def _split_flow(s: str) -> list[str]:
    """Split a single-line YAML flow mapping body on top-level commas
    (quote-aware, escape-aware): 'JAVA_VERSION: "17", FOO: bar' ->
    ['JAVA_VERSION: "17"', 'FOO: bar']. Handles backslash escapes inside
    double quotes and YAML doubled single quotes ('' -> ')."""
    parts: list[str] = []
    buf: list[str] = []
    q = None
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if q:
            if q == '"' and ch == "\\" and i + 1 < n:
                nxt = s[i + 1]
                if nxt in ('"', "\\"):
                    buf.append(nxt)      # YAML unescape: \" -> " and \\ -> \
                else:
                    buf.append(ch)       # unknown escape: keep verbatim
                    buf.append(nxt)
                i += 2
                continue
            if q == "'" and ch == "'" and i + 1 < n and s[i + 1] == "'":
                buf.append("'")          # YAML doubled single quote -> literal '
                i += 2
                continue
            buf.append(ch)
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
            buf.append(ch)
        elif ch == ",":
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    if buf:
        parts.append("".join(buf).strip())
    return [p for p in parts if p]


def _parse_matrix(text: str) -> dict[str, dict]:
    """Extract checks.build.matrix as {variant_id: {"env": {...}, "hooks": {...}}}.

    Mapping form (template-controlled schema, same minimal line-based parse
    as _parse_hooks — the module runtime has no pyyaml):

        checks:
          build:
            matrix:
              temurin-17:
                env:
                  JAVA_VERSION: "17"
                hooks:                      # optional per-variant hook override
                  build: mvn -B -ntp -Pfast package
              temurin-21:
                env:
                  JAVA_VERSION: "21"

    env values and hook lines are verbatim (outer quotes stripped); unknown
    sub-keys are ignored. env/hooks accept block form or single-line flow
    mappings (env: { JAVA_VERSION: "17" }). The reusable workflow
    (truenorth-v2.1) fans one runner pod per id and calls build(--variant=<id>).
    """
    entries: dict[str, dict] = {}
    top = None
    seen_build = False
    in_matrix = False
    matrix_indent = -1
    cur_id = None
    cur_sec = None       # "env" | "hooks" | None
    sec_indent = -1
    for ln in text.splitlines():
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        indent = len(ln) - len(ln.lstrip())
        stripped = ln.strip()
        if indent == 0:
            key0, _, val0 = stripped.partition(":")
            top = key0.strip()
            seen_build = top == "build" and not val0.strip()
            in_matrix = False
            cur_id = None
            cur_sec = None
            continue
        if ":" not in stripped:
            continue
        key, _, val = stripped.partition(":")
        key = key.strip()
        val = val.strip()
        if top not in ("checks", "build"):
            continue
        if key == "build" and not val:
            seen_build = True
            in_matrix = False
            cur_id = None
            cur_sec = None
            continue
        if key == "matrix" and not val and seen_build:
            in_matrix = True
            matrix_indent = indent
            cur_id = None
            cur_sec = None
            continue
        if not in_matrix:
            continue
        if indent <= matrix_indent:      # dedent: matrix block ended
            in_matrix = False
            cur_id = None
            cur_sec = None
            continue
        if cur_sec is not None and indent > sec_indent:
            # leaf of the current env/hooks section
            if val:
                entries[cur_id][cur_sec][key] = _strip_outer_quotes(val)
            continue
        if key in ("env", "hooks") and cur_id is not None:
            # section header (block form) or a single-line flow mapping:
            #   env: { JAVA_VERSION: "17", JOBS: "4" }
            if not val:
                cur_sec = key
                sec_indent = indent
            elif val.startswith("{") and val.endswith("}"):
                inner = val[1:-1].strip()
                if inner:
                    for part in _split_flow(inner):
                        k2, _, v2 = part.partition(":")
                        if v2.strip():
                            entries[cur_id][key][k2.strip()] = _strip_outer_quotes(v2.strip())
                cur_sec = None
            continue
        if not val:                       # a new variant id
            cur_id = key
            entries[cur_id] = {"env": {}, "hooks": {}}
            cur_sec = None
            sec_indent = indent
    return entries


def _toolchain(jdk: str) -> dagger.Container:
    return (
        dag.container()
        .from_(f"maven:3.9-eclipse-temurin-{jdk}")
        .with_mounted_cache("/root/.m2/repository", dag.cache_volume("maven-m2"))
    )


@object_type
class ChecksJava:
    @function
    async def build(self, source: dagger.Directory, variant: str = "") -> str:
        """REAL — the Java/JVM BUILD LEG (not a scan check): resolve -> build (FR-73).

        Fails when a declared stage fails or no target/*.jar artifact is
        produced. Warnings ([WARNING] lines) are counted and reported; they
        do not fail the check. `mvn package` runs the unit-test suite by
        default, so the build leg doubles as the test gate for Maven repos
        unless the repo declares -DskipTests.

        Matrix variants (mirrors dagger-checks-c@v1.1.2): the reusable
        workflow fans one runner pod per id in checks.build.matrix and calls
        build with --variant=<id>. The variant's env is exported before the
        hook chain, JAVA_VERSION selects the toolchain image, and its hooks:
        override the base hooks per slot; the result payload gains a
        "variant" field. Unknown variant -> hard error.
        """
        try:
            cfg = await source.file(".github/truenorth.yaml").contents()
            hooks = _parse_hooks(cfg)
            matrix = _parse_matrix(cfg)
        except Exception:  # noqa: BLE001 — no/unreadable truenorth.yaml -> legacy path
            hooks, matrix = {}, {}
        venv: dict[str, str] = {}
        if variant:
            if variant not in matrix:
                raise RuntimeError(
                    f"unknown build variant '{variant}' — declared in "
                    f"truenorth.yaml: {sorted(matrix) or 'NONE (no matrix block)'}")
            entry = matrix[variant]
            venv = {k: v for k, v in (entry.get("env") or {}).items()}
            # per-variant hook override wins per slot over the base hooks
            hooks = {**hooks, **{k: v for k, v in (entry.get("hooks") or {}).items() if v}}
        jdk = venv.get("JAVA_VERSION", DEFAULT_JDK)
        ctr = (
            _toolchain(jdk)
            .with_mounted_directory("/src", source)
            .with_workdir("/src")
        )
        for k in sorted(venv):
            ctr = ctr.with_env_variable(k, venv[k])
        ctr = (
            ctr
            .with_env_variable("TN_HOOK_RESOLVE", hooks.get("resolve", ""))
            .with_env_variable("TN_HOOK_BUILD", hooks.get("build", ""))
            .with_new_file("/tmp/build.sh", BUILD_SCRIPT)
            .with_exec(["bash", "/tmp/build.sh"])
        )
        status_raw = await ctr.file("/tmp/jbuild_status.json").contents()
        console = await ctr.file("/tmp/jbuild_console.log").contents()
        status = json.loads(status_raw)
        jar = (await ctr.file("/tmp/jar.txt").contents()).strip() if status["status"] == "ok" else ""
        size = (await ctr.file("/tmp/jarsize.txt").contents()).strip() if status["status"] == "ok" else ""

        payload = {
            "check": "build",
            "tool": f"maven@maven:3.9-eclipse-temurin-{jdk}",
            "status": "pass" if status["status"] == "ok" else "fail",
            "failed_stage": status.get("failed_stage") if status["status"] != "ok" else None,
            "warnings": status.get("warnings", 0),
            "binary": f"{jar} ({size} bytes)" if jar else None,
        }
        if variant:
            payload["variant"] = variant
        lines = ["=" * 50, " [build] resolve -> build (maven, real)"]
        lines.append(console.strip())
        if jar:
            lines.append(f"  artifact: {jar} ({size} bytes)")
        lines.append(f"TRUENORTH_RESULT: {json.dumps(payload)}")
        lines.append("=" * 50)
        if status["status"] != "ok":
            try:
                log = await ctr.file("/tmp/build.log").contents()
            except Exception:  # noqa: BLE001 — stage may not have produced its log
                log = console
            tail = "\n".join(log.splitlines()[-60:])
            raise RuntimeError(
                f"build FAILED at stage={status['failed_stage']}\n{tail}"
            )
        return "\n".join(lines)
