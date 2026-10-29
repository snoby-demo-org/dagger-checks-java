"""Java/JVM build checks for viporlab repos (Dagger module).

Language-specific module per the TrueNorth per-language-module decision.
Mirrors dagger-checks-c@v1.1.2: declared hooks, build matrix, TRUENORTH
result contract — but stages are Maven/Gradle-shaped and the artifact gate
looks for built JARs instead of ELF binaries. Entirely inside a pinned
toolchain container (no runner labels, no host toolchain — FR-73/FR-7/NFR-4).

Toolchains (chosen per repo, see "Build tool detection"):
  maven:  maven:3.9-eclipse-temurin-<JAVA_VERSION> (default 21) + shared
          /root/.m2/repository cache volume (cache contract P3).
  gradle: gradle:<GRADLE_VERSION>-jdk<JAVA_VERSION> (defaults 9.2.1 / 21)
          + shared /root/.gradle cache volume (wrapper dists + caches).
  gradle-wrapper (repo has ./gradlew): eclipse-temurin:<JAVA_VERSION>-jdk
          + the same /root/.gradle volume — the repo's wrapper pins the
          Gradle version, so the image only supplies the JDK.
Both gradle images run as root (gradle needs write access to /src/build).

Build contract — DECLARED HOOKS (the preferred control surface): declare
explicit command lines in the repo's own .github/truenorth.yaml:

    build:
      module: github.com/snoby-demo-org/dagger-checks-java@v1.1.0
      hooks:
        resolve: mvn -B -ntp dependency:go-offline   # optional
        build:   mvn -B -ntp package                 # optional
        # gradle repo:
        # build: ./gradlew --no-daemon build

The module self-reads hooks from the mounted source (no workflow changes;
values are single-line commands, no inline comments, run via bash -c in
/src). DECLARED MODE: only the declared stages run, in resolve->build order.

LEGACY (no hooks declared): pom.xml present -> `mvn -B -ntp package`;
build.gradle(.kts)/settings.gradle(.kts) present -> gradle path:
`./gradlew --no-daemon build` when gradlew exists (wrapper, repo-pinned
version), else `gradle --no-daemon build` from the toolchain image;
neither -> status no_pom. If both pom.xml and a gradle marker exist the
Maven path wins (log line says so).

Gradle remote build cache (the shared-cache layer for ephemeral pods):
pass --cache-url (plus --cache-user / --cache-pass=env:SECRET for Basic
auth, --cache-push to flip push) on the dagger call — the runner
environment's TRUENORTH_GRADLE_CACHE_URL/USER/PASS/PUSH and a variant's
env block are the fallbacks. When a URL is present the module generates an init script wiring
HttpBuildCache (push defaults true; Basic auth via TRUENORTH_GRADLE_CACHE_
USER/PASS; http:// URLs get allowInsecureProtocol) and:
  - legacy/default gradle invocations get `--init-script <file> --build-cache`
  - declared hooks whose first token is gradle/gradlew get the same flags
    appended (unless the hook already passes --init-script)
  - maven hooks are never touched.
The payload gains "build_cache": <url|null>. Point the URL at a self-hosted
build cache node (silo / fosterstack/cache; the official Gradle Build Cache
Node is EOL 2026-12-31). Recommended: run gradle with --no-daemon on
ephemeral pods (the default commands do; declared hooks should too — two
gradle invocations in one pod pay JVM+config startup twice).

The check FAILS on any stage failure or when no JAR artifact
(*/target/*.jar or */build/libs/*.jar, maxdepth 4, >256 bytes) is found ->
status no_jar. Warnings are counted from the build log ([WARNING] lines
for maven; [WARN]/javac `: warning:` lines for gradle) and reported; they
do not fail. On failure the module raises RuntimeError with the failing
stage's last 60 log lines; the TRUENORTH_RESULT line is emitted on PASS
only.

Result contract (FR-7), emitted as "TRUENORTH_RESULT: {json}":
  {"check":"build","tool":"maven@maven:3.9-eclipse-temurin-<jdk>|
   gradle@gradle:<v>-jdk<jdk>|gradle-wrapper@eclipse-temurin:<jdk>-jdk",
   "status":"pass|fail",
   "failed_stage":null|"resolve"|"build",
   "warnings":N,"binary":"<jar path> (<size> bytes)",
   "build_cache":<url|null>,"gradle_cache_hits":N,"elapsed_s":N}
gradle_cache_hits counts `FROM-CACHE` task lines in the build log — on a
cold engine with the remote cache configured it is the proof the cache is
actually serving hits (0 = cache miss or not configured). elapsed_s is the
wall time of the hook chain.
Internal status strings (resolve_failed etc.) appear only in console
[build] lines, not in the payload.

Matrix (mirrors dagger-checks-c@v1.1.2): the reusable workflow
(truenorth-v2.1+) parses checks.build.matrix (mapping form, {id: {env, hooks}})
and fans ONE runner pod per id, calling build(--variant=<id>) in parallel.
The variant's env is exported before the hook chain; its hooks override the
base hooks per slot; the payload gains "variant": "<id>". Env keys
JAVA_VERSION and GRADLE_VERSION select the toolchain image (e.g. 17 vs 21;
9.2.1 vs 8.14.3 — jdk8/11 need a GRADLE_VERSION that still ships those,
e.g. gradle:8.14.3-jdk8). No matrix: block = single implicit variant.
Unknown variant -> hard error naming the declared ids. The check fails if
ANY variant job fails (workflow-level aggregation, truenorth_report.py).

Run: dagger call --mod github.com/snoby-demo-org/dagger-checks-java build --source=.
"""

import json
import os
import re

import dagger
from dagger import dag, function, object_type

DEFAULT_JDK = "21"
DEFAULT_GRADLE_VERSION = "9.2.1"
GRADLE_INIT_PATH = "/tmp/tn-build-cache.init.gradle"
_CACHE_ENV = ("TRUENORTH_GRADLE_CACHE_URL", "TRUENORTH_GRADLE_CACHE_USER",
              "TRUENORTH_GRADLE_CACHE_PASS", "TRUENORTH_GRADLE_CACHE_PUSH")

# Auto-generated at run time when TRUENORTH_GRADLE_CACHE_URL is set. An init
# script applies to any build (groovy or kotlin DSL projects) and injects the
# remote HttpBuildCache without repos editing their own settings.gradle.
GRADLE_INIT_SCRIPT = r"""// Auto-generated by dagger-checks-java — remote build cache wiring.
import org.gradle.caching.http.HttpBuildCache

settingsEvaluated { settings ->
  settings.buildCache {
    local { enabled = true }
    remote(HttpBuildCache) {
      url = java.net.URI.create(System.getenv('TRUENORTH_GRADLE_CACHE_URL'))
      push = Boolean.parseBoolean(System.getenv('TRUENORTH_GRADLE_CACHE_PUSH') ?: 'true')
      def u = System.getenv('TRUENORTH_GRADLE_CACHE_USER')
      def p = System.getenv('TRUENORTH_GRADLE_CACHE_PASS')
      if (u != null && !u.isEmpty() && p != null) {
        credentials {
          username = u
          password = p
        }
      }
      if (url.toString().startsWith('http://')) {
        allowInsecureProtocol = true
      }
    }
  }
}
"""

BUILD_SCRIPT = r"""
set -u
cd /src
STATUS=ok
STAGE=resolve
T0=$SECONDS
log() { echo "[build] $*"; }
INIT=/tmp/tn-build-cache.init.gradle
GFLAGS=""
if [ -n "${TRUENORTH_GRADLE_CACHE_URL:-}" ] && [ -f "$INIT" ]; then
  GFLAGS="--init-script $INIT --build-cache"
  log "remote build cache: $TRUENORTH_GRADLE_CACHE_URL (push=${TRUENORTH_GRADLE_CACHE_PUSH:-true})"
else
  log "remote build cache: not configured (local /root/.gradle cache only)"
fi

{
  case "${TN_TOOL:-maven}" in
    gradle-wrapper)
      log "toolchain: repo-pinned gradle wrapper on $(java -version 2>&1 | head -1)"
      log "gradle: $(${TN_GRADLE_BIN:-./gradlew} --version 2>/dev/null | grep -m1 '^Gradle' || echo 'wrapper downloads on first run')"
      ;;
    gradle)
      log "toolchain: $(gradle --version 2>/dev/null | grep -m1 '^Gradle' || echo 'gradle missing') on $(java -version 2>&1 | head -1)"
      ;;
    *)
      log "toolchain: $(mvn -v 2>/dev/null | head -1 || echo 'maven missing')"
      ;;
  esac

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
    elif [ -f ./build.gradle ] || [ -f ./build.gradle.kts ] || [ -f ./settings.gradle ] || [ -f ./settings.gradle.kts ]; then
      STAGE=build
      if [ -f ./gradlew ]; then
        chmod +x ./gradlew 2>/dev/null || true
        log "stage=build (default: ./gradlew --no-daemon build; wrapper pins the gradle version)"
        ./gradlew --no-daemon $GFLAGS build > /tmp/build.log 2>&1 || STATUS="build_failed"
      else
        log "stage=build (default: gradle --no-daemon build from the toolchain image)"
        gradle --no-daemon $GFLAGS build > /tmp/build.log 2>&1 || STATUS="build_failed"
      fi
    else
      STATUS="no_pom"
      STAGE=build
      log "no pom.xml, gradle marker, or declared hooks -> nothing to build"
    fi
  fi

  if [ "$STATUS" = ok ]; then
    JAR=""
    for c in $(find /src -maxdepth 4 -type f -name '*.jar' \( -path '*/target/*' -o -path '*/build/libs/*' \) -size +256c 2>/dev/null | sort); do
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

  HITS=0
  if [ "${TN_TOOL:-maven}" != "maven" ] && [ -f /tmp/build.log ]; then
    HITS=$(grep -c 'FROM-CACHE' /tmp/build.log 2>/dev/null); HITS=${HITS%%$'\n'*}; HITS=${HITS:-0}
    UTD=$(grep -c 'UP-TO-DATE' /tmp/build.log 2>/dev/null); UTD=${UTD%%$'\n'*}; UTD=${UTD:-0}
    log "cache evidence: $HITS FROM-CACHE, $UTD UP-TO-DATE"
    grep -iE 'could not (load|remote)|unable to (load|store)|Caching has been disabled' /tmp/build.log 2>/dev/null | head -5 | while IFS= read -r l; do
      log "cache-diag: $l"
    done
  fi
  ELAPSED=$((SECONDS - T0))
  case "${TN_TOOL:-maven}" in
    maven*)
      WARN=$(grep -c '\[WARNING\]' /tmp/build.log 2>/dev/null); WARN=${WARN%%$'\n'*}; WARN=${WARN:-0}
      ERRS=$(grep -c '\[ERROR\]' /tmp/build.log 2>/dev/null); ERRS=${ERRS%%$'\n'*}; ERRS=${ERRS:-0}
      ;;
    *)
      WARN=$(grep -c -E '(\[WARN\]|: warning:)' /tmp/build.log 2>/dev/null); WARN=${WARN%%$'\n'*}; WARN=${WARN:-0}
      ERRS=$(grep -c -E '(\[ERROR\]|: error:)' /tmp/build.log 2>/dev/null); ERRS=${ERRS%%$'\n'*}; ERRS=${ERRS:-0}
      ;;
  esac
  printf '{"status":"%s","failed_stage":"%s","warnings":%s,"errors":%s,"gradle_cache_hits":%s,"elapsed_s":%s}\n' \
    "$STATUS" "$STAGE" "$WARN" "$ERRS" "$HITS" "$ELAPSED" > /tmp/jbuild_status.json
  log "status=$STATUS stage=$STAGE warnings=$WARN errors=$ERRS cache_hits=$HITS elapsed=${ELAPSED}s"
} > /tmp/jbuild_console.log 2>&1
exit 0
"""


_HOOK_KEYS = ("resolve", "build")

_GRADLE_FIRST_TOKEN = re.compile(r"^(\./)?gradlew?(\.bat)?$")


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


async def _file_exists(source: dagger.Directory, name: str) -> bool:
    try:
        await source.file(name).contents()
        return True
    except Exception:  # noqa: BLE001 — missing file raises in the python SDK
        return False


def _parse_build_scalars(text: str) -> dict[str, str]:
    """Extract scalar config keys from the checks.build block: cache_url,
    cache_user, cache_secret_uri, cache_push. Same minimal line-based parse
    as _parse_hooks (module runtime has no pyyaml); values verbatim (outer
    quotes stripped). This keeps modules self-configuring — the reusable
    workflow only ever runs `dagger call --mod <module> build --source=.`
    and passes no per-repo args.
    """
    scalars: dict[str, str] = {}
    keys = {"cache_url", "cache_user", "cache_secret_uri", "cache_push"}
    top = None
    seen_checks = False
    seen_build = False
    seen_matrix = False
    for ln in text.splitlines():
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        indent = len(ln) - len(ln.lstrip())
        stripped = ln.strip()
        if indent == 0:
            key0, _, val0 = stripped.partition(":")
            top = key0.strip()
            seen_checks = top == "checks" and not val0.strip()
            seen_build = top == "build" and not val0.strip()
            seen_matrix = False
            continue
        if ":" not in stripped:
            continue
        key, _, val = stripped.partition(":")
        key = key.strip()
        val = val.strip()
        if seen_build and not seen_matrix and indent > 0:
            # top-level build: block (same shape as the hooks parser accepts)
            if key in keys and val:
                scalars.setdefault(key, _strip_outer_quotes(val))
            if key == "matrix" and not val:
                seen_matrix = True
            continue
        if not (seen_checks and indent > 0):
            continue
        if key == "build" and not val:
            seen_build = True
            seen_matrix = False
            continue
        if key == "matrix" and not val and seen_build:
            seen_matrix = True
            continue
        if seen_build and not seen_matrix and key in keys and val:
            scalars.setdefault(key, _strip_outer_quotes(val))
    return scalars


async def _detect_tool(source: dagger.Directory, hooks: dict[str, str]) -> str:
    """Pick "maven" | "gradle" | "gradle-wrapper".

    Declared hooks win: a hook whose first token is gradle/gradlew makes it a
    gradle repo (./gradlew -> wrapper image). Otherwise legacy presence
    detection; pom.xml wins over a gradle marker when both exist (existing
    maven repos are unaffected).
    """
    joined = " ".join(hooks.values())
    if re.search(r"(^|[\s;&(])(\./)?gradlew(\.bat)?\b", joined):
        return "gradle-wrapper"
    if re.search(r"(^|[\s;&(])gradle\b", joined):
        return "gradle"
    if await _file_exists(source, "pom.xml"):
        return "maven"
    for marker in ("build.gradle.kts", "build.gradle",
                   "settings.gradle.kts", "settings.gradle"):
        if await _file_exists(source, marker):
            if await _file_exists(source, "gradlew"):
                return "gradle-wrapper"
            return "gradle"
    return "maven"


def _gradle_hook_append(cmd: str, enabled: bool) -> str:
    """Append --init-script/--build-cache to a declared gradle hook."""
    if not enabled or not cmd.strip() or "--init-script" in cmd:
        return cmd
    first = cmd.split(None, 1)[0]
    if not _GRADLE_FIRST_TOKEN.match(first):
        return cmd
    return f"{cmd} --init-script {GRADLE_INIT_PATH} --build-cache"


def _toolchain(tool: str, jdk: str, gradle_ver: str) -> dagger.Container:
    if tool == "maven":
        return (
            dag.container()
            .from_(f"maven:3.9-eclipse-temurin-{jdk}")
            .with_mounted_cache("/root/.m2/repository", dag.cache_volume("maven-m2"))
        )
    if tool == "gradle-wrapper":
        base = f"eclipse-temurin:{jdk}-jdk"
    else:
        base = f"gradle:{gradle_ver}-jdk{jdk}"
    return (
        dag.container()
        .from_(base)
        .with_user("root")  # gradle image defaults to user "gradle"; /src must be writable
        .with_env_variable("GRADLE_USER_HOME", "/root/.gradle")
        .with_mounted_cache("/root/.gradle", dag.cache_volume("gradle-home"))
    )


@object_type
class ChecksJava:
    @function
    async def build(self,
                    source: dagger.Directory,
                    variant: str = "",
                    cache_url: str = "",
                    cache_user: str = "",
                    cache_pass: dagger.Secret | None = None,
                    cache_push: bool = True) -> str:
        """REAL — the Java/JVM BUILD LEG (not a scan check): resolve -> build (FR-73).

        Maven and Gradle are both first-class: the toolchain image is chosen
        per repo (declared hooks or presence detection). Fails when a
        declared stage fails or no */target/*.jar or */build/libs/*.jar
        artifact is produced. Warnings are counted and reported; they do not
        fail the check. `mvn package` / `gradle build` run the unit-test
        suite by default, so the build leg doubles as the test gate unless
        the repo declares -DskipTests / -x test.

        Matrix variants (mirrors dagger-checks-c@v1.1.2): the reusable
        workflow fans one runner pod per id in checks.build.matrix and calls
        build with --variant=<id>. The variant's env is exported before the
        hook chain; JAVA_VERSION (and GRADLE_VERSION for installed-gradle
        images) selects the toolchain image; its hooks override the base
        hooks per slot; the result payload gains a "variant" field. Unknown
        variant -> hard error.

        Remote build cache: pass --cache-url on the dagger call (or set
        TRUENORTH_GRADLE_CACHE_URL in the runner env / a variant's env
        block) and the module injects an init script wiring HttpBuildCache
        with push=true into every gradle invocation.
        """
        try:
            cfg = await source.file(".github/truenorth.yaml").contents()
            hooks = _parse_hooks(cfg)
            matrix = _parse_matrix(cfg)
            scalars = _parse_build_scalars(cfg)
        except Exception:  # noqa: BLE001 — no/unreadable truenorth.yaml -> legacy path
            hooks, matrix, scalars = {}, {}, {}
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
        tool = await _detect_tool(source, hooks)
        jdk = venv.get("JAVA_VERSION", DEFAULT_JDK)
        gradle_ver = venv.get("GRADLE_VERSION", DEFAULT_GRADLE_VERSION)

        # remote build cache: function args > truenorth.yaml scalars > env.
        # The yaml scalars keep the module self-configuring (the reusable
        # workflow passes no per-repo args); cache_secret_uri resolves
        # ENGINE-side via the dagger secret provider (env: URIs need the var
        # in the ENGINE's env — true for in-pod engines, not shared ones).
        cache_pass_val = ""
        if cache_pass is not None:
            cache_pass_val = await cache_pass.plaintext()
        elif scalars.get("cache_secret_uri"):
            try:
                cache_pass_val = await dag.secret(scalars["cache_secret_uri"]).plaintext()
            except Exception as exc:  # noqa: BLE001 — provider missing -> clear failure
                raise RuntimeError(
                    f"cache_secret_uri '{scalars['cache_secret_uri']}' could not be "
                    f"resolved by the engine secret provider: {exc}") from exc
        push_val = str(cache_push)
        if cache_push and scalars.get("cache_push", "").strip().lower() in ("false", "no", "0"):
            push_val = "false"
        cache_cfg = {
            "TRUENORTH_GRADLE_CACHE_URL": cache_url.strip()
            or scalars.get("cache_url", "").strip()
            or venv.get("TRUENORTH_GRADLE_CACHE_URL", os.environ.get("TRUENORTH_GRADLE_CACHE_URL", "")),
            "TRUENORTH_GRADLE_CACHE_USER": cache_user.strip()
            or scalars.get("cache_user", "").strip()
            or venv.get("TRUENORTH_GRADLE_CACHE_USER", os.environ.get("TRUENORTH_GRADLE_CACHE_USER", "")),
            "TRUENORTH_GRADLE_CACHE_PASS": cache_pass_val
            or venv.get("TRUENORTH_GRADLE_CACHE_PASS", os.environ.get("TRUENORTH_GRADLE_CACHE_PASS", "")),
            "TRUENORTH_GRADLE_CACHE_PUSH": venv.get("TRUENORTH_GRADLE_CACHE_PUSH", push_val),
        }
        cache_url = cache_cfg["TRUENORTH_GRADLE_CACHE_URL"].strip()
        cache_on = bool(cache_url)

        if tool == "gradle":
            hooks = {k: _gradle_hook_append(v, cache_on) for k, v in hooks.items()}
        elif tool == "maven":
            hooks = {k: _gradle_hook_append(v, False) for k, v in hooks.items()}
        else:  # gradle-wrapper — same treatment, hooks reference ./gradlew
            hooks = {k: _gradle_hook_append(v, cache_on) for k, v in hooks.items()}

        if tool == "gradle-wrapper":
            tool_name = "gradle-wrapper"
            toolchain_desc = f"eclipse-temurin:{jdk}-jdk (repo-pinned wrapper)"
        elif tool == "gradle":
            tool_name = "gradle"
            toolchain_desc = f"gradle:{gradle_ver}-jdk{jdk}"
        else:
            tool_name = "maven"
            toolchain_desc = f"maven:3.9-eclipse-temurin-{jdk}"

        ctr = (
            _toolchain(tool, jdk, gradle_ver)
            .with_mounted_directory("/src", source)
            .with_workdir("/src")
        )
        for k in sorted(venv):
            ctr = ctr.with_env_variable(k, venv[k])
        if cache_on:
            for k in _CACHE_ENV:
                if cache_cfg[k]:
                    ctr = ctr.with_env_variable(k, cache_cfg[k])
            ctr = ctr.with_new_file(GRADLE_INIT_PATH, GRADLE_INIT_SCRIPT)
        ctr = (
            ctr
            .with_env_variable("TN_TOOL", tool)
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
            "tool": f"{tool_name}@{toolchain_desc}",
            "status": "pass" if status["status"] == "ok" else "fail",
            "failed_stage": status.get("failed_stage") if status["status"] != "ok" else None,
            "warnings": status.get("warnings", 0),
            "binary": f"{jar} ({size} bytes)" if jar else None,
            "build_cache": cache_url if cache_on else None,
            "gradle_cache_hits": status.get("gradle_cache_hits", 0),
            "elapsed_s": status.get("elapsed_s", 0),
        }
        if variant:
            payload["variant"] = variant
        lines = ["=" * 50, f" [build] resolve -> build ({tool_name}, real)"]
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
