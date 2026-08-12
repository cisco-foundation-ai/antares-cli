# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Generic CWE evidence derived from public APIs, language syntax, and protocols."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class CweEvidenceMatch:
    cwe_id: str
    label: str
    score: int


@dataclass(slots=True, frozen=True)
class _EvidenceRule:
    label: str
    cwe_scores: tuple[tuple[str, int], ...]
    tokens: tuple[str, ...]
    languages: frozenset[str] = frozenset()
    required_token_groups: tuple[tuple[str, ...], ...] = ()


_SENSITIVE_VALUE_TOKENS = (
    "password",
    "passwd",
    "api_key",
    "api key",
    "secret",
    "credential",
    "access_token",
    "access token",
    "accesstoken",
    "auth_token",
    "auth token",
    "authtoken",
    "bearer token",
    "refresh_token",
    "refresh token",
    "refreshtoken",
    "session_token",
    "session token",
    "sessiontoken",
)


_EVIDENCE_RULES = (
    _EvidenceRule(
        label="regular-expression processing",
        cwe_scores=(("CWE-1333", 110), ("CWE-400", 75)),
        tokens=(
            "new regexp(",
            "regexp.compile(",
            "re.compile(",
            "regex::new(",
            "pattern.compile(",
        ),
    ),
    _EvidenceRule(
        label="schema and format validation",
        cwe_scores=(("CWE-1286", 120), ("CWE-20", 100)),
        tokens=(
            "jsonschema.validate(",
            "jsonschema.draft",
            "jsonschemafactory",
            "schemafactory.newinstance(",
            "new ajv(",
            "ajv.compile(",
        ),
    ),
    _EvidenceRule(
        label="HTTP header and message parsing",
        cwe_scores=(("CWE-113", 125), ("CWE-444", 125), ("CWE-436", 120)),
        tokens=(
            "content-length",
            "transfer-encoding",
            "httpheaders",
            "httpheader",
            "http2headers",
            "header validation",
            "headername",
            "headervalue",
        ),
    ),
    _EvidenceRule(
        label="outbound HTTP request construction",
        cwe_scores=(("CWE-918", 120), ("CWE-601", 75)),
        tokens=(
            "http.request(",
            "https.request(",
            "http.newrequest(",
            "http.newrequestwithcontext(",
            ".client.do(",
            "client.do(",
            "requests.get(",
            "requests.post(",
            "httpx.get(",
            "httpx.post(",
        ),
    ),
    _EvidenceRule(
        label="unbounded request-body accumulation",
        cwe_scores=(("CWE-400", 125), ("CWE-770", 120)),
        tokens=(
            "body += chunk",
            "body = body + chunk",
            "chunks.push(chunk",
            "buffer.concat(chunks",
        ),
        required_token_groups=((".on('data'", '.on("data"', ".on(`data`"),),
        languages=frozenset({"javascript", "typescript"}),
    ),
    _EvidenceRule(
        label="parser/resource-boundary handling",
        cwe_scores=(
            ("CWE-400", 110),
            ("CWE-770", 90),
            ("CWE-1286", 110),
            ("CWE-1287", 110),
            ("CWE-674", 115),
            ("CWE-754", 75),
        ),
        tokens=(
            "maxdepth",
            "max_depth",
            "max_recursion_depth",
            "recursionlimit",
            "recursive depth",
            "maximum nesting",
            "nesting depth",
            "parsing depth",
        ),
    ),
    _EvidenceRule(
        label="structured-data parser validation",
        cwe_scores=(("CWE-20", 110), ("CWE-1286", 100), ("CWE-400", 70)),
        tokens=(
            "yaml.node",
            "json.loads(",
            "yaml.safe_load(",
            "tomllib.loads(",
            "toml.loads(",
            "serde_json::from_",
            "serde_yaml::from_",
        ),
    ),
    _EvidenceRule(
        label="security-sensitive randomness",
        cwe_scores=(("CWE-338", 120), ("CWE-330", 100)),
        tokens=(
            "new random(",
            "math.random(",
            "random.random(",
            "rand.newsource(",
            "java.util.random",
            ".nextrandom",
        ),
    ),
    _EvidenceRule(
        label="dynamic code or template generation",
        cwe_scores=(
            ("CWE-94", 125),
            ("CWE-95", 100),
            ("CWE-1336", 90),
            ("CWE-20", 75),
        ),
        tokens=(
            "new function(",
            "eval(",
            "exec(",
            "compile(template",
            "template.compile(",
            "groovyshell",
            "scriptengine",
        ),
    ),
    _EvidenceRule(
        label="unsafe or unauthenticated deserialization",
        cwe_scores=(
            ("CWE-502", 125),
            ("CWE-345", 110),
            ("CWE-913", 115),
            ("CWE-184", 115),
        ),
        tokens=(
            "pickle.loads",
            "pickle.load(",
            "torch.load(",
            "yaml.load(",
            "marshal.loads",
            "objectinputstream",
            "readobject(",
            "deserialize(",
        ),
    ),
    _EvidenceRule(
        label="unsafe memory and buffer access",
        cwe_scores=(
            ("CWE-119", 120),
            ("CWE-125", 115),
            ("CWE-787", 115),
            ("CWE-120", 95),
        ),
        tokens=(
            "unsafe fn",
            "unsafe {",
            "get_unchecked",
            "from_raw_parts",
            "unsafe.pointer",
            "memcpy(",
            "strcpy(",
            "strcat(",
        ),
        languages=frozenset({"rust", "go", "c", "cpp"}),
    ),
    _EvidenceRule(
        label="file serving and resource exposure",
        cwe_scores=(
            ("CWE-402", 115),
            ("CWE-668", 110),
            ("CWE-22", 105),
            ("CWE-552", 95),
        ),
        tokens=(
            "staticfileserver",
            "readallbytes(",
            "send_file(",
            "servefile(",
            "http.fileserver(",
            "static resource",
            "static file",
            "public directory",
        ),
    ),
    _EvidenceRule(
        label="privilege and authorization controls",
        cwe_scores=(
            ("CWE-250", 120),
            ("CWE-862", 115),
            ("CWE-863", 105),
            ("CWE-732", 90),
        ),
        tokens=(
            "securitycontext",
            "privileged: true",
            "net_admin",
            "setuid(",
            "seteuid(",
            "runasuser",
            "rolebinding",
            "clusterrole",
            "authorizationmanager",
            "securityfilterchain",
            "accesscontrol",
        ),
    ),
    _EvidenceRule(
        label="authorization and access-control enforcement",
        cwe_scores=(("CWE-862", 125), ("CWE-863", 115), ("CWE-285", 100)),
        tokens=(
            "authorizationmanager",
            "securityfilterchain",
            "accesscontrol",
            "checkpermission(",
            "haspermission(",
            "permissionchecker",
            "securityinterceptor",
        ),
    ),
    _EvidenceRule(
        label="anti-CSRF request protection",
        cwe_scores=(("CWE-352", 130),),
        tokens=("csrf", "xsrf", "anti-forgery", "antiforgery"),
    ),
    _EvidenceRule(
        label="cryptographic signature verification",
        cwe_scores=(("CWE-347", 125), ("CWE-345", 115), ("CWE-295", 110)),
        tokens=(
            "signature.getinstance(",
            ".initverify(",
            "verify(signature",
            "verify_signature",
            "verifysignature",
            "publickey.verify(",
            "signedxml",
            "checksignature(",
        ),
    ),
    _EvidenceRule(
        label="dynamic object property mutation",
        cwe_scores=(("CWE-1321", 125), ("CWE-915", 100), ("CWE-913", 75)),
        tokens=(
            "__proto__",
            "constructor.prototype",
            "object.setprototypeof(",
            "prototype pollution",
            "prototypepollution",
        ),
        languages=frozenset({"javascript", "typescript"}),
    ),
    _EvidenceRule(
        label="ignored return value or error handling",
        cwe_scores=(
            ("CWE-252", 120),
            ("CWE-755", 110),
            ("CWE-754", 100),
            ("CWE-703", 110),
        ),
        tokens=(
            ", _ :=",
            "_, _ =",
            "catch (exception ignored",
            "catch (ignored",
            "except pass",
            "except:\n        pass",
        ),
    ),
    _EvidenceRule(
        label="LDAP query construction",
        cwe_scores=(("CWE-90", 125), ("CWE-74", 90), ("CWE-20", 75)),
        tokens=(
            "ldap.search(",
            "ldapsearch(",
            "searchfilter",
            "ldap filter",
            "dircontext.search(",
        ),
    ),
    _EvidenceRule(
        label="contextual output encoding",
        cwe_scores=(("CWE-116", 120), ("CWE-79", 115), ("CWE-74", 80)),
        tokens=(
            "html.escapestring(",
            "html.escape(",
            "encodeforhtml(",
            "escapehtml(",
            "dompurify.sanitize(",
            "output encoding",
            "contextual escape",
        ),
    ),
    _EvidenceRule(
        label="terminal and control-sequence output",
        cwe_scores=(("CWE-74", 120), ("CWE-116", 110), ("CWE-150", 95)),
        tokens=(
            "\\x1b[",
            "\\u001b[",
            "\\033[",
            "ansi escape",
            "escape sequence",
        ),
        required_token_groups=((".sprint(", "fmt.fprint", "writer", "output"),),
    ),
    _EvidenceRule(
        label="shared-state synchronization",
        cwe_scores=(("CWE-362", 120), ("CWE-662", 115), ("CWE-667", 75)),
        tokens=(
            "sync.mutex",
            "sync.rwmutex",
            ".lock()",
            ".unlock()",
            "synchronized (",
            "reentrantlock",
            "pthread_mutex",
            "atomic::",
            "nonreentrant",
            "reentrancyguard",
            "reentrancy_guard",
        ),
    ),
    _EvidenceRule(
        label="temporary-file creation and cleanup",
        cwe_scores=(("CWE-377", 120), ("CWE-459", 120), ("CWE-276", 70)),
        tokens=(
            "tempfile.mktemp(",
            "namedtemporaryfile(",
            "mkstemp(",
            "createtempfile(",
            "os.tempdir(",
            "ioutil.tempfile(",
            "os.createtemp(",
        ),
    ),
    _EvidenceRule(
        label="sensitive-data logging",
        cwe_scores=(("CWE-532", 115), ("CWE-200", 75)),
        tokens=(
            "logger.info(",
            "logger.debug(",
            "log.printf(",
            "log.println(",
            "logging.info(",
            "console.log(",
        ),
        required_token_groups=(_SENSITIVE_VALUE_TOKENS,),
    ),
    _EvidenceRule(
        label="archive or compressed-data expansion",
        cwe_scores=(("CWE-409", 120), ("CWE-400", 105), ("CWE-770", 85)),
        tokens=(
            "zipfile(",
            "zipfile.zipfile(",
            ".extractall(",
            "gzip.newreader(",
            "tarfile.open(",
            "zipinputstream",
            "gzipinputstream",
            "decompress(",
        ),
    ),
    _EvidenceRule(
        label="URL decoding and repeated parameter handling",
        cwe_scores=(
            ("CWE-177", 120),
            ("CWE-235", 105),
            ("CWE-20", 75),
        ),
        tokens=(
            "queryunescape(",
            "urldecode(",
            "decodeuricomponent(",
            "url.query()[",
            "getparametervalues(",
            "getall(",
            "repeated parameter",
        ),
    ),
    _EvidenceRule(
        label="sensitive configuration storage",
        cwe_scores=(("CWE-922", 125), ("CWE-200", 90), ("CWE-312", 80)),
        tokens=(
            "config.set(",
            "self.set(",
            "settings.set(",
            "preferences.set(",
            "write_config",
            "save_config",
        ),
        required_token_groups=(
            _SENSITIVE_VALUE_TOKENS,
            ("config", "settings", "preferences"),
        ),
    ),
    _EvidenceRule(
        label="HTTP redirect destination handling",
        cwe_scores=(("CWE-601", 125), ("CWE-20", 70)),
        tokens=(
            "http.redirecthandler(",
            "http.redirect(",
            "response.redirect(",
            "res.redirect(",
            "redirect(url",
            "redirect_uri",
            "redirect_url",
        ),
    ),
    _EvidenceRule(
        label="conflicting HTTP parameter sources",
        cwe_scores=(("CWE-235", 125), ("CWE-20", 75)),
        tokens=("req.params[", "request.path_params", ".path_params["),
        required_token_groups=(("req.query[", "request.query_params", ".query_params["),),
        languages=frozenset({"javascript", "typescript", "python"}),
    ),
    _EvidenceRule(
        label="operating-system command execution",
        cwe_scores=(("CWE-78", 130), ("CWE-77", 120)),
        tokens=(
            "childprocess.exec(",
            "child_process.exec(",
            "exec.command(",
            "runtime.getruntime().exec(",
            "subprocess.popen(",
            "subprocess.run(",
            "os.system(",
            "require('child_process').exec",
            'require("child_process").exec',
            "require('child_process').spawn",
            'require("child_process").spawn',
        ),
    ),
    _EvidenceRule(
        label="legacy or weak cryptographic algorithm",
        cwe_scores=(("CWE-327", 125), ("CWE-328", 105)),
        tokens=(
            "hashlib.md5(",
            "hashlib.sha1(",
            'messagedigest.getinstance("md5',
            'messagedigest.getinstance("sha-1',
            "messagedigest.getinstance('md5",
            "messagedigest.getinstance('sha-1",
            'cipher.getinstance("des',
            "cipher.getinstance('des",
            "md5.new(",
            "sha1.new(",
            "des.new(",
            "des_ecb",
            "createcipher('des",
            'createcipher("des',
            "rc4",
        ),
    ),
    _EvidenceRule(
        label="user-influenced path construction",
        cwe_scores=(("CWE-22", 120), ("CWE-35", 110), ("CWE-36", 105)),
        tokens=(
            "filepath.join(",
            "path.join(",
            "paths.get(",
            ".resolve(user",
            "joinpath(user",
        ),
    ),
    _EvidenceRule(
        label="allow-list and deny-list protection",
        cwe_scores=(("CWE-693", 125), ("CWE-184", 120)),
        tokens=(
            "allowlist",
            "allow_list",
            "whitelist",
        ),
        required_token_groups=(
            (
                "denylist",
                "deny_list",
                "blacklist",
                "dangerous",
            ),
        ),
    ),
    _EvidenceRule(
        label="compiler control-flow generation",
        cwe_scores=(("CWE-670", 120), ("CWE-691", 115)),
        tokens=("codegen", "compile_", "compiler", "emit_", "generate_"),
        required_token_groups=(
            ("jump", "branch", "label", "opcode", "control flow", "control_flow"),
            ("ast", "ir_", "syntax", "bytecode"),
        ),
    ),
    _EvidenceRule(
        label="resource-consuming loop",
        cwe_scores=(("CWE-1050", 110), ("CWE-400", 90)),
        tokens=("while (", "while(", "for (", "for("),
        required_token_groups=(
            (
                "stack.push(",
                ".append(",
                "open(",
                "allocate(",
                "malloc(",
                ".read(",
                ".write(",
            ),
        ),
    ),
    _EvidenceRule(
        label="TLS peer-certificate verification",
        cwe_scores=(("CWE-295", 125), ("CWE-319", 80)),
        tokens=(
            "verify_ssl",
            "verifyssl",
            "insecure_skip_verify",
            "insecureskipverify",
            "checkhostname",
            "check_hostname",
            "certificateverify",
        ),
    ),
    _EvidenceRule(
        label="message and allocation size limits",
        cwe_scores=(("CWE-400", 125), ("CWE-770", 115)),
        tokens=(
            "maxrecvmessagesize",
            "maxsendmessagesize",
            "max_message_size",
            "maxmessagesize",
            "maxpayloadsize",
            "max_payload_size",
            "maxbuffersize",
            "max_buffer_size",
            "io.limitreader(",
            "resourceexhausted",
        ),
    ),
    _EvidenceRule(
        label="authentication gate",
        cwe_scores=(("CWE-287", 125), ("CWE-306", 90)),
        tokens=(
            "@login_required",
            "flask_login.login_required",
            "authenticationmanager",
            "passport.authenticate(",
            "jwt.verify(",
            "jose.jwt.decode(",
        ),
    ),
)


def detect_cwe_evidence(
    lower_text: str,
    *,
    language: str,
) -> tuple[CweEvidenceMatch, ...]:
    """Return deterministic CWE evidence matches for one source file."""
    matches: list[CweEvidenceMatch] = []
    for rule in _EVIDENCE_RULES:
        if rule.languages and language not in rule.languages:
            continue
        if not any(token in lower_text for token in rule.tokens):
            continue
        if any(
            not any(token in lower_text for token in group) for group in rule.required_token_groups
        ):
            continue
        matches.extend(
            CweEvidenceMatch(cwe_id=cwe_id, label=rule.label, score=score)
            for cwe_id, score in rule.cwe_scores
        )
    return tuple(matches)
