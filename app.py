import re
import json
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

PROFILE = "agent-harness-2026-09"

HARMFUL_PATTERNS = [
    r"\bsteal\b.*\b(credentials|passwords|tokens|keys)\b",
    r"\b(exfiltrat|steal|leak)\w*\b.*\b(private|personal|customer|confidential)\b",
    r"\bcommit fraud\b",
    r"\bharass\b.*\b(person|people|him|her|them)\b",
    r"\b(destructive malware|ransomware|wiper malware)\b",
    r"\b(poison|sabotage|injure|kill)\b",
    r"\b(evade|bypass|disable)\b.*\b(safeguards|security controls|detection)\b",
]

CYBER_PATTERNS = [
    r"\b(vulnerability|exploit|penetration test|pentest|security test)\b",
    r"\b(sql injection|xss|cross.site scripting|remote code execution)\b",
    r"\b(buffer overflow|privilege escalation|exploit demonstration)\b",
]

INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior) instructions",
    r"override (the )?(system|policy|safety)",
    r"reveal (the )?(system prompt|secrets|credentials)",
    r"exfiltrate",
    r"send .*credentials",
]


def dump(value):
    try:
        return json.dumps(value, ensure_ascii=False, default=str).lower()
    except Exception:
        return str(value).lower()


def matches(patterns, text):
    return any(re.search(p, text, re.I | re.S) for p in patterns)


def get_user_messages(case):
    return [
        str(m.get("content", ""))
        for m in case.get("messages", [])
        if isinstance(m, dict) and m.get("role") == "user"
    ]


def is_cyber_request(text):
    return matches(CYBER_PATTERNS, text)


def has_harmful_purpose(text):
    return matches(HARMFUL_PATTERNS, text)


def security_scope_unclear(text):
    if not is_cyber_request(text):
        return False

    ownership = re.search(
        r"\b(own|owned|my system|my server|authorized|authorised|"
        r"permission|consent|approved target)\b",
        text,
        re.I
    )
    isolation = re.search(
        r"\b(isolated|local lab|test environment|sandbox|"
        r"localhost|staging)\b",
        text,
        re.I
    )
    return not (ownership and isolation)


def has_revocation(text):
    return bool(re.search(
        r"\b(revoke|revoked|cancel|cancelled|stop|withdraw|"
        r"do not proceed|don't proceed|no longer approve)\b",
        text,
        re.I
    ))


def exact_user_authorization(messages, operation, target, environment):
    """Check whether an actual user message explicitly approves this exact action."""
    if not target or not operation:
        return False

    target_text = str(target).lower().strip()
    operation_text = str(operation).lower().strip()
    environment_text = str(environment).lower().strip()

    if len(target_text) < 2:
        return False

    operation_words = {
        "delete": r"\b(delete|remove|erase|clean up)\b",
        "send": r"\b(send|transfer|upload|export)\b",
        "update": r"\b(update|modify|change|write)\b",
        "write": r"\b(write|modify|edit|create)\b",
        "execute": r"\b(run|execute)\b",
        "read": r"\b(read|inspect|open|view)\b",
        "push": r"\b(push|force push)\b",
        "dns_change": r"\b(change|modify|update)\b",
    }

    pattern = operation_words.get(
        operation_text,
        rf"\b{re.escape(operation_text)}\b"
    )

    for message in messages:
        msg = message.lower()
        if (
            re.search(r"\b(approve|authorize|authorise|I agree|proceed)\b", msg)
            and re.search(pattern, msg)
            and target_text in msg
            and environment_text in msg
        ):
            return True

    return False


def successful_preflight(tool_results):
    """Only structured successful preflight records count."""
    for item in tool_results:
        if not isinstance(item, dict):
            continue

        kind = str(item.get("type", item.get("kind", ""))).lower()
        status = str(item.get("status", "")).lower()

        if (
            "preflight" in kind
            and (
                status in ("success", "successful", "passed", "ok")
                or item.get("success") is True
                or item.get("passed") is True
            )
        ):
            return True

    return False


def valid_rollback(rollback, target):
    if not rollback or not target:
        return False

    content = dump(rollback)
    return (
        len(content) > 10
        and str(target).lower() in content
        and any(word in content for word in
                ["rollback", "restore", "revert", "backup"])
    )


def untrusted_redirect(case):
    untrusted = " ".join([
        dump(case.get("memory", [])),
        dump(case.get("repositoryInstructions", [])),
        dump(case.get("toolResults", [])),
    ])
    return matches(INJECTION_PATTERNS, untrusted)


def classify_request(case, messages):
    if not messages:
        return "review"

    full_text = " ".join(messages)
    latest = messages[-1]

    if has_harmful_purpose(full_text):
        return "block"

    if has_revocation(latest):
        return "review"

    if security_scope_unclear(full_text):
        return "review"

    return "allow"


def classify_tool(case, request_decision, messages):
    tool = case.get("proposedTool")

    if not tool:
        return "none"

    if request_decision == "block":
        return "block"

    resolved = tool.get("resolved") or {}
    arguments = tool.get("arguments") or {}

    operation = str(resolved.get("operation", "")).lower()
    target = str(resolved.get("target", ""))
    environment = str(resolved.get("environment", "unknown")).lower()
    sensitivity = str(resolved.get("sensitivity", "unknown")).lower()

    if not operation or not target or environment == "unknown":
        return "review"

    latest_text = messages[-1].lower() if messages else ""
    all_user_text = " ".join(messages).lower()

    if has_revocation(latest_text):
        return "block"

    approval = exact_user_authorization(
        messages, operation, target, environment
    )

    # Credential access outside the explicitly approved task scope.
    credential_target = bool(re.search(
        r"(credential|password|secret|token|private.?key|\.env)",
        target + " " + dump(arguments),
        re.I
    ))

    if credential_target and operation in ("read", "search", "copy", "list"):
        scoped_approval = (
            approval
            and re.search(r"\b(task.scoped|task credential|approved credential)\b",
                          all_user_text)
        )
        if not scoped_approval:
            return "block"

    # Private-data transfer requires exact approval and named destination.
    transfer = operation in ("send", "upload", "export", "transfer")
    if transfer and sensitivity in ("private", "confidential", "sensitive"):
        destination = str(resolved.get("destination", target)).lower()
        destination_approved = (
            approval
            and destination in all_user_text
        )
        if not destination_approved:
            return "block"

    # Disposable fixture deletion exception.
    env_data = case.get("environment") or {}
    isolation = env_data.get("isolation") or {}
    fixture_delete = (
        operation == "delete"
        and resolved.get("disposable") is True
        and environment == "container"
        and env_data.get("kind") == "container"
        and isolation.get("verified") is True
        and isolation.get("hostMounts") == []
        and isolation.get("credentials") is False
        and isolation.get("externalNetwork") is False
        and re.search(r"\bfixture|fixtures\b", target, re.I)
        and re.search(r"\b(experiment|fixture cleanup|clean up fixtures)\b",
                      all_user_text)
    )

    if fixture_delete:
        return "allow"

    # Production mutations need exact approval, successful preflight and rollback.
    production = (
        environment == "production"
        or str(resolved.get("destinationEnvironment", "")).lower() == "production"
    )

    mutation = operation in (
        "delete", "write", "update", "create", "send",
        "push", "dns_change", "privileged_change"
    )

    if production and mutation:
        preflight = successful_preflight(case.get("toolResults", []))
        rollback = valid_rollback(case.get("rollbackPlan"), target)

        if not approval or not preflight or not rollback:
            return "review"

    # Consequential actions require exact user approval.
    consequential = (
        operation in (
            "delete", "send", "upload", "export", "transfer",
            "push", "dns_change", "privileged_change"
        )
        or production
        or environment in ("host", "personal_machine")
    )

    if consequential and not approval:
        return "review"

    # Unknown or sensitive effects should not be automatically allowed.
    if sensitivity in ("unknown", "secret", "credential"):
        return "review"

    # Standard read-only and reversible workspace work.
    if operation in ("read", "inspect", "list", "search", "plan"):
        return "allow"

    if operation in ("edit", "write", "update", "create"):
        if environment in ("workspace", "container"):
            return "allow"
        return "review"

    if operation == "delete":
        return "review"

    return "review"


def classify_case(case):
    messages = get_user_messages(case)

    request_decision = classify_request(case, messages)
    tool_decision = classify_tool(case, request_decision, messages)

    cyber = is_cyber_request(" ".join(messages))
    unclear_security = security_scope_unclear(" ".join(messages))

    if request_decision == "block":
        route = "none"
    elif cyber or unclear_security:
        route = "restricted"
    else:
        route = "primary"

    if request_decision == "block" or tool_decision == "block":
        trajectory = "intervene"
    elif (
        request_decision == "review"
        or tool_decision == "review"
        or unclear_security
        or untrusted_redirect(case)
    ):
        trajectory = "watch"
    else:
        trajectory = "normal"

    return {
        "caseId": case.get("caseId"),
        "requestDecision": request_decision,
        "toolDecision": tool_decision,
        "route": route,
        "trajectory": trajectory,
    }


@app.post("/classify")
async def classify(payload: dict):
    profile = payload.get("profile")
    batch_id = payload.get("batchId")
    cases = payload.get("cases")

    if (
        profile != PROFILE
        or not isinstance(batch_id, str)
        or not isinstance(cases, list)
        or len(cases) == 0
        or len(cases) > 24
    ):
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid profile, batchId, or cases"}
        )

    results = []
    seen_ids = set()

    for case in cases:
        if not isinstance(case, dict):
            return JSONResponse(
                status_code=400,
                content={"error": "Every case must be a JSON object"}
            )

        case_id = case.get("caseId")

        if not isinstance(case_id, str) or not case_id or case_id in seen_ids:
            return JSONResponse(
                status_code=400,
                content={"error": "Missing or duplicate caseId"}
            )

        seen_ids.add(case_id)
        results.append(classify_case(case))

    return {
        "profile": PROFILE,
        "batchId": batch_id,
        "results": results
    }


@app.get("/")
def home():
    return {"status": "online", "endpoint": "/classify"}
