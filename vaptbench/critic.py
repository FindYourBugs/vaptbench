"""Critic pass — a skeptical second opinion on each finding.

A reasoning model (set VAPT_MODEL_REASONER, e.g. deepseek-r1:14b) answers the
hard questions a senior tester would ask: Is this really exploitable here? Is
the severity right? Is there a false-positive risk? Is there a better / simpler
exploitation path? Is remediation actually needed, or is it a non-issue in
context?

ADVISORY ONLY. The critic never overturns deterministic proof and never invents
a vulnerability. Its output is attached to the finding as an "Analyst review"
note; at most it can RAISE a false-positive flag for a human to check. This
keeps vaptbench's anti-hallucination guarantee intact while adding judgment.
"""
from . import ai as ai_mod

_SYSTEM = (
    "You are a senior penetration tester doing QA on a junior's finding. Be "
    "skeptical and precise. You are given a finding that a deterministic "
    "verifier already produced from real HTTP evidence. Do NOT invent new "
    "vulnerabilities and do NOT claim the finding is proven beyond its evidence. "
    "Judge it: real impact in context, whether the severity fits, false-positive "
    "risk, a better or simpler exploitation path if one exists, and whether "
    "remediation is genuinely warranted. Ground every statement in the evidence "
    "shown; if something cannot be determined from the evidence, say so."
)


def review(finding, skill_body=""):
    """Return a critic review dict, or {} if the model is unavailable/unhelpful.

    finding: dict-like with title, vuln_class, severity, description, poc_request,
    poc_response.
    """
    if not ai_mod.available()[0]:
        return {}
    skill = ("\n\nMethodology reference (your own playbook):\n" + skill_body[:2500]) if skill_body else ""
    prompt = (
        f"FINDING\n"
        f"- title: {finding.get('title','')}\n"
        f"- class: {finding.get('vuln_class','')}\n"
        f"- severity: {finding.get('severity','')}\n"
        f"- description: {finding.get('description','')[:1500]}\n"
        f"- request: {finding.get('poc_request','')[:600]}\n"
        f"- evidence (response, truncated): {finding.get('poc_response','')[:1500]}\n"
        f"{skill}\n\n"
        "Answer as JSON with these fields:\n"
        '{"verdict":"real|likely_real|possible_false_positive",'
        '"false_positive_risk":"low|medium|high",'
        '"severity_assessment":"<agree, or propose + why>",'
        '"real_impact":"<1-2 sentences, evidence-grounded>",'
        '"better_path":"<a simpler/stronger exploitation path, or \'none\'>",'
        '"remediation_needed":"yes|no|context-dependent",'
        '"reasoning":"<2-4 sentences of your skeptical analysis>"}'
    )
    out = ai_mod.ask_json(prompt, system=_SYSTEM, role="reasoner")
    # keep only expected keys, coerce to str
    keys = ("verdict", "false_positive_risk", "severity_assessment", "real_impact",
            "better_path", "remediation_needed", "reasoning")
    review = {k: str(out.get(k, "")).strip() for k in keys if out.get(k)}
    return review


def format_note(review):
    """Render a review dict as a Markdown 'Analyst review' block for the report."""
    if not review:
        return ""
    fp = review.get("false_positive_risk", "")
    lines = ["--- Analyst review (AI critic, advisory) ---"]
    if review.get("verdict"):
        lines.append(f"Verdict: {review['verdict']}" + (f"  |  false-positive risk: {fp}" if fp else ""))
    if review.get("real_impact"):
        lines.append(f"Impact: {review['real_impact']}")
    if review.get("severity_assessment"):
        lines.append(f"Severity: {review['severity_assessment']}")
    bp = review.get("better_path", "")
    if bp and bp.lower() not in ("none", "n/a", ""):
        lines.append(f"Better path: {bp}")
    if review.get("remediation_needed"):
        lines.append(f"Remediation needed: {review['remediation_needed']}")
    if review.get("reasoning"):
        lines.append(f"Analysis: {review['reasoning']}")
    return "\n".join(lines)


def is_fp_suspect(review):
    return bool(review) and (
        review.get("verdict") == "possible_false_positive"
        or review.get("false_positive_risk") == "high")
