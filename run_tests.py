"""
Test Runner: Executes the prompt library against the detector and produces
a professional, business-readable Markdown report — the kind you'd hand to
an engineering team or include in a portfolio.

Usage:
    python3 run_tests.py
"""

import json
from datetime import datetime
from detector import PromptInjectionDetector


def load_library(path="tests/prompt_library.json"):
    with open(path, "r") as f:
        return json.load(f)


def run():
    detector = PromptInjectionDetector()
    library = load_library()

    all_results = []
    category_stats = {}

    for category in library["categories"]:
        cat_name = f"{category['id']} - {category['name']}"
        category_stats[cat_name] = {"total": 0, "detected": 0}

        for prompt in category["prompts"]:
            result = detector.analyze(prompt)
            all_results.append({
                "test_category": cat_name,
                "description": category["description"],
                **result.to_dict(),
            })
            category_stats[cat_name]["total"] += 1
            if result.is_suspicious:
                category_stats[cat_name]["detected"] += 1

    total_prompts = len(all_results)
    total_detected = sum(1 for r in all_results if r["is_suspicious"])
    detection_rate = round((total_detected / total_prompts) * 100, 1) if total_prompts else 0

    generate_markdown_report(all_results, category_stats, total_prompts, total_detected, detection_rate)
    generate_json_report(all_results, category_stats, total_prompts, total_detected, detection_rate)

    print(f"Ran {total_prompts} adversarial prompts through the detector.")
    print(f"Detected: {total_detected}/{total_prompts} ({detection_rate}%)")
    print("Reports written to reports/detection_report.md and reports/detection_report.json")


def generate_markdown_report(results, category_stats, total, detected, rate):
    lines = []
    lines.append("# LLM Prompt Injection - Detection Test Report\n")
    lines.append(f"**Run date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ")
    lines.append(f"**Total adversarial prompts tested:** {total}  ")
    lines.append(f"**Flagged as suspicious:** {detected} ({rate}%)  ")
    lines.append(f"**Framework reference:** OWASP Top 10 for LLM Applications\n")

    lines.append("## Executive Summary\n")
    lines.append(
        "This report evaluates a heuristic prompt-injection detector against a "
        "curated library of adversarial prompts spanning direct injection, "
        "indirect injection, jailbreak role-play, sensitive data extraction, "
        "excessive-agency requests, and basic obfuscation techniques. Results "
        "are broken down by category so gaps in coverage are visible at a glance.\n"
    )

    lines.append("## Results by Category\n")
    lines.append("| Category | Detected | Total | Detection Rate |")
    lines.append("|---|---|---|---|")
    for cat, stats in category_stats.items():
        cat_rate = round((stats["detected"] / stats["total"]) * 100, 1) if stats["total"] else 0
        lines.append(f"| {cat} | {stats['detected']} | {stats['total']} | {cat_rate}% |")
    lines.append("")

    lines.append("## Missed Detections (Highest Priority to Review)\n")
    missed = [r for r in results if not r["is_suspicious"]]
    if not missed:
        lines.append("None — all test prompts were flagged.\n")
    else:
        for r in missed:
            lines.append(f"- **[{r['test_category']}]** `{r['prompt'][:80]}...`" if len(r['prompt']) > 80
                          else f"- **[{r['test_category']}]** `{r['prompt']}`")
        lines.append("")

    lines.append("## Sample Detailed Findings\n")
    for r in results[:5]:
        lines.append(f"### Prompt: `{r['prompt'][:70]}{'...' if len(r['prompt']) > 70 else ''}`")
        lines.append(f"- **Category:** {r['test_category']}")
        lines.append(f"- **Flagged:** {'Yes' if r['is_suspicious'] else 'No'}")
        lines.append(f"- **Risk score:** {r['risk_score']}/10")
        lines.append(f"- **Matched rules:** {', '.join(r['matched_rules']) if r['matched_rules'] else 'None'}")
        lines.append(f"- **OWASP mapping:** {r['owasp_category']}\n")

    lines.append("## Recommendations\n")
    lines.append(
        "1. **Defense in depth:** Keyword-based detection alone is insufficient against "
        "paraphrased or novel attacks — pair with output validation and least-privilege "
        "tool access for any agent that can take real-world actions.\n"
        "2. **Continuous red-teaming:** Expand the prompt library regularly as new jailbreak "
        "techniques are published (e.g., via OWASP's LLM Top 10 updates).\n"
        "3. **Log and alert:** Route flagged prompts to a monitoring pipeline rather than "
        "silently blocking them, to catch emerging attack patterns.\n"
    )

    with open("reports/detection_report.md", "w") as f:
        f.write("\n".join(lines))


def generate_json_report(results, category_stats, total, detected, rate):
    report = {
        "run_date": datetime.now().isoformat(),
        "total_prompts": total,
        "total_detected": detected,
        "detection_rate_pct": rate,
        "category_stats": category_stats,
        "results": results,
    }
    with open("reports/detection_report.json", "w") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    run()
