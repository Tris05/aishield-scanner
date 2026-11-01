# AIShield evaluation protocol

`python -m aishield.benchmark` runs only AIShield's deterministic custom source-pattern rules against two seeded vulnerable patterns and a small benign fixture. It records true positives, false negatives and false positives for those labeled cases. It does **not** estimate performance on real-world repositories and does not measure Semgrep/Bandit/CVE/model/red-team coverage.

For an academic evaluation, expand this into a versioned, labeled corpus with language/framework strata, clean controls, CVE-grounded dependency fixtures, model serialization fixtures, RAG/agent attack scenarios, reviewer adjudication and repeatability tests. Report precision/recall with confidence intervals and separate static detections from confirmed dynamic exploit outcomes. Do not use only the scanner's own rules as the ground truth for claims of general security efficacy.
