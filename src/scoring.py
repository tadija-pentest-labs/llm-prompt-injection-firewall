"""
scoring.py
Pretvara sirovi skor iz detector.py u konkretnu odluku:
ALLOW / WARN / BLOCK
"""


# Pragovi odlučivanja
THRESHOLD_WARN  = 25   # Skor >= 25 → upozorenje, ali pusti
THRESHOLD_BLOCK = 50   # Skor >= 50 → blokiraj


def score_to_decision(scan_result: dict) -> dict:
    """
    Prima rezultat iz scan_message() i donosi odluku.

    Vraća rečnik sa:
    - decision: "ALLOW" / "WARN" / "BLOCK"
    - score: ukupan skor
    - reason: objašnjenje odluke
    - matches: lista uhvaćenih pattern-a
    """
    score   = scan_result.get("raw_score", 0)
    matches = scan_result.get("matches", [])
    flags   = scan_result.get("encoding_flags", [])

    # Odluka na osnovu skora
    if score >= THRESHOLD_BLOCK:
        decision = "BLOCK"
        reason   = f"Visok rizik (skor {score}): poruka blokirana pre slanja LLM-u."
    elif score >= THRESHOLD_WARN:
        decision = "WARN"
        reason   = f"Umeren rizik (skor {score}): poruka prosleđena uz upozorenje."
    else:
        decision = "ALLOW"
        reason   = f"Nizak rizik (skor {score}): poruka prosleđena normalno."

    # Kratki opis uhvaćenih pattern-a za log
    match_names = [m["name"] for m in matches]

    return {
        "decision"      : decision,
        "score"         : score,
        "reason"        : reason,
        "matches"       : match_names,
        "encoding_flags": flags
    }


def format_response(decision_result: dict) -> dict:
    """
    Formatira finalni odgovor koji proxy šalje nazad korisniku
    kada je poruka blokirana ili upozorena.
    """
    decision = decision_result["decision"]

    if decision == "BLOCK":
        return {
            "blocked"  : True,
            "decision" : "BLOCK",
            "message"  : "Poruka je blokirana: detektovan potencijalni prompt injection napad.",
            "score"    : decision_result["score"],
            "matches"  : decision_result["matches"],
            "tip"      : "Ako smatrate da je ovo greška, reformulišite poruku."
        }
    elif decision == "WARN":
        return {
            "blocked"  : False,
            "decision" : "WARN",
            "message"  : "Upozorenje: poruka sadrži sumnjive elemente ali je prosleđena.",
            "score"    : decision_result["score"],
            "matches"  : decision_result["matches"]
        }
    else:
        return {
            "blocked"  : False,
            "decision" : "ALLOW",
            "message"  : "OK",
            "score"    : decision_result["score"]
        }


# Brzo testiranje
if __name__ == "__main__":
    # Simuliramo 3 scenarija: ALLOW, WARN, BLOCK
    test_cases = [
        {
            "label"     : "Bezazlena poruka",
            "scan_result": {"raw_score": 0, "matches": [], "encoding_flags": []}
        },
        {
            "label"     : "Sumnjiva poruka",
            "scan_result": {"raw_score": 30, "matches": [{"name": "persona_override"}], "encoding_flags": []}
        },
        {
            "label"     : "Napad - blokiraj",
            "scan_result": {"raw_score": 145, "matches": [{"name": "instruction_override"}, {"name": "system_prompt_extraction"}], "encoding_flags": []}
        }
    ]

    for tc in test_cases:
        result   = score_to_decision(tc["scan_result"])
        response = format_response(result)
        print(f"\n{'='*50}")
        print(f"Test: {tc['label']}")
        print(f"Odluka : {result['decision']}")
        print(f"Skor   : {result['score']}")
        print(f"Razlog : {result['reason']}")
        print(f"Odgovor: {response['message']}")