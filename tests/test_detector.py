"""
test_detector.py
Pokreće sve 50 payload-a iz test-suite-a kroz detektor i ispisuje rezultate.
Pokazuje koliko napada detektor hvata, a koliko propušta.
"""

import json
import sys
import os

# Dodaj src folder u Python putanju da možemo da importujemo detector
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from detector import scan_message


def run_tests():
    # Učitaj sve payload-e iz JSON fajla
    payloads_path = os.path.join(os.path.dirname(__file__), '..', 'payloads', 'injection_payloads.json')
    
    with open(payloads_path, 'r') as f:
        payloads = json.load(f)

    print("=" * 60)
    print(f"POKRETANJE TESTA: {len(payloads)} payload-a")
    print("=" * 60)

    detected = 0
    missed = 0
    missed_list = []

    for payload in payloads:
        result = scan_message(payload['payload'])
        
        if result['is_suspicious']:
            detected += 1
            status = "✅ UHVACEN"
        else:
            missed += 1
            missed_list.append(payload)
            status = "❌ PROPUSTEN"

        print(f"{status} | {payload['id']} | Skor: {result['raw_score']} | {payload['technique']}")

    print("=" * 60)
    print(f"UKUPNO: {len(payloads)} payload-a")
    print(f"✅ Uhvaceno: {detected} ({round(detected/len(payloads)*100)}%)")
    print(f"❌ Propusteno: {missed} ({round(missed/len(payloads)*100)}%)")
    print("=" * 60)

    if missed_list:
        print("\nPROPUSTENI NAPADI (ove treba popraviti u detector.py):")
        for p in missed_list:
            print(f"  - [{p['id']}] {p['technique']}: {p['payload'][:60]}...")

    return detected, missed


if __name__ == "__main__":
    run_tests()