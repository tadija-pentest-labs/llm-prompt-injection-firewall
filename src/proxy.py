"""
proxy.py
FastAPI server koji stoji između korisnika i LLM API-ja.
Svaka poruka prolazi kroz detektor i scoring pre nego što stigne do LLM-a.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import os
from dotenv import load_dotenv

from detector import scan_message
from scoring import score_to_decision, format_response

load_dotenv()

app = FastAPI(
    title="LLM Prompt Injection Firewall",
    description="Proxy koji detektuje i blokira prompt injection napade pre nego što stignu do LLM-a.",
    version="1.0.0"
)

# CORS - dozvoli pozive iz browsera tokom testiranja
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────
# MODELI PODATAKA
# ─────────────────────────────────────────

class MessageRequest(BaseModel):
    message: str
    user_id: str = "anonymous"


class FirewallResponse(BaseModel):
    blocked: bool
    decision: str
    message: str
    score: int
    matches: list = []
    llm_response: str = None


# ─────────────────────────────────────────
# LOG (u memoriji, za demo)
# ─────────────────────────────────────────

request_log = []


# ─────────────────────────────────────────
# RUTE
# ─────────────────────────────────────────

@app.get("/")
def root():
    return {
        "name"   : "LLM Prompt Injection Firewall",
        "status" : "running",
        "version": "1.0.0"
    }


@app.post("/analyze")
def analyze_message(request: MessageRequest):
    """
    Analizira poruku bez prosleđivanja LLM-u.
    Korisno za testiranje i debug.
    """
    scan_result     = scan_message(request.message)
    decision_result = score_to_decision(scan_result)
    response        = format_response(decision_result)

    # Dodaj u log
    request_log.append({
        "user_id" : request.user_id,
        "message" : request.message[:100],
        "decision": decision_result["decision"],
        "score"   : decision_result["score"],
        "matches" : decision_result["matches"]
    })

    return response


@app.post("/chat")
def chat(request: MessageRequest):
    """
    Glavna ruta: prima poruku, analizira je, i ako prođe
    prosleđuje je LLM-u (simulacija bez pravog API ključa).
    """
    # Korak 1: Analiziraj poruku
    scan_result     = scan_message(request.message)
    decision_result = score_to_decision(scan_result)
    response        = format_response(decision_result)

    # Korak 2: Ako je blokirano, vrati odmah bez pozivanja LLM-a
    if response["blocked"]:
        request_log.append({
            "user_id" : request.user_id,
            "message" : request.message[:100],
            "decision": "BLOCK",
            "score"   : decision_result["score"],
            "matches" : decision_result["matches"]
        })
        return response

    # Korak 3: Ako je ALLOW ili WARN, simuliraj LLM odgovor
    # (U produkciji ovde bi bio pravi API poziv ka OpenAI/Anthropic)
    llm_response = simulate_llm(request.message)

    request_log.append({
        "user_id"     : request.user_id,
        "message"     : request.message[:100],
        "decision"    : decision_result["decision"],
        "score"       : decision_result["score"],
        "matches"     : decision_result["matches"],
        "llm_response": llm_response[:100]
    })

    return {
        "blocked"     : False,
        "decision"    : decision_result["decision"],
        "message"     : decision_result["reason"],
        "score"       : decision_result["score"],
        "matches"     : decision_result["matches"],
        "llm_response": llm_response
    }


@app.get("/log")
def get_log():
    """
    Vraća listu svih zahteva – korisno za monitoring.
    """
    return {
        "total"   : len(request_log),
        "requests": request_log
    }


@app.get("/stats")
def get_stats():
    """
    Statistike: koliko zahteva je blokirano, upozoreno, propušteno.
    """
    if not request_log:
        return {"total": 0, "ALLOW": 0, "WARN": 0, "BLOCK": 0}

    stats = {"ALLOW": 0, "WARN": 0, "BLOCK": 0}
    for entry in request_log:
        decision = entry.get("decision", "ALLOW")
        stats[decision] = stats.get(decision, 0) + 1

    return {
        "total"      : len(request_log),
        "ALLOW"      : stats["ALLOW"],
        "WARN"       : stats["WARN"],
        "BLOCK"      : stats["BLOCK"],
        "block_rate" : f"{round(stats['BLOCK'] / len(request_log) * 100)}%"
    }


# ─────────────────────────────────────────
# SIMULACIJA LLM ODGOVORA (za demo)
# ─────────────────────────────────────────

def simulate_llm(message: str) -> str:
    """
    Simulira LLM odgovor za demo svrhe.
    U produkciji ovde bi bio pravi API poziv.
    """
    return f"[SIMULIRANI LLM ODGOVOR] Primio sam vašu poruku: '{message[:50]}...'"


# ─────────────────────────────────────────
# POKRETANJE SERVERA
# ─────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "proxy:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )