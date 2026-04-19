"""
phishing_classifier.py
Pezzi 1 + 2 + 3: Feature Extraction, Dataset, Training
(senza export ONNX — verrà aggiunto nel Pezzo 4)
"""

import re
import math
import pandas as pd
import numpy as np
from urllib.parse import urlparse, parse_qs


# ─────────────────────────────────────────────
# PEZZO 1 — FEATURE EXTRACTION
# ─────────────────────────────────────────────

# Parole che compaiono spesso negli URL phishing — inglese + italiano
PAROLE_ACCESSO = [
    # Inglese
    "login", "signin", "sign-in", "logon", "account", "auth",
    # Italiano
    "accedi", "accesso", "entra", "area-riservata", "area-personale",
]

PAROLE_BANCA = [
    # Inglese — brand internazionali
    "paypal", "bank", "credit", "wallet", "ebay", "amazon", "apple", "microsoft",
    # Italiano — banche e servizi italiani
    "intesa", "unicredit", "poste", "postepay", "bancoposta", "fineco",
    "mediolanum", "mps", "bper", "bnl", "credem", "ing", "widiba",
]

PAROLE_VERIFICA = [
    # Inglese
    "verify", "update", "confirm", "validate", "suspend", "restore", "unlock",
    # Italiano
    "verifica", "aggiorna", "conferma", "valida", "sospeso", "ripristina",
    "sblocca", "scaduto", "sicurezza", "attenzione",
]

PAROLE_TRUFFA = [
    # Italiano — truffe tipiche
    "premio", "vinto", "vincita", "gratis", "gratuito", "offerta",
    "congratulazioni", "selezionato", "urgente", "subito", "immediato",
    "riscatta", "coupon", "sconto", "cashback",
    # Inglese equivalenti
    "free", "winner", "won", "prize", "congratulations", "urgent", "claim",
]

TLD_SOSPETTI = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".pw", ".top", ".icu", ".click", ".link", ".online",
}

IP_REGEX = re.compile(r"(\d{1,3}\.){3}\d{1,3}")


def _entropia(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def estrai_feature(url: str) -> dict:
    parsed        = urlparse(url if "://" in url else "http://" + url)
    url_low       = url.lower()
    dominio       = parsed.netloc.lower().split(":")[0]
    parti         = dominio.split(".")
    path          = parsed.path.lower()
    tld           = "." + parti[-1] if parti else ""
    domain_no_tld = parti[-2] if len(parti) >= 2 else dominio

    return {
        # Lunghezze
        "lunghezza_url":              len(url),
        "lunghezza_dominio":          len(dominio),
        "lunghezza_path":             len(path),
        "n_sottodomini":              max(0, len(parti) - 2),
        # Caratteri sospetti
        "n_punti":                    url_low.count("."),
        "n_trattini":                 dominio.count("-"),
        "ha_chiocciola":              int("@" in url_low),
        "ha_doppio_slash":            int("//" in path),
        # Protocollo e host
        "usa_https":                  int(parsed.scheme == "https"),
        "ha_ip":                      int(bool(IP_REGEX.search(dominio))),
        "ha_porta":                   int(":" in parsed.netloc),
        # Parole chiave (inglese + italiano)
        "parola_accesso":             int(any(p in url_low for p in PAROLE_ACCESSO)),
        "parola_banca":               int(any(p in url_low for p in PAROLE_BANCA)),
        "parola_verifica":            int(any(p in url_low for p in PAROLE_VERIFICA)),
        "parola_truffa":              int(any(p in url_low for p in PAROLE_TRUFFA)),
        # Struttura URL
        "n_parametri_get":            len(parse_qs(parsed.query)),
        "profondita_path":            len([p for p in path.split("/") if p]),
        "tld_sospetto":               int(tld in TLD_SOSPETTI),
        # Entropia — alta = dominio generato casualmente (es. "xk3f9ab.xyz")
        "entropia_dominio":           round(_entropia(domain_no_tld), 4),
    }


NOMI_FEATURE = list(estrai_feature("http://example.com").keys())


# ─────────────────────────────────────────────
# PEZZO 2 — DATASET
# ─────────────────────────────────────────────

def carica_dataset(percorso: str = "dataset.csv") -> tuple:
    """
    Legge il CSV di Kaggle e restituisce (X, y, df):
      X  = array numpy delle feature  → input del modello
      y  = array numpy delle etichette 0/1  → output atteso
      df = DataFrame completo per debug
    """
    print(f"[dataset] Carico: {percorso}")
    df = pd.read_csv(percorso)
    print(f"[dataset] Righe: {len(df)} | Colonne: {list(df.columns)}")

    # Caso A: CSV con colonna 'url' + 'status' → estraiamo le feature noi
    if "url" in df.columns and "status" in df.columns:
        print("[dataset] Estraggo feature dagli URL...")
        righe = []
        for i, row in df.iterrows():
            f = estrai_feature(str(row["url"]))
            f["etichetta"] = 1 if str(row["status"]).lower() == "phishing" else 0
            righe.append(f)
            if (i + 1) % 2000 == 0:
                print(f"  ...{i + 1}/{len(df)}")
        df_proc = pd.DataFrame(righe)

    # Caso B: CSV con colonne numeriche già pronte
    else:
        print("[dataset] Uso feature pre-estratte dal CSV")
        colonna_label = "status" if "status" in df.columns else df.columns[-1]
        df["etichetta"] = (
            df[colonna_label]
            .map({"phishing": 1, "legitimate": 0})
            .fillna(df[colonna_label])
        )
        df_proc = df.copy()

    if all(c in df_proc.columns for c in NOMI_FEATURE):
        X = df_proc[NOMI_FEATURE].values.astype(np.float32)
    else:
        X = (
            df_proc
            .drop(columns=["etichetta"], errors="ignore")
            .select_dtypes(include=[np.number])
            .values.astype(np.float32)
        )

    y = df_proc["etichetta"].values.astype(int)

    print(f"[dataset] Legittimi: {(y == 0).sum()} | Phishing: {(y == 1).sum()}")
    return X, y, df_proc


# ─────────────────────────────────────────────
# PEZZO 3 — TRAINING
# ─────────────────────────────────────────────

def train(X, y):
    """
    Allena un RandomForest su X, y.
    Stampa i risultati sul test set e restituisce il modello.
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    modello = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        class_weight="balanced",
        random_state=42,
    )
    modello.fit(X_train, y_train)

    y_pred = modello.predict(X_test)

    print("\n[training] === Risultati sul test set ===")
    print(classification_report(y_test, y_pred, target_names=["legittimo", "phishing"]))
    print("[training] Confusion matrix (righe=reale, colonne=predetto):")
    print(confusion_matrix(y_test, y_pred))

    # Feature importance — quali feature contano di più
    print("\n[training] Feature più importanti:")
    importanza = sorted(
        zip(NOMI_FEATURE, modello.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    for nome, valore in importanza:
        barra = "█" * int(valore * 60)
        print(f"  {nome:<30} {valore:.4f}  {barra}")

    return modello


def classifica_url(url: str, modello) -> dict:
    """
    Classifica un URL usando il modello sklearn (senza ONNX per ora).
    Restituisce un dizionario con risultato e probabilità.
    """
    x      = np.array(list(estrai_feature(url).values()), dtype=np.float32).reshape(1, -1)
    label  = int(modello.predict(x)[0])
    probs  = modello.predict_proba(x)[0]  # [prob_legittimo, prob_phishing]

    return {
        "url":                  url,
        "risultato":            "PHISHING" if label == 1 else "LEGITTIMO",
        "prob_phishing":        round(float(probs[1]), 3),
        "prob_legittimo":       round(float(probs[0]), 3),
    }


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    # Uso: python phishing_classifier.py https://sito.com  → classifica URL
    # (richiede che il modello sia già stato allenato nella stessa sessione)
    #
    # Uso: python phishing_classifier.py           → allena con dataset.csv
    # Uso: python phishing_classifier.py file.csv  → allena con file custom

    csv = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].endswith(".csv") else "dataset_phishing.csv"

    X, y, _ = carica_dataset(csv)
    modello  = train(X, y)

    # Test su URL italiani e internazionali
    print("\n[test] Classificazione URL di esempio:")
    url_test = [
        # Legittimi
        ("https://www.google.it",                                    "legittimo"),
        ("https://www.bancaintesa.it/accesso-banca",                 "legittimo"),
        ("https://www.poste.it/prodotti/postepay.html",              "legittimo"),
        ("https://github.com/user/repo",                             "legittimo"),
        # Phishing
        ("http://postepay-verifica.xyz/accedi?token=abc",            "phishing"),
        ("http://intesa-sanpaolo.aggiorna-account.tk/conferma",      "phishing"),
        ("http://paypal-login.xyz/verify?token=abc",                 "phishing"),
        ("http://hai-vinto-un-premio.gratis/riscatta",               "phishing"),
        ("http://unicredit.sicurezza-urgente.top/accesso",           "phishing"),
        ("http://192.168.1.1/bancoposta/signin",                     "phishing"),
    ]

    for url, atteso in url_test:
        r     = classifica_url(url, modello)
        icona = "🔴" if r["risultato"] == "PHISHING" else "🟢"
        ok    = "✅" if r["risultato"] == atteso.upper() else "❌"
        print(f"  {ok} {icona} {r['risultato']:10}  phishing={r['prob_phishing']:.1%}  {url}")