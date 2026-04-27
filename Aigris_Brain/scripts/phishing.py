"""
phishing.py
Aigris_brain/scripts/phishing.py

Struttura progetto:
    Aigris_brain/
    ├── dataset/
    │   └── phishing_site_urls.csv
    └── scripts/
        └── phishing.py  ← sei qui
"""

import re
import os
import math
import numpy as np
import pandas as pd
from urllib.parse import urlparse, parse_qs


# ─────────────────────────────────────────────────────────────────
# PERCORSO DATASET
# os.path.dirname(__file__)  → cartella dove si trova phishing.py  (scripts/)
# ..                         → cartella superiore                  (Aigris_brain/)
# dataset/phishing_site_urls.csv → percorso completo del dataset
# Così funziona da qualsiasi cartella tu lanci il terminale.
# ─────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "..", "dataset", "phishing_site_urls.csv")
MODEL_DIR    = os.path.join(BASE_DIR, "..", "models")
ONNX_PATH    = os.path.join(MODEL_DIR, "phishing_url.onnx")


# ─────────────────────────────────────────────────────────────────
# PEZZO 1 — FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────────

# Parole cercate SOLO nel dominio (non nel path)
# Questo evita falsi positivi tipo "bancaintesa.it/accesso"
PAROLE_ACCESSO = [
    "login", "signin", "sign-in", "logon", "auth",
    "accedi", "accesso", "entra", "area-riservata", "area-personale",
]
PAROLE_BANCA = [
    "paypal", "bank", "credit", "wallet", "ebay", "amazon", "apple", "microsoft",
    "intesa", "unicredit", "poste", "postepay", "bancoposta", "fineco",
    "mediolanum", "mps", "bper", "bnl", "credem", "ing", "widiba",
]
PAROLE_VERIFICA = [
    "verify", "update", "confirm", "validate", "suspend", "restore", "unlock",
    "verifica", "aggiorna", "conferma", "valida", "sospeso", "ripristina",
    "sblocca", "scaduto", "sicurezza",
]
PAROLE_TRUFFA = [
    "free", "winner", "won", "prize", "congratulations", "urgent", "claim",
    "premio", "vinto", "vincita", "gratis", "gratuito", "offerta",
    "congratulazioni", "selezionato", "urgente", "subito", "riscatta",
]

# Domini ufficiali delle banche italiane
# Usati per rilevare quando un brand viene imitato nel dominio
DOMINI_BANCHE_UFFICIALI = {
    "intesasanpaolo.com", "bancaintesa.it", "unicredit.it",
    "poste.it", "postepay.it", "fineco.it", "mps.it",
    "bnl.it", "credem.it", "ing.it", "widiba.it",
    "paypal.com", "amazon.it", "amazon.com",
}

TLD_SOSPETTI = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".pw", ".top", ".icu", ".click", ".link", ".online",
}

IP_REGEX = re.compile(r"(\d{1,3}\.){3}\d{1,3}")


def _entropia(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _rapporto_consonanti(s: str) -> float:
    if not s:
        return 0.0
    consonanti = sum(1 for c in s.lower() if c in "bcdfghjklmnpqrstvwxyz")
    return round(consonanti / len(s), 4)


def _brand_imitato(dominio: str) -> int:
    """
    Controlla se il dominio contiene il nome di una banca/brand noto
    MA non è il dominio ufficiale di quel brand.
    Esempio:
        "intesa-login.xyz"     → contiene "intesa", non è "intesasanpaolo.com" → 1
        "intesasanpaolo.com"   → è il dominio ufficiale → 0
    """
    if dominio in DOMINI_BANCHE_UFFICIALI:
        return 0
    for brand in PAROLE_BANCA:
        if brand in dominio:
            return 1
    return 0


def estrai_feature(url: str) -> dict:
    parsed        = urlparse(url if "://" in url else "http://" + url)
    url_low       = url.lower()
    netloc        = parsed.netloc.lower()
    dominio       = netloc.split(":")[0]
    parti         = dominio.split(".")
    path          = parsed.path.lower()
    tld           = "." + parti[-1] if parti else ""
    domain_no_tld = parti[-2] if len(parti) >= 2 else dominio

    return {
        # Lunghezze
        "lunghezza_url":                len(url),
        "lunghezza_dominio":            len(dominio),
        "lunghezza_path":               len(path),
        "n_sottodomini":                max(0, len(parti) - 2),

        # Caratteri sospetti
        "n_punti":                      url_low.count("."),
        "n_trattini_dominio":           dominio.count("-"),
        "n_cifre_dominio":              sum(c.isdigit() for c in dominio),
        "n_slash":                      url_low.count("/"),
        "ha_chiocciola":                int("@" in url_low),
        "ha_doppio_slash_path":         int("//" in path),

        # Protocollo e host
        "usa_https":                    int(parsed.scheme == "https"),
        "ha_ip":                        int(bool(IP_REGEX.search(dominio))),
        "ha_porta":                     int(":" in netloc),

        # Parole chiave — cercate SOLO nel dominio
        "parola_accesso_nel_dominio":   int(any(p in dominio for p in PAROLE_ACCESSO)),
        "parola_banca_nel_dominio":     int(any(p in dominio for p in PAROLE_BANCA)),
        "parola_verifica_nel_dominio":  int(any(p in dominio for p in PAROLE_VERIFICA)),
        "parola_truffa_nel_dominio":    int(any(p in dominio for p in PAROLE_TRUFFA)),

        # Rilevamento imitazione brand
        "brand_imitato":                _brand_imitato(dominio),

        # Struttura URL
        "n_parametri_get":              len(parse_qs(parsed.query)),
        "profondita_path":              len([p for p in path.split("/") if p]),
        "tld_sospetto":                 int(tld in TLD_SOSPETTI),

        # Entropia e pattern caratteri
        "entropia_dominio":             round(_entropia(domain_no_tld), 4),
        "rapporto_consonanti_dominio":  _rapporto_consonanti(domain_no_tld),
    }


NOMI_FEATURE = list(estrai_feature("http://example.com").keys())
N_FEATURE    = len(NOMI_FEATURE)


# ─────────────────────────────────────────────────────────────────
# PEZZO 2 — DATASET
# ─────────────────────────────────────────────────────────────────

def carica_dataset(percorso: str = DATASET_PATH) -> tuple:
    """
    Carica phishing_site_urls.csv e restituisce (X, y, df).
    Colonne attese: 'URL' e 'Label' (valori: 'good' / 'bad')
    """
    print(f"[dataset] Carico: {percorso}")
    df = pd.read_csv(percorso)
    print(f"[dataset] Righe: {len(df):,} | Colonne: {list(df.columns)}")

    # Verifica colonne
    if "URL" not in df.columns or "Label" not in df.columns:
        raise ValueError(
            f"Colonne attese: 'URL' e 'Label'. "
            f"Trovate: {list(df.columns)}"
        )

    # Converti etichette: good → 0, bad → 1
    df["etichetta"] = df["Label"].map({"good": 0, "bad": 1})

    n_sconosciuti = df["etichetta"].isna().sum()
    if n_sconosciuti > 0:
        print(f"[dataset] ⚠️  {n_sconosciuti} etichette non riconosciute, rimosse.")
        df = df.dropna(subset=["etichetta"])

    print(f"[dataset] Legittimi (good): {(df['etichetta'] == 0).sum():,}")
    print(f"[dataset] Phishing  (bad):  {(df['etichetta'] == 1).sum():,}")
    print("[dataset] Estraggo feature dagli URL (attendere)...")

    # Estrai feature da ogni URL
    righe = []
    totale = len(df)
    saltati = 0
    for i, row in df.iterrows():
        try:
            f = estrai_feature(str(row["URL"]))
            f["etichetta"] = int(row["etichetta"])
            righe.append(f)
        except ValueError:
            saltati += 1
            continue
        if (i + 1) % 50000 == 0:
            print(f"  ...{i + 1:,} / {totale:,}")

    if saltati > 0:
        print(f"[dataset] ⚠️  {saltati} URL non validi saltati (es. IPv6)")
    df_proc = pd.DataFrame(righe)

    X = df_proc[NOMI_FEATURE].values.astype(np.float32)
    y = df_proc["etichetta"].values.astype(int)

    print(f"[dataset] ✅ Dataset pronto — {X.shape[0]:,} righe, {X.shape[1]} feature")
    return X, y, df_proc


# ─────────────────────────────────────────────────────────────────
# PEZZO 3 — TRAINING
# ─────────────────────────────────────────────────────────────────

def train(X: np.ndarray, y: np.ndarray):
    """
    Allena un RandomForestClassifier e stampa i risultati.
    Restituisce il modello addestrato.
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix

    print("\n[training] Split train/test (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )
    print(f"[training] Train: {len(X_train):,} | Test: {len(X_test):,}")

    print("[training] Alleno il modello (attendere)...")
    modello = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,       # usa tutti i core del PC per velocizzare
    )
    modello.fit(X_train, y_train)

    # Risultati
    y_pred = modello.predict(X_test)
    print("\n[training] === Risultati sul test set ===")
    print(classification_report(y_test, y_pred, target_names=["legittimo", "phishing"]))
    print("[training] Confusion matrix (righe=reale, colonne=predetto):")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  Veri negativi  (legittimo corretto): {cm[0][0]:,}")
    print(f"  Falsi positivi (legittimo→phishing): {cm[0][1]:,}")
    print(f"  Falsi negativi (phishing→legittimo): {cm[1][0]:,}")
    print(f"  Veri positivi  (phishing corretto):  {cm[1][1]:,}")

    # Feature importance
    print("\n[training] Feature più importanti:")
    importanza = sorted(
        zip(NOMI_FEATURE, modello.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    for nome, valore in importanza:
        barra = "█" * int(valore * 80)
        print(f"  {nome:<35} {valore:.4f}  {barra}")

    return modello


# ─────────────────────────────────────────────────────────────────
# PEZZO 4 — EXPORT ONNX
# ─────────────────────────────────────────────────────────────────

def esporta_onnx(modello, percorso: str = ONNX_PATH) -> str:
    """
    Esporta il modello in formato ONNX.
    Il file prodotto verrà copiato nella cartella android/app/src/main/assets/
    """
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    os.makedirs(os.path.dirname(percorso), exist_ok=True)

    onnx_model = convert_sklearn(
        modello,
        initial_types=[("float_input", FloatTensorType([None, N_FEATURE]))],
        target_opset=17,
        options={type(modello): {"zipmap": False}},
    )

    with open(percorso, "wb") as f:
        f.write(onnx_model.SerializeToString())

    dimensione_kb = os.path.getsize(percorso) / 1024
    print(f"\n[onnx] ✅ Modello salvato: {percorso}")
    print(f"[onnx] Dimensione: {dimensione_kb:.1f} KB")
    print(f"[onnx] Feature attese in input: {N_FEATURE}")
    print(f"[onnx] Nomi feature: {NOMI_FEATURE}")
    print(f"\n[onnx] Copia questo file in:")
    print(f"       android/app/src/main/assets/phishing_url.onnx")
    return percorso


# ─────────────────────────────────────────────────────────────────
# CLASSIFICAZIONE SINGOLO URL (per testing)
# ─────────────────────────────────────────────────────────────────

def classifica_url(url: str, modello) -> dict:
    """
    Classifica un singolo URL usando il modello sklearn.
    Usata per testing — in produzione Android userà il file .onnx.
    """
    x     = np.array(list(estrai_feature(url).values()), dtype=np.float32).reshape(1, -1)
    label = int(modello.predict(x)[0])
    probs = modello.predict_proba(x)[0]

    return {
        "url":             url,
        "risultato":       "PHISHING" if label == 1 else "LEGITTIMO",
        "prob_phishing":   round(float(probs[1]), 3),
        "prob_legittimo":  round(float(probs[0]), 3),
    }


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    # ── Modalità 1: classifica URL singolo
    #    python phishing.py https://sito-da-testare.com
    if len(sys.argv) > 1 and not sys.argv[1].endswith(".csv"):
        if not os.path.exists(ONNX_PATH):
            print("❌ Modello non trovato. Prima esegui senza argomenti per allenarlo.")
            sys.exit(1)

        import onnxruntime as rt
        sess  = rt.InferenceSession(ONNX_PATH)
        x     = np.array(list(estrai_feature(sys.argv[1]).values()), dtype=np.float32).reshape(1, -1)
        label, probs = sess.run(
            [sess.get_outputs()[0].name, sess.get_outputs()[1].name],
            {sess.get_inputs()[0].name: x}
        )
        icona = "🔴" if int(label[0]) == 1 else "🟢"
        print(f"\n{icona} {'PHISHING' if int(label[0]) == 1 else 'LEGITTIMO'}")
        print(f"Probabilità phishing:  {float(probs[0][1]):.1%}")
        print(f"Probabilità legittimo: {float(probs[0][0]):.1%}")
        sys.exit(0)

    # ── Modalità 2: training completo
    #    python phishing.py
    print("=" * 60)
    print("AIGRIS — Modulo Phishing")
    print("=" * 60)

    X, y, _  = carica_dataset()
    modello  = train(X, y)
    esporta_onnx(modello)

    # ── Test finale su URL italiani e internazionali
    print("\n" + "=" * 60)
    print("[test] Classificazione URL di esempio")
    print("=" * 60)

    url_test = [
        # Legittimi
        ("https://www.google.it",                                   "legittimo"),
        ("https://www.bancaintesa.it/accesso-banca",                "legittimo"),
        ("https://www.poste.it/prodotti/postepay.html",             "legittimo"),
        ("https://github.com/user/repo",                            "legittimo"),
        ("https://www.unicredit.it/it/privati.html",                "legittimo"),
        # Phishing
        ("http://postepay-verifica.xyz/accedi?token=abc",           "phishing"),
        ("http://intesa-sanpaolo.aggiorna.tk/conferma",             "phishing"),
        ("http://paypal-login.xyz/verify?token=abc",                "phishing"),
        ("http://hai-vinto-un-premio.gratis/riscatta",              "phishing"),
        ("http://unicredit.sicurezza-urgente.top/accesso",          "phishing"),
        ("http://192.168.1.1/bancoposta/signin",                    "phishing"),
        ("http://amazon.com.account-update.tk/login",               "phishing"),
    ]

    corretti  = 0
    totale    = len(url_test)

    for url, atteso in url_test:
        r     = classifica_url(url, modello)
        ok    = r["risultato"].lower() == atteso
        icona = "🔴" if r["risultato"] == "PHISHING" else "🟢"
        check = "✅" if ok else "❌"
        if ok:
            corretti += 1
        print(
            f"  {check} {icona} {r['risultato']:10} "
            f"phishing={r['prob_phishing']:.1%}  "
            f"{url}"
        )

    print(f"\n[test] Risultato: {corretti}/{totale} corretti ({corretti/totale:.1%})")