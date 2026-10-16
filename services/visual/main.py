from fastapi import FastAPI
from pydantic import BaseModel
import imagehash
import os

app = FastAPI()

class HashRequest(BaseModel):
    hash: str
    domain: str

class URLRequest(BaseModel):
    url: str

KNOWN_HASHES_FILE = "known_brand_hashes.txt"

def load_known_hashes():
    hashes = {}
    if not os.path.exists(KNOWN_HASHES_FILE):
        print(f"ADVERTENCIA: {KNOWN_HASHES_FILE} no encontrado")
        return hashes
    with open(KNOWN_HASHES_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or "|" not in line:
                continue
            domain, hash_str = line.split("|", 1)
            hashes[domain] = hash_str
    print(f"Cargados {len(hashes)} hashes de marcas conocidas")
    return hashes

known_hashes = load_known_hashes()

@app.post("/analyze-hash")
def analyze_hash(req: HashRequest):
    """Recibe hash ya calculado desde el navegador"""
    if not known_hashes:
        return {"score": 0.5, "reasons": ["Base de hashes no disponible"]}

    try:
        page_hash = imagehash.hex_to_hash(req.hash)
    except Exception as e:
        return {"score": 0.5, "reasons": [f"Hash inválido: {str(e)}"]}

    domain = req.domain.replace("www.", "")
    min_distance = 64
    closest_brand = None

    for brand_domain, brand_hash_str in known_hashes.items():
        brand_hash = imagehash.hex_to_hash(brand_hash_str)
        distance = int(page_hash - brand_hash)
        if distance < min_distance:
            min_distance = distance
            closest_brand = brand_domain

    if closest_brand and min_distance <= 8 and closest_brand != domain:
        reasons = [f"Visualmente similar a {closest_brand} (distancia: {min_distance}/64)"]
        score = max(0.0, round(min_distance / 20, 3))
        return {"score": score, "reasons": reasons}

    if closest_brand == domain:
        return {"score": 1.0, "reasons": []}

    return {"score": 0.8, "reasons": []}

@app.post("/analyze")
def analyze(req: URLRequest):
    """Mantener compatibilidad — devuelve neutro sin Playwright"""
    return {"score": 0.8, "reasons": ["Análisis visual vía navegador"]}