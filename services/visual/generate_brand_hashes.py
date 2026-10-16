from playwright.sync_api import sync_playwright
import imagehash
from PIL import Image
import io

# Marcas conocidas relevantes para Chile + globales
KNOWN_BRANDS = {
    "paypal.com": "https://www.paypal.com",
    "google.com": "https://www.google.com",
    "facebook.com": "https://www.facebook.com",
    "santander.cl": "https://www.santander.cl",
    "bci.cl": "https://www.bci.cl",
    "falabella.com": "https://www.falabella.com",
    "mercadolibre.cl": "https://www.mercadolibre.cl",
    "bancoestado.cl": "https://www.bancoestado.cl",
    "microsoft.com": "https://www.microsoft.com",
    "amazon.com": "https://www.amazon.com",
}

def capture_and_hash(url: str) -> str:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        try:
            page.goto(url, timeout=15000, wait_until="domcontentloaded")
            page.wait_for_timeout(2000)
            screenshot = page.screenshot()
        finally:
            browser.close()
        img = Image.open(io.BytesIO(screenshot))
        h = imagehash.phash(img, hash_size=8)
        return str(h)

def main():
    results = []
    for domain, url in KNOWN_BRANDS.items():
        print(f"Capturando {domain}...")
        try:
            hash_str = capture_and_hash(url)
            results.append(f"{domain}|{hash_str}")
            print(f"  -> hash: {hash_str}")
        except Exception as e:
            print(f"  -> ERROR: {e}")

    with open("known_brand_hashes.txt", "w") as f:
        f.write("\n".join(results))

    print(f"\n{len(results)} hashes guardados en known_brand_hashes.txt")

if __name__ == "__main__":
    main()