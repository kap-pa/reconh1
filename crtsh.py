import requests
import sys
import json
import time
import threading
import os

def spinner():
    while not spinner_done:
        for char in "-\\|/":
            print(f"\r{char}", end='', flush=True)
            time.sleep(0.1)

def main():

    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <dominio>")
        sys.exit(1)

    domain = sys.argv[1]
    crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"

    print(f"Escaneando dominio: {domain}...")

    global spinner_done
    spinner_done = False
    t = threading.Thread(target=spinner)
    t.start()

    try:
        response = requests.get(crt_url, timeout=30)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"\n[!] Error al obtener datos: {e}")
        spinner_done = True
        t.join()
        sys.exit(1)

    spinner_done = True
    t.join()

    subdomains = set()
    for entry in data:
        names = entry.get("name_value", "").split("\n")
        for name in names:
            subdomains.add(name.lstrip("*."))

    sorted_subdomains = sorted(subdomains)

    output_filename = f"{domain}_crt.txt"
    with open(output_filename, "w") as f:
        f.write("\n".join(sorted_subdomains))

    print(f"\rEscaneo completo. Resultados guardados en: {output_filename}")

if __name__ == "__main__":
    main()
