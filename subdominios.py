import requests
import csv
import socket
from datetime import datetime

shodan_key = "REDACTED"

class SubdomainFinder:
    def __init__(self, favicon_file, wildcards=None):
        self.favicon_file = favicon_file
        self.wildcards = wildcards if wildcards else []

    def resolve_dns(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return "N/A"
        except Exception:
            return "Error"

    def get_favicons(self):
        results = []
        favicon_hashes = []

        with open(self.favicon_file, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]

        for url in urls:
            try:
                # Obtener hash del favicon
                r = requests.get(f'https://favicon-hash.kmsec.uk/api/?url={url}', timeout=10)
                response_favicon_json = r.json()
                favicon_hash = response_favicon_json.get('favicon_hash')
                if not favicon_hash:
                    print(f"[!] No se pudo obtener el hash para {url}")
                    continue

                # Buscar en Shodan
                
                r2 = requests.get(
                    f'https://api.shodan.io/shodan/host/search?key={shodan_key}&query=http.favicon.hash:{favicon_hash}',
                    timeout=15
                )
                response_shodan = r2.json()

                # Procesar resultados
                for match in response_shodan.get('matches', []):
                    ip = match.get('ip_str')
                    if ip:
                        dominio = self.resolve_dns(ip)  # Resolución DNS
                        result_data = {
                            'ip': ip,
                            'dominio': dominio,
                            'favicon_url': url,
                            'hash': favicon_hash,
                            'port': match.get('port', ''),
                            'org': match.get('org', '')
                        }
                        if result_data not in results:
                            results.append(result_data)
                            print(f"[+] {ip} | {dominio} | {url}")

            except requests.exceptions.RequestException as e:
                print(f"[!] Error de conexión con {url}: {str(e)}")
            except Exception as e:
                print(f"[!] Error inesperado con {url}: {str(e)}")

        # Exportar a CSV
        if results:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"shodan_favicon_results_{timestamp}.csv"
            self.export_to_csv(results, filename)
        else:
            print("\n[-] No se encontraron resultados para exportar")

        return results

    def export_to_csv(self, data, filename):
        if not data:
            print("[!] No hay datos para exportar")
            return

        fieldnames = data[0].keys()

        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
            print(f"\n[+] Datos exportados correctamente a {filename}")
        except IOError as e:
            print(f"[!] Error al escribir el archivo CSV: {str(e)}")
        except Exception as e:
            print(f"[!] Error inesperado al exportar: {str(e)}")

if __name__ == "__main__":
    finder = SubdomainFinder("favicon_list.txt")
    finder.get_favicons()