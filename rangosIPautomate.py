import requests
import csv

NETWORKSDB_APIKEY = "REDACTED"

class RangosIp:
    def __init__(self, org_search_url, org_networks_url, empresa):
        self.org_search_url = org_search_url # busqueda inicial de la empresa
        self.org_networks_url = org_networks_url # Buscar org_networks_url que es el id de la red
        self.empresa = empresa

    def networksDb(self):
        headers = {
            "X-Api-Key": NETWORKSDB_APIKEY,
            "Accept": "application/json"
        }

        params = {'search': self.empresa}
        r = requests.get(self.org_search_url, headers=headers, params=params)
        print(f"{r.text}")

        try:
            organisations = r.json()
        except ValueError:
            print("Respuesta no es JSON válido.")
            print(f"[DEBUG] Respuesta de organizaciones: {organisations}")

            return []

        all_networks_data = []

        for org in organisations.get('results', []):
            org_id = org.get('id')
            print(f"[INFO] Procesando organización ID: {org_id}")
            if not org_id:
                continue

            network_params = {'id': org_id}
            network_response = requests.post(self.org_networks_url, headers=headers, params=network_params)

            try:
                networks_data = network_response.json()
                print(f"[DEBUG] Red encontrada para {org_id}: {networks_data}")
            except ValueError:
                print("Respuesta de red no es JSON válido.")
                continue

            for network in networks_data.get('results', []):
                network_info = {
                    'cidr': network.get('cidr', ''),
                    'description': network.get('description', ''),
                    'country': network.get('country', ''),
                    'netname': network.get('netname', ''),
                    'organization': org.get('organisation', ''),
                    'organization_id': org_id
                }
                all_networks_data.append(network_info)
        print(f"[INFO] Total de redes encontradas: {len(all_networks_data)}")
        self.export_to_csv(all_networks_data, f"{self.empresa}_networks.csv")
        return all_networks_data

    def export_to_csv(self, data, filename):
        if not data:
            return
        fieldnames = ['organization', 'organization_id', 'cidr', 'country', 'description', 'netname']
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
            print(f"Datos exportados correctamente a {filename}")
        except IOError as e:
            print(f"Error al escribir el archivo CSV: {e}")

if __name__ == "__main__":
    org_networks_url = "https://networksdb.io/api/org-networks"
    org_search_url = "https://networksdb.io/api/org-search"
    empresa = "REDACTED"
    
    rango = RangosIp(org_search_url, org_networks_url, empresa)
    resultado = rango.networksDb()

    if resultado:
        print(f"Se encontraron {len(resultado)} redes para {empresa}")
