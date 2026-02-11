import time
import re
import os
import json
import shutil
import argparse
import subprocess

class Subfinder:

    def __init__(self, program_name, securitytrails_apikey, whoisxmlapi_apikey, shodan_apikey):
        self.subf_url = f"https://hackerone.com/{program_name}/policy_scopes"
        self.program_name = program_name
        self.folder_name = f"{program_name}_results"
        self.subdominios_generados_subfinder = False
        self.subdominios_generados = False
        self.securitytrails_apikey = securitytrails_apikey
        self.whoisxmlapi_apikey = whoisxmlapi_apikey
        self.shodan_key = shodan_apikey


    def anew_append(self, source_file, target_file):
        with open(source_file, "rb") as sf:
            subprocess.run(
               f"cat {source_file} | anew {target_file}",
               shell=True,
               check=True
        )
    
    def leerDominios(self):
        if not os.path.exists(self.folder_name):
            os.makedirs(self.folder_name)

        url = "https://hackerone.com/graphql"
        headers = {
            "Host": "hackerone.com",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
            "X-Product-Area": "h1_assets"
        }

        variables = {
            "handle": self.program_name,
            "assetTypes": ["WILDCARD"],
            "from": 0,
            "size": 100,
            "sort": {
                "field": "cvss_score",
                "direction": "DESC"
            },
            "product_area": "h1_assets",
            "product_feature": "policy_scopes"
        }

        query_string = """
            query PolicySearchStructuredScopesQuery(
                $handle: String!,
                $searchString: String,
                $eligibleForSubmission: Boolean,
                $eligibleForBounty: Boolean,
                $minSeverityScore: SeverityRatingEnum,
                $asmTagIds: [Int],
                $assetTypes: [StructuredScopeAssetTypeEnum!],
                $from: Int,
                $size: Int,
                $sort: SortInput
            ) {
                team(handle: $handle) {
                    structured_scopes_search(
                        search_string: $searchString,
                        eligible_for_submission: $eligibleForSubmission,
                        eligible_for_bounty: $eligibleForBounty,
                        min_severity_score: $minSeverityScore,
                        asm_tag_ids: $asmTagIds,
                        asset_types: $assetTypes,
                        from: $from,
                        size: $size,
                        sort: $sort
                    ) {
                        nodes {
                            ... on StructuredScopeDocument {
                                identifier
                            }
                        }
                    }
                }
            }
        """

        data = {
            "operationName": "PolicySearchStructuredScopesQuery",
            "variables": variables,
            "query": query_string
        }

        try:
            import requests
            response = requests.post(url, headers=headers, json=data)
            response.raise_for_status()
            json_data = response.json()

            nodes = json_data.get('data', {}).get('team', {}).get('structured_scopes_search', {}).get('nodes', [])
            with open(os.path.join(self.folder_name, "wildcards.txt"), "w") as output:
                for node in nodes:
                    identifier = node.get('identifier')
                    if identifier and ('.' in identifier or '*' in identifier):
                        output.write(identifier + "\n")

            print(f"[+] Se han guardado {len(nodes)} dominios/wildcards en wildcards.txt")

        except Exception as e:
            print(f"[!] Error al obtener los dominios: {e}")

    def generarSubdominios(self):
        regex = re.compile(r'^\*\.|^(\*)')
        wildcards_path = os.path.join(self.folder_name, "wildcards.txt")
        clean_path = os.path.join(self.folder_name, "clean_wildcards.txt")

        with open(clean_path, "w") as output:
            with open(wildcards_path, "r") as file:
                for domain in file:
                    if '.' not in domain or '*' not in domain:
                        continue
                    clean_domain = regex.sub('', domain.strip())
                    output.write(clean_domain + "\n")

        subprocess.run([
            "subfinder", "-all", "-dL", clean_path,
            "-o", os.path.join(self.folder_name, "subfinder_results.txt")
        ], check=True)
        self.subdominios_generados_subfinder = True 

        # bbot
        bbot_name = f"{self.program_name}_bbot"
        bbot_output_dir = os.path.join(self.folder_name)    
        subprocess.run([
            "bbot", "-t", clean_path,
            "-f", "subdomain-enum", "cloud-enum", "web-basic",
            "-m", "shodan_dns", "--yes",
            "-c", f"modules.shodan_dns.api_key={self.shodan_key}",
            "--output-dir", bbot_output_dir,
            "--name", bbot_name
        ], 
        check=True,)    
        # put subdomains.txt (from bbot) in main file subdomains.txt
        origen = os.path.join(bbot_output_dir, bbot_name, "subdomains.txt")
        destino = os.path.join(self.folder_name, "subdomains.txt")
        if os.path.exists(origen):
            shutil.move(origen, destino)

        # anew subfinder-bbot
        self.anew_append(os.path.join(self.folder_name, "subfinder_results.txt"),os.path.join(self.folder_name, "subdomains.txt"))  
        # amass
        subprocess.run([
            "amass", "enum", "-df", clean_path,
            "-o", os.path.join(self.folder_name, "amass_results.txt")
        ], check=True)
        self.anew_append(os.path.join(self.folder_name, "amass_results.txt"), os.path.join(self.folder_name, "subdomains.txt"))  
        # whoisxmlapi
        subprocess.run([
            "./whoisxmlapi.sh", clean_path, self.whoisxmlapi_apikey
        ], check=True)
        # Mover todos los *_subdomains.txt al folder principal
        for f in os.listdir("."):
            if f.endswith("_subdomains.txt"):
                shutil.move(f, os.path.join(self.folder_name, f))   
        # securitytrails
        subprocess.run([
            "./security_trails_api.sh", clean_path, self.securitytrails_apikey
        ], check=True)
        # Mover todos los *_subdomains.txt al folder principal
        for f in os.listdir("."):
            if f.endswith("_subdomains.txt"):
                shutil.move(f, os.path.join(self.folder_name, f))   
        # append securitytrails and whoisxmlapi results a subdomains.txt
        subprocess.run(
            f"cat {self.folder_name}/*_subdomains.txt > {self.folder_name}/st_wixa_results.txt",
            check=True,
            shell=True
        )   
        self.anew_append(os.path.join(self.folder_name, "st_wixa_results.txt"), os.path.join(self.folder_name, "subdomains.txt"))    
        #crt.sh script
        try:
            subprocess.run(
                f"for i in $(cat {clean_path}); do python3 crtsh.py $i; done",
                check=True,
                shell=True
            )
        except subprocess.CalledProcessError as e:
            print(f"[!] Error al ejecutar crtsh.py: {e}")

        crt_files = [f for f in os.listdir(".") if f.endswith("_crt.txt")]
        if crt_files:
            subprocess.run(
                f"cat {' '.join(crt_files)} > {self.folder_name}/crtsh_results.txt",
                check=True,
                shell=True
            )
            self.anew_append(os.path.join(self.folder_name, "crtsh_results.txt"), os.path.join(self.folder_name, "subdomains.txt"))
        else:
            print("[!] No se encontraron archivos *_crt.txt para concatenar.")

        self.anew_append(os.path.join(self.folder_name, "crtsh_results.txt"), os.path.join(self.folder_name, "subdomains.txt"))
        # HTTPX
        os.system("cat subdomains.txt | httpx -fr -sc -td -title -bp -silent -csv -t 3 -o subdominios_capillary.csv")        
        subprocess.run(
                f"cat {os.path.join(self.folder_name,"subdomains.txt")} | httpx -fr -sc -td -title -bp -silent -csv -t 3 -o httpx_results.csv",
                check=True,
                shell=True
            )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="ReconOne",
        description="Lanza subfinder, bbot, amass, crt.sh, securitytrails, whoisxmlapi y agrupa resultados"
    )
    parser.add_argument("-p", "--program", help='Nombre del programa en HackerOne (url)')
    parser.add_argument("--securitytrails", required=True, help='API key de SecurityTrails')
    parser.add_argument("--whoisxml", required=True, help='API key de WhoisXMLAPI')
    parser.add_argument("--shodan", required=True, help='API key de Shodan')

    args = parser.parse_args()

    if not args.program and not os.path.exists("custom_results/wildcards.txt"):
        print("Debes especificar un programa con -p o tener un archivo custom_results/wildcards.txt existente.")
        exit(1)

    subfinder = Subfinder(
        args.program if args.program else "custom",  # folder será "custom_results" si no hay programa
        args.securitytrails,
        args.whoisxml,
        args.shodan
    )

    if args.program:
        subfinder.leerDominios()

    subfinder.generarSubdominios()

