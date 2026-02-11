#!/bin/bash

# Comprobar argumentos
if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Uso: $0 <domains_path> <apikey>"
  exit 1
fi

path="$1"
apikey="$2"

# Procesar cada dominio
while IFS= read -r domain; do
  ts=$(date +%Y%m%d)
  echo "[🔍] Consultando subdominios para: $domain"

  # Consulta a la API
  getsubdomains=$(curl -s --request GET \
    --url "https://subdomains.whoisxmlapi.com/api/v1?apiKey=$apikey&domainName=$domain")

  # Extraer subdominios
  if echo "$getsubdomains" | jq -e '.result.records' >/dev/null 2>&1; then
    echo "$getsubdomains" | jq -r '.result.records[].domain' > "${ts}_${domain}_subdomains.txt"
    echo "Subdominios guardados en: ${ts}_${domain}_subdomains.txt"
  else
    echo "Error al extraer subdominios de $domain"
    echo "$getsubdomains" > "${ts}_${domain}_error.json"
  fi

done < "$path"
