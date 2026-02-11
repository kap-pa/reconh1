#!/bin/bash

# Comprobar que se pasan los argumentos necesarios
if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Uso: $0 <domains_path> <apikey>"
  exit 1
fi

# Argumentos
path="$1"
apikey="$2"

# Procesar cada dominio en la lista
while IFS= read -r domain; do
  ts=$(date +%Y%m%d)
  echo "Consultando subdominios para: $domain"

  # Consultar API
  getsubdomains=$(curl -s --request GET \
    --url "https://api.securitytrails.com/v1/domain/$domain/subdomains" \
    --header "accept: application/json" \
    --header "APIKEY: $apikey")

  # Verificar si hubo error
  if echo "$getsubdomains" | jq -e '.subdomains' >/dev/null 2>&1; then
    echo "$getsubdomains" | jq -r ".subdomains[]" | while read sub; do
      echo "$sub.$domain"
    done > "${ts}_${domain}_subdomains.txt"
    echo "Subdominios guardados en: ${ts}_${domain}_subdomains.txt"
  else
    echo "Error al obtener subdominios para $domain"
    echo "$getsubdomains" > "${ts}_${domain}_error.json"
  fi

done < "$path"
