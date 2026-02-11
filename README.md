# Description
ReconOne is a Python script designed to automate subdomain enumeration from public programs on HackerOne or from a custom list of domains.

It integrates popular tools and APIs to maximize subdomain discovery:

- subfinder
- amass
- bbot
- crt.sh

APIs:
- SecurityTrails
- WhoisXMLAPI
- Shodan

# Usage

#### With a list of domains (no hackerone)
1. Create directory custom_results
2. Create txt file with wildcards with syntaxis *.example.com or *example.com in custom_results/clean_wildcards.txt
```
python3 recon_hackerone.py --securitytrails <REDACTED> --whoisxml <REDACTED> --shodan <REDACTED>
```

#### With a bugbounty program 
Get the name of the bugbounty program

<img width="522" height="83" alt="image" src="https://github.com/user-attachments/assets/160814d2-b333-4ee6-a7e6-4b2dbebe034f" />

```
python3 recon_hackerone.py -p <bugbounty_program_name> --securitytrails <REDACTED> --whoisxml <REDACTED> --shodan <REDACTED>
```

## TODO
- requirments.txt
- Modules
- Clear output and leave only subdomains.txt
