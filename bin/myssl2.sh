#!/usr/bin/env bash

# {{MYSSL_TEMPLATES}}
#
# # {{CONFBLOCK}}
#   MYSSL_BASE_DIR="{{base-dir}}"
#   MYSSL_CERTS_DIR="{{certs-dir}}"
#   MYSSL_CA_DIR="{{ca-dir}}"
#
#   declare -A MYSSL_CONF=(
#     # Output file prefix (without extension)
#     [out-prefix]="{{out-prefix}}"
#     # Encrypt private key
#     [encrypt]={{encrypt}}
#     # Can be more than 365 for CA. For servers 365 or below
#     [days]={{days}}
#     [cn]="{{cn}}"
#     # Issuer cert path. Leave blank for self-signed
#     [issuer-cert]="{{issuer-cert}}"
#     # Issuer key path. Ignored with no issuer-cert. When
#     # blank, issuer-cert file will be used
#     [issuer-key]="{{issuer-key}}"
#     # Domains and IPs for SAN. One per line, empty lines are
#     # ignored. Leave blank for CA certificate generation
#     [hosts]="{{hosts}}"
#     # Merge key and cert into a single *.pem file
#     [merge]={{merge}}
#     #
#     # EXTRA DISTINGUISHED NAME
#     #
#     # ISO 3166-1 country code. Example: US
#     [country]="{{country}}"
#     # State or Province name. Example: New York
#     [state]="{{state}}"
#     # Locality name. Example: New York
#     [locality]="{{locality}}"
#     # Organization name. Example: Second hand vacuum cleaner corp
#     [org]="{{org}}"
#     # Organization unit name. Example: marketing
#     [org-unit]="{{org-unit}}"
#     # Spam destination
#     [email]="{{email}}"
#   )
# # {{/CONFBLOCK}}
#
# {{/MYSSL_TEMPLATES}}
