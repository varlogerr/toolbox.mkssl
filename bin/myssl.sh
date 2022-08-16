#!/usr/bin/env bash

# Path rules by example:
# "./certs/localhost"  - relative to $(pwd)
# "!./certs/localhost" - relative to the current conf file
declare -A CONF=(
  [is-tpl]='DELETE THIS KEY'
  [out-prefix]="!./certs/localhost"
  # Encrypt private key. Will prompt for pass or use
  # `--passfile PASSFILE` option
  [encrypt]=false
  [days]=365
  [cn]=localhost
  # Issuer cert path (see path rules above). Leave blank
  # for self-signed
  [issuer-cert]=
  # Issuer key path. Ignored with no issuer-cert. When
  # blank, issuer-cert file will be used
  [issuer-key]=
  # Domains and IPs for SAN, one per line. Leave
  # blank for CA certificate generation
  [domains]="
    localhost
  "
  # Merge key into cert file
  [merge]=false
)

declare -a ERRBAG=()

declare -a OPTS_HELP
_opts_help() {
  unset _opts_help

  local is_help=false
  local -a sections

  while :; do
    [[ -n "${1+x}" ]] || break

    case "${1}" in
      -h|-\?|--help ) is_help=true ;;
      description   ) sections+=("${1}") ;;
      usage|opts    ) sections+=("${1}") ;;
      env|demo      ) sections+=("${1}") ;;
      *             ) ERRBAG+=("${1}") ;;
    esac

    shift
  done

  OPTS_HELP+=("${is_help}")
  [[ ${#sections[@]} -gt 0 ]] \
    && OPTS_HELP+=("${sections[@]}") \
    || OPTS_HELP+=(help)

  # if help detected return 0 to reset input args
  ${is_help} && return 0

  ERRBAG=()
  return 1
}; _opts_help "${@}" && set --

# OPTS_CONFGEN=(IS_CONFGEN FORCE DEST...)
declare -a OPTS_CONFGEN
_opts_confgen() {
  unset _opts_confgen

  local endopts=false
  local is_confgen=false
  local force=false
  local -a dests

  local key
  while :; do
    [[ -n "${1+x}" ]] || break
    ${endopts} && key='*' || key="${1}"

    case "${key}" in
      --          ) endopts=true ;;
      --confgen   ) is_confgen=true ;;
      -f|--force  ) force=true ;;
      -*          ) ERRBAG+=("${1}") ;;
      *           ) dests+=("${1}") ;;
    esac

    shift
  done

  OPTS_CONFGEN+=("${is_confgen}" "${force}")
  [[ ${#dests} -gt 0 ]] && OPTS_CONFGEN+=("${dests[@]}")

  # if confgen detected return 0 to reset input args
  ${is_confgen} && return 0

  ERRBAG=()
  return 1
}; _opts_confgen "${@}" && set --

declare PASSFILE
declare CA_PASSFILE
declare FORCE=false
_opts_main() {
  unset _opts_main
  while :; do
    [[ -n "${1+x}" ]] || break

    case "${1}" in
      --passfile    ) shift; [[ -n "${1+x}" ]] && PASSFILE="${1}" ;;
      --ca-passfile ) shift; [[ -n "${1+x}" ]] && CA_PASSFILE="${1}" ;;
      -f|--force    ) FORCE=true ;;
      *             ) ERRBAG+=("${1}") ;;
    esac

    shift
  done
}; _opts_main "${@}"

[[ ${#ERRBAG} -gt 0 ]] && {
  echo "Unsupported or conflicting arguments:" >&2
  printf -- '* %s\n' "${ERRBAG[@]}" >&2
  echo
  echo "Issue \`${0} -h\` for help"
  exit 1
}

help_description() {
  echo "Generate certificates"
}

help_usage() {
  local TODO="
    USAGE
    =====
    \`\`\`sh
    # View help or help sections.
    # Available sections: description, usage, opts, env, demo
   .${0} -h [SECTION...]
   .
    # Generate configuration to DEST files or to stdout if
    # no DEST specified
   .${0} --confgen [-f] [--] [DEST...]
   .
    # Generate certificates based on configuration in
    # ${0}
   .${0} [-f] [--passfile PASSFILE] \\
   .  [--ca-passfile CA_PASSFILE]
   .
    # Generate certificates based on configuration in
    # ${0} to PREFIX with inline overrides
   .${0} [-f] [--passfile PASSFILE] \\
   .  [--ca-passfile CA_PASSFILE] [--encrypt] \\
   .  [--days DAYS] [--cn CN] \\
   .  [--issuer-cert ISSUER_CERT] \\
   .  [--issuer-key ISSUER_KEY] \\
   .  [--domain DOMAIN...] [--merge] [PREFIX]
    \`\`\`
  "

  sed -E 's/^\s*//'  <<< "
    USAGE
    =====
    \`\`\`sh
    # View help or help sections.
    # Available sections: description, usage, opts, env, demo
   .${0} -h [SECTION...]
   .
    # Generate configuration to DEST files or to stdout if
    # no DEST specified
   .${0} --confgen [-f] [--] [DEST...]
   .
    # Generate certificates based on configuration in
    # ${0}
   .${0} [-f] [--passfile PASSFILE] \\
   .  [--ca-passfile CA_PASSFILE]
    \`\`\`
  " | grep -vFx '' | sed 's/^\.//'
}

help_opts() {
  local TODO="
    OPTIONS
    =======
    --confgen       Generate configuration file. Basicly
   .                the script just copies itself with
   .                minor modification
    -f, --force     Force override files if exist
    --passfile      Key password file. Only takes effect
   .                when certificate key file is
   .                configured to be encrypted
    --ca-passfile   CA key password file
    --encrypt       Encrypt key. In this case you either
   .                will be prompted for pass or provide
   .                PASSFILE
    --days          Number of days cert is valid for
    --cn            Common name
    --issuer-cert   CA issuer cert file. I.e. if this
   .                option is used the certificate won't
   .                be self-signed
    --issuer-key    CA issuer key file. Ignored without
   .                ISSUER_CERT. When ISSUER_CERT is set
   .                but ISSUER_KEY is not ISSUER_CERT
   .                will be used
    --domain        Domains and IPs for SAN
    --merge         Merge key into cert file
    -h, -?, --help  Print help
    \`\`\`
  "

  sed -E 's/^\s*//'  <<< "
    OPTIONS
    =======
    --confgen       Generate configuration file. Basicly
   .                the script just copies itself with
   .                minor modification
    -f, --force     Force override files if exist
    --passfile      Key password file. Only takes effect
   .                when certificate key file is
   .                configured to be encrypted
    --ca-passfile   CA key password file
    -h, -?, --help  Print help
  " | grep -vFx '' | sed 's/^\.//'
}

help_env() {
  sed -E 's/^\s*//'  <<< "
    ENV VARS
    ========
    Alternative way to pass sencitive data is via env
    variables. It's convinient when you keep this data
    in a file in encrypted form. The following
    environment variables are supported:
    * MYSSL_CA_KEY      - issuer key text
    * MYSSL_KEYPASS     - key password
    * MYSSL_CA_KEYPASS  - issuer key password
  " | grep -vFx '' | sed 's/^\.//'
}

help_demo() {
  sed -E 's/^\s*//'  <<< "
    DEMO
    ====
    \`\`\`sh
    # Generate configuration
    $(basename "$(realpath "${BASH_SOURCE[0]}")") ./my-cert-conf.sh
   .
    # Edit the CONF section
    vim ./my-cert-conf.sh
   .
    # Run the configuration
   ../my-cert-conf.sh

    # Assuming you're generating a cert signed by CA
    # with encrypted key
    MYSSL_CA_KEY=\"\$(cat ./ca.key)\" \\
   .  MYSSL_CA_KEYPASS=qwerty \\
   .  ./my-cert-conf.sh
    \`\`\`
  " | grep -vFx '' | sed 's/^\.//'
}

help_help() {
  help_description
  echo
  help_usage
  echo
  help_opts
  echo
  help_env
  echo
  help_demo
}

_help() {
  unset _help

  ${1} || return 0
  shift

  local sections=("${@}")
  local ix
  local fnc
  for ix in "${!sections[@]}"; do
    [[ ${ix} -gt 0 ]] && echo
    fnc="help_${sections[$ix]}"
    ${fnc}
  done

  exit 0
}; _help "${OPTS_HELP[@]}"

_confgen() {
  unset _confgen

  ${1} || return 0
  shift

  local force="${1}"
  shift
  local -a dests=("${@}")
  local tpl_txt
  local dest_dir

  tpl_txt="$(cat -- "${0}" | grep -Ev '^\s*\[is-tpl\]=')"

  [[ ${#dests} -gt 0 ]] || {
    printf -- '%s\n' "${tpl_txt}"
    exit 0
  }

  for dest in "${dests[@]}"; do
    grep -qEx '\s*' <<< "${dest}" && {
      ERRBAG+=("Conf file can't be with empty name")
      continue
    }
    if ! ${force} && [[ -e "${dest}" ]]; then
      ERRBAG+=("Conf file already exists: ${dest}")
      continue
    fi

    dest_dir="$(dirname "${dest}")"
    mkdir -p "${dest_dir}" 2>/dev/null || {
      ERRBAG+=("Can't create conf file directory: ${dest_dir}")
      continue
    }

    printf -- '%s\n' "${tpl_txt}" \
    | tee "${dest}" >/dev/null 2>&1 || {
      ERRBAG+=("Can't write to conf file: ${dest}")
      continue
    }

    chmod +x "${dest}" || {
      ERRBAG+=("Can't chmod: ${dest}")
      continue
    }

    echo "Generated: ${dest}" >&2
  done

  [[ ${#ERRBAG[@]} -gt 0 ]] && {
    echo "Errors:" >&2
    printf -- '* %s\n' "${ERRBAG[@]}" >&2
    return 1
  }

  exit 0
}; _confgen "${OPTS_CONFGEN[@]}" || exit $?

if [[ -n "${CONF[is-tpl]}" ]]; then
  sed -E 's/^\s+//' <<< "
    Can't generate certificates, you must \`--confgen\` first
    or remove \`is-tpl\` entry line from CONF section
  " | grep -vFx '' >&2
  echo
  echo "Issue \`${0} -h\` for help"
  exit 1
fi

fix_path() {
  local path="${1}"
  [[ "${path:0:3}" == '!./' ]] && {
    path="$(realpath "$(dirname ${0})")/${path:3}"
  }
  printf -- '%s\n' "${path}"
}

CONF[out-prefix]="$(fix_path "${CONF[out-prefix]}")"
CONF[issuer-cert]="$(fix_path "${CONF[issuer-cert]}")"
CONF[issuer-key]="$(fix_path "${CONF[issuer-key]}")"

filename="$(basename "${CONF[out-prefix]}")"

TMPDIR="$(/bin/mktemp -d --suffix '-mkssl')" || {
  echo "Error creating temp directory" >&2
  exit 1
}
[[ "${CONF[encrypt]}" =~ ^(true|false)$ ]] || {
  echo "Invalid ENCRYPT value: ${CONF[encrypt]}" >&2
  exit 1
}
[[ "${CONF[merge]}" =~ ^(true|false)$ ]] || {
  echo "Invalid MERGE value: ${CONF[merge]}" >&2
  exit 1
}
OUTDIR="$(dirname "${CONF[out-prefix]}")"
ENCRYPT="${CONF[encrypt]}"
DAYS="${CONF[days]}"
DOMAINS="$(sed -E 's/^\s+//' <<< "${CONF[domains]}" | grep -vFx '')"
MERGE="${CONF[merge]}"
ISSUER_CERT="${CONF[issuer-cert]}"
ISSUER_KEY="${CONF[issuer-key]:-${ISSUER_CERT}}"
TMPKEYFILE="${TMPDIR}/${filename}.key"
TMPCERTFILE="${TMPDIR}/${filename}.crt"
TMPREQFILE="${TMPDIR}/${filename}.csr"

KEYFILE="${OUTDIR}/${filename}.key"
CERTFILE="${OUTDIR}/${filename}.crt"
REQFILE="${OUTDIR}/${filename}.csr"

for v in KEYFILE CERTFILE REQFILE; do
  ${FORCE} && break
  [[ -e "${!v}" ]] && ERRBAG+=("${!v}")
done

[[ ${#ERRBAG[@]} -gt 0 ]] && {
  echo "Files already exist:" >&2
  printf -- '* %s\n' "${ERRBAG[@]}" >&2
  exit 1
}


MYSSL_KEYPASS="${MYSSL_KEYPASS-$(
  cat -- "${PASSFILE}" 2>/dev/null
)}" && PASSFILE=true

MYSSL_CA_KEYPASS="${MYSSL_CA_KEYPASS-$(
  cat -- "${CA_PASSFILE}" 2>/dev/null
)}" && CA_PASSFILE=true

trap "rm -f '${TMPDIR}'/*" SIGINT

CONFFILE="
  [req]
  default_bits = 4096
  prompt = no
  default_md = sha256
  distinguished_name = dn
  x509_extensions = ca-ext
  req_extensions = req-ext

  [ca-ext]
  subjectKeyIdentifier = hash
  authorityKeyIdentifier = keyid, issuer
  basicConstraints = CA:$([[ -n "${DOMAINS}" ]] && echo FALSE || echo TRUE)

  [req-ext]
  authorityKeyIdentifier = keyid, issuer
  basicConstraints = CA:FALSE
  keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
  extendedKeyUsage = serverAuth, clientAuth
  subjectAltName = @alt-names

  [dn]
  CN = ${CONF[cn]}

  [alt-names]
"

CONFFILE="$(sed -E 's/^\s+//' <<< "${CONFFILE}" \
  | grep -vFx '')"

# mkkey
cmd_key=(
  openssl genpkey -algorithm RSA -outform PEM
  -pkeyopt rsa_keygen_bits:4096 -out "${TMPKEYFILE}"
)
${CONF[encrypt]} && cmd_key+=(-aes256)
if [[ -n "${PASSFILE+x}" ]]; then
  "${cmd_key[@]}" -pass file:<(pass="${MYSSL_KEYPASS}" printenv pass)
else
  "${cmd_key[@]}"
fi

[[ -z "${DOMAINS}" ]] && {
  # CA certificate, but still needs an entry under SAN section
  # for valid conffile
  CONFFILE+=$'\n'"DNS.1 = localhost"
} || {
  declare -a dns_arr
  mapfile -t dns_arr <<< "${DOMAINS}"

  declare -a fqdns
  declare -a ips
  for dns in "${dns_arr[@]}"; do
    grep -qxE '([0-9]{1,3}\.){3}[0-9]{1,3}' <<< "${dns}" \
      && ips+=("${dns}") \
      || fqdns+=("${dns}")
  done

  for ix in "${!fqdns[@]}"; do
    CONFFILE+=$'\n'"DNS.$(( ix + 1 )) = ${fqdns[$ix]}"
  done

  for ix in "${!ips[@]}"; do
    CONFFILE+=$'\n'"IP.$(( ix + 1 )) = ${ips[$ix]}"
  done
}

if [[ -n "${ISSUER_CERT}" ]]; then
  # in case CA key is passed via env var
  MYSSL_CA_KEY="${MYSSL_CA_KEY-$(cat -- "${ISSUER_CERT}" 2>/dev/null)}"

  cmd_req=(
    openssl req -new -key "${TMPKEYFILE}"
    -out "${TMPREQFILE}"
  )
  cmd_cert=(
    openssl x509 -req -in "${TMPREQFILE}"
    -CA "${ISSUER_CERT}" -CAcreateserial
    -out "${TMPCERTFILE}" -days "${DAYS}"
    -extensions 'req-ext'
  )

  if [[ -n "${PASSFILE+x}" ]]; then
    "${cmd_req[@]}" \
      -config <(grep -Ev 'authorityKeyIdentifier =' <<< "${CONFFILE}") \
      -passin file:<(cat - <<< "${MYSSL_KEYPASS}")
  else
    "${cmd_req[@]}" \
      -config <(grep -Ev 'authorityKeyIdentifier =' <<< "${CONFFILE}")
  fi

  if [[ -n "${CA_PASSFILE+x}" ]]; then
    "${cmd_cert[@]}" \
      -CAkey <(cat - <<< "${MYSSL_CA_KEY}") \
      -extfile <(cat - <<< "${CONFFILE}") \
      -passin file:<(cat - <<< "${MYSSL_CA_KEYPASS}")
  else
    "${cmd_cert[@]}" \
      -CAkey <(cat - <<< "${MYSSL_CA_KEY}") \
      -extfile <(cat - <<< "${CONFFILE}")
  fi
else
  # mkcert
  cmd_cert=(
    openssl req -new -x509 -key "${TMPKEYFILE}"
    -days "${DAYS}" -out "${TMPCERTFILE}"
  )
  [[ -n "${DOMAINS}" ]] && {
    cmd_cert+=(-extensions 'req-ext')
  }
  if [[ -n "${PASSFILE+x}" ]]; then
    "${cmd_cert[@]}" \
      -config <(cat - <<< "${CONFFILE}") \
      -passin file:<(cat - <<< "${MYSSL_KEYPASS}")
  else
    "${cmd_cert[@]}" \
      -config <(cat - <<< "${CONFFILE}")
  fi
fi

[[ (-f "${TMPCERTFILE}" && -f "${TMPKEYFILE}") ]] && {
  mkdir -p "${OUTDIR}"

  if ${MERGE}; then
    cat -- - "${TMPKEYFILE}" <<< $'\n' >> "${TMPCERTFILE}"
  else
    mv "${TMPKEYFILE}" "${OUTDIR}"
  fi
  mv "${TMPCERTFILE}" "${OUTDIR}"

  rm -f "${TMPDIR}"/*

  exit 0
}

echo "Something went wrong" >&2

exit 1

## generate CA key and cert
# openssl genrsa -out ./certs/ca.key 4096
# openssl req -new -x509 -key ./certs/ca.key -days 730 -out ./certs/ca.crt -config openssl.conf

## generate server key and csr
# openssl genrsa -out ./certs/server.key 4096
# openssl req -new -key ./certs/server.key -out ./certs/server.csr -config openssl.conf
# openssl x509 -req -in ./certs/server.csr -CA ./certs/ca.crt -CAkey ./certs/ca.key -CAcreateserial -out ./certs/server.crt -days 365 -extensions 'req_ext' -extfile ./openssl.conf

# # generate CA key and cert
# openssl genpkey -algorithm RSA -aes256 \
#   -outform PEM -pkeyopt rsa_keygen_bits:4096 \
#   -out ./certs/ca.key -pass file:<(pass=changeme printenv pass)
# ${ca} && {
#   openssl req -new -x509 -key ./certs/ca.key -days 35600 \
#     -out ./certs/ca.crt -passin file:<(pass=changeme printenv pass)
#     -config openssl.conf
# } || {
#   openssl req -new -x509 -key ./certs/ca.key -days 35600 \
#     -out ./certs/ca.crt -passin file:<(pass=changeme printenv pass)
#     -config openssl.conf -extensions 'req_ext'
# }

# # generate server key and csr, and sign cert
# openssl genrsa -out ./certs/server.key 4096
# openssl req -new -key ./certs/server.key -out ./certs/server.csr -config openssl.conf
# openssl x509 -req -in ./certs/server.csr -CA ./certs/ca.crt -CAkey ./certs/ca.key -CAcreateserial -out ./certs/server.crt -days 365 -extensions 'req_ext' -extfile ./openssl.conf
