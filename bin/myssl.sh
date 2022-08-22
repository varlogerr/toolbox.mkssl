#!/usr/bin/env bash

# {CONF_TPL}
# # {CONFBLOCK}
# # Configuration block. Ignored by force confgen
#
# BASE_DIR="{{ BASE_DIR }}"
# CERTS_DIR="{{ CERTS_DIR }}"
# CA_DIR="{{ CA_DIR }}"
#
# declare -A CONF=(
#   # Output file prefix (without extension)
#   [out-prefix]="{{ out-prefix }}"
#   # Encrypt private key
#   [encrypt]={{ encrypt }}
#   # Can be more than 365 for CA. For servers 365 or below
#   [days]={{ days }}
#   [cn]="{{ cn }}"
#   # Issuer cert path. Leave blank for self-signed
#   [issuer-cert]="{{ issuer-cert }}"
#   # Issuer key path. Ignored with no issuer-cert. When
#   # blank, issuer-cert file will be used
#   [issuer-key]="{{ issuer-key }}"
#   # Domains and IPs for SAN. One per line, empty lines are
#   # ignored. Leave blank for CA certificate generation
#   [hosts]="{{ hosts }}"
#   # Merge key and cert into a single *.pem file
#   [merge]={{ merge }}
# )
#
# ## If you generated this configuration with a system wide
# ## installed myssl tool, probably you'll want to use it
# ## instead of stand alone code under CONFBLOCK.
# ## In this case uncomment sourcing line below and remove
# ## everything after CONFBLOCK.
# # . "{{ SOURCE_SCRIPT }}"
#
# # {/CONFBLOCK}
# {/CONF_TPL}

declare -A DEF=(
  # conf template only defaults
  [SOURCE_SCRIPT]="$(realpath -- "${0}")"
  [BASE_DIR]='$(dirname -- "${0}")'
  [CERTS_DIR]='${BASE_DIR}/certs'
  [CA_DIR]='${BASE_DIR}/ca'
  [out-prefix]='${CERTS_DIR}/$(basename -s .sh -- "${0}")'
  # common defaults
  [encrypt]=false
  [days]=365
  [cn]="Root CA"
  [issuer-cert]=""
  [issuer-key]=""
  [hosts]=""
  [merge]=false
)

# Ensure defaults
[[ -n "${CONF+x}" ]] || declare -A CONF
CONF+=(
  # only avoid defaulting 'out-prefix'
  [out-prefix]="${CONF[out-prefix]}"
  [encrypt]="${CONF[encrypt]-${DEF[encrypt]}}"
  [days]="${CONF[days]-${DEF[days]}}"
  [cn]="${CONF[cn]-${DEF[cn]}}"
  [issuer-cert]="${CONF[issuer-cert]-${DEF[issuer-cert]}}"
  [issuer-key]="${CONF[issuer-key]-${DEF[issuer-key]}}"
  [hosts]="${CONF[hosts]-${DEF[hosts]}}"
  [merge]="${CONF[merge]-${DEF[merge]}}"
)

declare -a ERRBAG=()

print_msg() {
  local res
  res="$(printf -- '%s\n' "${@}" \
    | sed -e 's/^\s*//' -e 's/\s*$//' \
    | grep -vFx '' | sed 's/^\.//')"
  [[ -n "${res}" ]] || return 1
  printf -- '%s\n' "${res}"
  return 0
}
print_err() { print_msg "${@}" >&2; }

log_msg() {
  print_msg "${@}" | sed 's/^/[myssl] /'
}
log_err() { log_msg "${@}" >&2; }

log_fail_rc() {
  local rc=${1}
  shift
  local msg="${@}"

  [[ "${rc}" -lt 1 ]] && return ${rc}

  log_err "${msg[@]}"
  exit "${rc}"
}

# https://gist.github.com/varlogerr/2c058af053921f1e9a0ddc39ab854577#file-sed-quote
sed_quote_keyword() {
  local keyword="${1-$(cat -)}"
  sed -e 's/[]\/$*.^[]/\\&/g' <<< "${keyword}"
}
sed_quote_replace() {
  local keyword="${1-$(cat -)}"
  sed -e 's/[\/&]/\\&/g' <<< "${keyword}"
}

_get_block() {
  local tag_word="${1}"
  local txt="${2}"
  local tag_start="# {$tag_word}"
  local tag_end="# {/$tag_word}"

  grep -A 999999 -Fx -- "${tag_start}" <<< "${txt}" \
  | grep -B 999999 -Fx -- "${tag_end}"
}

get_confblock() {
  local txt="${1}"

  _get_block CONFBLOCK "${1}"
}

get_conftpl() {
  local txt="${1}"
  local -a sed_opts

  local key
  local replace
  for key in "${!DEF[@]}"; do
    key="$(sed_quote_keyword "${key}")"
    replace="$(sed_quote_replace "${DEF[$key]}")"
    sed_opts+=(-e "s/{{\s*${key}\s*}}/${replace}/g")
  done

  _get_block CONF_TPL "${1}" | sed -E 's/#\s?//' \
  | tail -n +2 | head -n -1 | sed "${sed_opts[@]}"
}

get_body() {
  local txt="${1}"
  local ignore_tag='# {CONF_TPL}'

  grep -A 999999 -Fx -- "${ignore_tag}" <<< "${txt}"
}

{
  declare -a OPTS_HELP
  _opts_help() {
    unset _opts_help

    local -a available_sections=(
      description usage opts env demo import
    )

    local is_help=false
    local -a sections

    local key
    local sections_rex="$(printf -- '%s\n' "${available_sections[@]}" \
      | tr '\n' '|' | sed 's/|$//')"
    while :; do
      [[ -n "${1+x}" ]] || break
      key="${1}"; shift

      [[ "${key}" =~ ^(-h|-\?|--help)$ ]] && {
        is_help=true
        continue
      }

      [[ "${key}" =~ ^(${sections_rex})$ ]] && {
        sections+=("${key}")
        continue
      }

      ERRBAG+=("${key}")
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
} || {
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
        --genconf   ) is_confgen=true ;;
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
} || {
  # extend CONF with inline only options,
  # commented ones are placeholders
  CONF+=(
    # [passfile]=
    # [ca_passfile]=
    [force]=false
  )
  _opts_main() {
    unset _opts_main

    declare -A overrides
    local overkeys_rex="$(print_msg "
      issuer-key
      issuer-cert
      days
      cn
    " | tr '\n' '|' | sed 's/|$//')"
    declare key
    declare endopts=false
    while :; do
      [[ -n "${1+x}" ]] || break
      ${endopts} && key='*' || key="${1}"

      [[ "${key}" =~ ^--(${overkeys_rex})$ ]] && {
        # override keys from CONF
        overrides["${1:2}"]="${2}"
        shift; shift; continue
      }

      case "${key}" in
        --passfile    ) shift; [[ -n "${1+x}" ]] && CONF[passfile]="${1}" ;;
        --ca-passfile ) shift; [[ -n "${1+x}" ]] && CONF[ca_passfile]="${1}" ;;
        -f|--force    ) CONF[force]=true ;;
        # override keys from CONF
        --encrypt     ) overrides[encrypt]=true ;;
        --merge       ) overrides[merge]=true ;;
        --host        ) shift; overrides[hosts]+="${overrides[hosts]+$'\n'}${1}" ;;
        --            ) endopts=true ;;
        -*            ) ERRBAG+=("${1}") ;;
        *             ) overrides[out-prefix]="${1}" ;;
      esac

      shift
    done

    [[ -z "${overrides[out-prefix]+x}" && ${#overrides[@]} -gt 0 ]] \
      && log_fail_rc 1 "
        PREFIX is required
      .
        Issue \`${0} -h\` for help
      "

    # merge hosts with the ones from CONF
    [[ -n "${CONF[hosts]}" && "${overrides[hosts]}" ]] \
      && overrides[hosts]="${CONF[hosts]}"$'\n'"${overrides[hosts]}"

    local k
    for k in "${!overrides[@]}"; do
      CONF[$k]="${overrides[$k]}"
    done
  }; _opts_main "${@}"
}

[[ ${#ERRBAG} -gt 0 ]] \
  && log_fail_rc 1 "
    Unsupported or conflicting arguments:
    $(printf -- '* %s\n' "${ERRBAG[@]}" | sort -n | uniq)
   .
    Issue \`${0} -h\` for help
  "

help_description() {
  print_msg "Generate certificates"
}

help_usage() {
  local tool="$(basename -- "${0}")"

  print_msg "
    USAGE
    =====
    \`\`\`sh
    # View help or help sections.
    # Available sections: description, usage, opts, env, demo
   .${tool} -h [SECTION...]
   .
    # Generate configuration to DEST files or to stdout if
    # no DEST specified
   .${tool} --confgen [-f] [--] [DEST...]
   .
    # Generate certificates based on configuration in
    # ${tool}
   .${tool} [-f] [--passfile PASSFILE] \\
   .  [--ca-passfile CA_PASSFILE]
   .
    # Generate certificates based on configuration in
    # ${tool} to PREFIX with inline overrides,
    # see EXTENDED OPTIONS under OPTIONS help menu
   .${tool} [-f] [--passfile PASSFILE] \\
   .  [--ca-passfile CA_PASSFILE] [--encrypt] \\
   .  [--days DAYS] [--cn CN] \\
   .  [--issuer-cert ISSUER_CERT] \\
   .  [--issuer-key ISSUER_KEY] \\
   .  [--host HOST...] [--merge] PREFIX
    \`\`\`
  "
}

help_opts() {
  print_msg "
    BASIC options are used in conjunction with conffile,
    while EXTENDED are meant to override conffile values
   .
    BASIC
    =======
    --confgen       Generate configuration file.
   .                Basically the script just copies
   .                itself with minor modification
    -f, --force     Force override files if exist
    --passfile      Key password file. Only takes effect
   .                when certificate key file is
   .                configured to be encrypted. See
   .                MYSSL_KEYPASS env variable for
   .                replacement
    --ca-passfile   CA key password file. See
   .                MYSSL_CA_KEYPASS env variable for
   .                replacement
    -h, -?, --help  Print help
    EXTENDED
    ========
    --encrypt       Encrypt key. In this case you either
   .                will be prompted for pass or provide
   .                PASSFILE
    --days          Number of days cert is valid for.
   .                Defaults to '${DEF[days]}'
    --cn            Common name. Defaults to '${DEF[cn]}'
    --issuer-cert   CA issuer cert file. I.e. if this
   .                option is used the certificate won't
   .                be self-signed
    --issuer-key    CA issuer key file. Ignored without
   .                ISSUER_CERT. When ISSUER_CERT is set
   .                but ISSUER_KEY is not ISSUER_CERT
   .                will be used. See MYSSL_CA_KEY env
   .                variable for replacement
    --host          Domain or IP for SAN
    --merge         Merge key and cert into a *.pem file
    \`\`\`
  "
}

help_env() {
  print_msg "
    ENV VARS
    ========
    Alternative way to pass sencitive data is via env
    variables. It's convinient when you keep this data
    in a file in encrypted form. The following
    environment variables are supported:
    * MYSSL_CA_KEY      - issuer key text
    * MYSSL_KEYPASS     - key password
    * MYSSL_CA_KEYPASS  - issuer key password
  "
}

help_demo() {
  local tool="$(basename -- "${0}")"
  print_msg "
    DEMO
    ====
    \`\`\`sh
    # Generate configuration
    ${tool} --confgen ./my-cert-conf.sh
   .
    # Edit the CONF section
    vim ./my-cert-conf.sh
   .
    # Run the configuration to generate CA
   ../my-cert-conf.sh
   .
    # Assuming you're generating a cert signed by CA
    # with encrypted key
    MYSSL_CA_KEY=\"\$(cat ./ca.key)\" \\
   .  MYSSL_CA_KEYPASS=qwerty \\
   .  ./my-cert-conf.sh
    \`\`\`
  "
}

help_import() {
  print_msg "
    IMPORT
    ======
    Certificate import options:
    * Google Chrome
   .  chrome://settings/certificates -> Authorities tab -> Import
    * Firefox
   .  about:preferences#privacy -> Certificates section
   .  -> Certificates section -> View Certificates ...
    * Android
   .  Settings -> Security & Lock Screen
   .  -> Encryption & Credentials -> Install a certificate
    * Debian / Ubuntu
   .  \`\`\`sh
   .  sudo cp '\${CERTFILE}' /usr/local/share/ca-certificates
   .  sudo update-ca-certificates
   .  \`\`\`
   .
  "
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
  echo
  help_import
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
  local shebang='#!/usr/bin/env bash'
  local tpl_txt
  local tpl_confblock
  local tpl_body
  local dest_dir

  tpl_txt="$(cat -- "${0}")"
  tpl_body="$(get_body "${tpl_txt}")"
  tpl_confblock="$(get_conftpl "${tpl_body}")"

  [[ ${#dests} -gt 0 ]] || {
    printf -- '%s\n\n%s\n\n%s\n' \
      "${shebang}" "${tpl_confblock}" "${tpl_body}"
    exit 0
  }

  local dest_txt
  local confblock
  for dest in "${dests[@]}"; do
    grep -qEx '\s*' <<< "${dest}" && {
      ERRBAG+=("Conf file can't be with empty name")
      continue
    }
    if ! ${force} && [[ -e "${dest}" ]]; then
      ERRBAG+=("Conf file already exists: ${dest}")
      continue
    fi

    dest_dir="$(dirname -- "${dest}")"
    mkdir -p -- "${dest_dir}" 2>/dev/null || {
      ERRBAG+=("Can't create conf file directory: ${dest_dir}")
      continue
    }

    dest_txt="$(cat -- "${dest}" 2>/dev/null)"
    confblock="$(get_confblock "${dest_txt}")"
    confblock="${confblock:-${tpl_confblock}}"

    printf -- '%s\n\n%s\n\n%s\n' \
      "${shebang}" "${confblock}" "${tpl_body}" \
    | tee "${dest}" >/dev/null 2>&1 || {
      ERRBAG+=("Can't write to conf file: ${dest}")
      continue
    }

    chmod 0755 "${dest}" || {
      ERRBAG+=("Can't chmod: ${dest}")
      continue
    }

    log_err "Generated: ${dest}"
  done

  [[ ${#ERRBAG[@]} -gt 0 ]] && {
    log_err "
      Errors:
      $(printf -- '* %s\n' "${ERRBAG[@]}")
    " && return 1
  }

  exit 0
}; _confgen "${OPTS_CONFGEN[@]}" || exit $?

[[ -n "${CONF[out-prefix]}" ]] \
  || log_fail_rc 1 "
    Can't generate certificates.
    1. If you're using this script installed system wide:
    * Option 1: Use PREFIX argument of the command.
    * Option 2: generate a configuration, configure and
   .  execute it.
    2. If you're using a generated configuration, just
   .  make sure CONF['out-prefix'] is configured.
    3. If you downloaded this script want to use it stand
   .  alone either use point 1 or generate the
   .  configuration to the script itself:
   .  \`\`\`sh
   .  ${0} --confgen -f -- ${0}
   .  \`\`\`
   .  Then configure the resulting file and execute.
   .
    Issue \`${0} -h\` for help
  "

filename="$(basename -- "${CONF[out-prefix]}")"

TMPDIR="$(/bin/mktemp -d --suffix '-mkssl')" || {
  log_fail_rc 1 "Error creating temp directory"
}
[[ "${CONF[encrypt]}" =~ ^(true|false)$ ]] || {
  log_fail_rc 1 "Invalid ENCRYPT value: ${CONF[encrypt]}"
}
[[ "${CONF[merge]}" =~ ^(true|false)$ ]] || {
  log_fail_rc 1 "Invalid MERGE value: ${CONF[merge]}" && exit 1
}
OUTDIR="$(dirname -- "${CONF[out-prefix]}")"
ENCRYPT="${CONF[encrypt]}"
DAYS="${CONF[days]}"
HOSTS="$(print_msg "${CONF[hosts]}")"
MERGE="${CONF[merge]}"
ISSUER_CERT="${CONF[issuer-cert]}"
ISSUER_KEY="${CONF[issuer-key]:-${ISSUER_CERT}}"
TMPKEYFILE="${TMPDIR}/${filename}.key"
TMPCERTFILE="${TMPDIR}/${filename}.crt"
TMPREQFILE="${TMPDIR}/${filename}.csr"

KEYFILE="${OUTDIR}/${filename}.key"
CERTFILE="${OUTDIR}/${filename}.crt"
REQFILE="${OUTDIR}/${filename}.csr"

declare -r IS_CA="$([[ -n "${HOSTS}" ]] && echo false || echo true)"

for v in KEYFILE CERTFILE REQFILE; do
  ${CONF[force]} && break
  [[ -e "${!v}" ]] && ERRBAG+=("${!v}")
done

[[ ${#ERRBAG[@]} -gt 0 ]] && {
  log_fail_rc 1 "
    Files already exist:
    $(printf -- '* %s\n' "${ERRBAG[@]}")
  "
}

MYSSL_KEYPASS="${MYSSL_KEYPASS-$(
  cat -- "${CONF[passfile]}" 2>/dev/null
)}" && CONF[passfile]=true

MYSSL_CA_KEYPASS="${MYSSL_CA_KEYPASS-$(
  cat -- "${CONF[ca_passfile]}" 2>/dev/null
)}" && CONF[ca_passfile]=true

trap "rm -f '${TMPDIR}'/*" SIGINT

# COMPOSE CONFFILE
{
  declare TMPCONFFILE_CRT="${TMPDIR}/crt.cfg"
  declare TMPCONFFILE_REQ="${TMPDIR}/req.cfg"

  conffile_txt="$(print_msg "
    # https://support.dnsimple.com/categories/ssl-certificates/
    # https://www.openssl.org/docs/manmaster/man5/x509v3_config.html
    # https://www.ibm.com/docs/en/ztpf/1.1.0.15?topic=gssccr-configuration-file-generating-self-signed-certificates-certificate-requests
    # https://two-oes.medium.com/working-with-openssl-and-dns-alternative-names-367f06a23841
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
    basicConstraints = CA:${IS_CA^^}

    [req-ext]
    authorityKeyIdentifier = keyid, issuer
    basicConstraints = CA:${IS_CA^^}
    keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
    extendedKeyUsage = serverAuth, clientAuth
    subjectAltName = @alt-names

    [dn]
    CN = ${CONF[cn]}

    [alt-names]
  ")"

  ${IS_CA} && {
    # CA certificate still needs an entry under SAN section
    # for valid conffile
    conffile_txt+=$'\n'"DNS.1 = localhost"
  } || {
    declare ip_rex='([0-9]{1,3}\.){3}[0-9]{1,3}'
    declare ips
    declare domains

    domains="$(grep -vxE "${ip_rex}" <<< "${HOSTS}")"
    ips="$(grep -xE "${ip_rex}" <<< "${HOSTS}")"

    conffile_txt+="${domains:+$'\n'$(
      cat -n <<< "${domains}" \
      | sed -E 's/^\s*([0-9]+)\s*/DNS.\1 = /')}${ips:+$'\n'$(
      cat -n <<< "${ips}" \
      | sed -E 's/^\s*([0-9]+)\s*/IP.\1 = /')}"
  }

  tee "${TMPCONFFILE_CRT}" <<< "${conffile_txt}" >/dev/null 2>&1
  log_fail_rc $? "Error creating temp cert conffile: ${TMPCONFFILE_CRT}"

  # there is no authority parameters while creating a request file
  grep -Ev '^authorityKeyIdentifier =' <<< "${conffile_txt}" \
  | tee "${TMPCONFFILE_REQ}" >/dev/null 2>&1 \
    || log_fail_rc $? "Error creating temp req conffile: ${TMPCONFFILE_REQ}"
}

# CREATE KEY
{
  log_msg "Generating key ..."

  cmd_key=(
    openssl genpkey -algorithm RSA -outform PEM
    -pkeyopt rsa_keygen_bits:4096 -out "${TMPKEYFILE}"
  )
  ${CONF[encrypt]} && cmd_key+=(-aes256)

  {
    if [[ -n "${CONF[passfile]+x}" ]]; then
      "${cmd_key[@]}" -pass file:<(pass="${MYSSL_KEYPASS}" printenv pass)
    else
      "${cmd_key[@]}"
    fi
    log_fail_rc $? "Couldn't generate key"
  }
}

if [[ -n "${ISSUER_CERT}" ]]; then
  # CREATE SCR AND SIGNED BY ISSUER CERT

  # in case CA key is passed via env var
  MYSSL_CA_KEY="${MYSSL_CA_KEY-$(cat -- "${ISSUER_KEY}" 2>/dev/null)}"

  cmd_req=(
    openssl req -new -key "${TMPKEYFILE}"
    -out "${TMPREQFILE}" -config "${TMPCONFFILE_REQ}"
  )
  cmd_cert=(
    openssl x509 -req -in "${TMPREQFILE}"
    -CA "${ISSUER_CERT}" -CAcreateserial
    -out "${TMPCERTFILE}" -days "${DAYS}"
    -extfile "${TMPCONFFILE_CRT}"
  )
  # either server cert or intermediate
  ${IS_CA} \
    && cmd_cert+=(-extensions 'ca-ext') \
    || cmd_cert+=(-extensions 'req-ext')

  {
    log_msg "Generating CSR file ..."
    if [[ -n "${CONF[passfile]+x}" ]]; then
      "${cmd_req[@]}" -passin file:<(cat - <<< "${MYSSL_KEYPASS}")
    else
      "${cmd_req[@]}"
    fi
    log_fail_rc $? "Couldn't generate CSR file"
  }

  {
    log_msg "Generating cert ..."
    if [[ -n "${CONF[ca_passfile]+x}" ]]; then
      "${cmd_cert[@]}" \
        -CAkey <(cat - <<< "${MYSSL_CA_KEY}") \
        -passin file:<(cat - <<< "${MYSSL_CA_KEYPASS}")
    else
      "${cmd_cert[@]}" -CAkey <(cat - <<< "${MYSSL_CA_KEY}")
    fi
    log_fail_rc $? "Couldn't generate cert"
  }

  {
    log_msg "Creating certificate bundle ..."
    # https://serverfault.com/a/755815
    issuer_pkcs7="$(openssl crl2pkcs7 -nocrl -certfile "${ISSUER_CERT}")"
    log_fail_rc $? "Can't parse ISSUER_CERT"

    openssl pkcs7 -print_certs <<< "${issuer_pkcs7}" | grep -v \
      -e '^\s*$' -e '\s=\s' -e '^\s*subject=[^=]' -e '^\s*issuer=[^=]' \
    | tee -a "${TMPCERTFILE}" >/dev/null
    log_fail_rc $? "Couldn't create bundle"
  }

  log_msg "Vertifying cert against CA ..."
  openssl verify -CAfile "${ISSUER_CERT}" "${TMPCERTFILE}"
  log_fail_rc $? "Verification failed"
else
  # CREATE SELF-SIGNED CERT

  cmd_cert=(
    openssl req -new -x509 -key "${TMPKEYFILE}"
    -days "${DAYS}" -out "${TMPCERTFILE}"
    -config "${TMPCONFFILE_CRT}"
  )
  ${IS_CA} || cmd_cert+=(-extensions 'req-ext')

  {
    log_msg "Generating cert ..."
    if [[ -n "${CONF[passfile]+x}" ]]; then
      "${cmd_cert[@]}" -passin file:<(cat - <<< "${MYSSL_KEYPASS}")
    else
      "${cmd_cert[@]}"
    fi
    log_fail_rc $? "Couldn't generate cert"
  }
fi

_final() {
  unset _final

  [[ (-f "${TMPCERTFILE}" && -f "${TMPKEYFILE}") ]] || return 1

  mkdir -p -- "${OUTDIR}"
  log_fail_rc $? "Couldn't create destination directory: ${OUTDIR}"

  if ${MERGE}; then
    log_msg "Merging key into cert ..."
    cat -- "${TMPKEYFILE}" >> "${TMPCERTFILE}"
    log_fail_rc $? "Couldn't merge to ${TMPCERTFILE}"
    chmod 0600 -- "${TMPCERTFILE}"
    log_fail_rc $? "Couldn't chmod 0600 ${TMPCERTFILE}"
    CERTFILE="${CERTFILE%.*}.pem"
  else
    chmod 0600 -- "${TMPKEYFILE}"
    mv -- "${TMPKEYFILE}" "${KEYFILE}"
    log_fail_rc $? "Couldn't move to ${KEYFILE}"
  fi
  mv -- "${TMPCERTFILE}" "${CERTFILE}"
  log_fail_rc $? "Couldn't move to ${CERTFILE}"

  rm -f "${TMPDIR}"/*

  log_msg "
    Generated to $(realpath -- "${OUTDIR}")
    DONE
  "
}; _final || {
  log_err "Something went wrong" && exit 1
}

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
