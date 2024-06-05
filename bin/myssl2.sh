#!/usr/bin/env bash

# {{ MYSSL_TEMPLATES }}
#
# # {{ CONFBLOCK }}
#   # DON'T REMOVE OR EDIT CONFBLOCK OPEN AND CLOSE COMMENTS!
#
#   # # Uncomment for insecure PK passphrase override
#   # MYSSL_PKPASS=changeme
#
#   MYSSL_CONFFILE_DIR="{{ conffile-dir }}"
#   MYSSL_CONFFILE_NAME="{{ conffile-name }}"
#
#   declare -A MYSSL_CONF=(
#     # Generated files destination prefix
#     [dest-prefix]="{{ dest-prefix }}"
#     # Encrypt private key
#     [encrypt]={{ encrypt }}
#     # Can be more than 365 for CA. For servers 365 or below
#     [days]={{ days }}
#     # Common name
#     [cn]="{{ cn }}"
#     # Issuer cert path. Leave blank for self-signed
#     [issuer-cert]="{{ issuer-cert }}"
#     # Issuer key path. Ignored with no issuer-cert. When blank, issuer-cert file
#     # will be used, considering key and cert are merged into a single file.
#     [issuer-key]="{{ issuer-key }}"
#     # Domains and IPs for SAN. One per line. Empty lines and #-prefixed comments
#     # are ignored. Leave blank for CA certificate generation
#     [hosts]="{{ hosts }}"
#     # Merge key and cert into a single *.pem file
#     [merge]={{ merge }}
#     #
#     # EXTRA DISTINGUISHED NAME
#     #
#     # ISO 3166-1 country code. Example: US
#     [country]="{{ country }}"
#     # State or Province name. Example: New York
#     [state]="{{ state }}"
#     # Locality name. Example: New York
#     [locality]="{{ locality }}"
#     # Organization name. Example: Second hand vacuum cleaner corp
#     [org]="{{ org }}"
#     # Organization unit name. Example: marketing
#     [org-unit]="{{ org-unit }}"
#     # Spam destination
#     [email]="{{ email }}"
#     #
#     # AUTO-POPULATED VALUES
#     #
#     # [is-ca]=false
#     # [alt-names]=""
#     # [dn-extra]=""
#   )
# # {{/ CONFBLOCK }}
#
# # {{ HELP_USAGE }}
#   Generate conffile:
#   =================
#  ,
#  ,  # Available flags:
#  ,  # -f, --force   Force override existing conffile in case it's passed
#  ,  #               as an argument, otherwise will fail when destination
#  ,  #               file exists
#  ,  {{ tool }} gen-conffile [-f] [CONFFILE]
#  ,
#  ,  # DEMO:
#  ,
#  ,  # Generate "{{ conffile }}" configuration file:
#  ,  {{ tool }} gen-conffile {{ conffile }}
#  ,
#  ,  # (Alternative) Generate configuration file by stdout redirection:
#  ,  {{ tool }} gen-conffile > {{ conffile }}
#  ,
#  ,  # Edit the configuration file:
#  ,  vim {{ conffile }}
#  ,
#   Generate certificates:
#   =====================
#  ,
#  ,  # Available flags:
#  ,  # -f, --force   Force override existing cert files, otherwise will
#  ,  #               fail when destination files exist
#  ,  {{ tool }} gen-certs [-f] [CONFFILE]
#  ,
#  ,  # DEMO:
#  ,
#  ,  # Generate certificates by using self-contained configuration file:
#  ,  {{ conffile }} gen-certs {{ conffile }}
#  ,
#  ,  # (Alternative) Generate certificates using {{ tool }} feeded by the
#  ,  # generated configuration file. For this scenario the code after confblock
#  ,  # can be removed in the configuration file.
#  ,  {{ tool }} gen-certs {{ conffile }}
#  ,
#  ,  # In order to avoid prompt for passphrase with MYSSL_CONF[encrypt]=true
#  ,  # provide PK passphrase via MYSSL_PKPASS environment variable:
#  ,  MYSSL_PKPASS=changeme {{ tool }} gen-cert {{ conffile }}
# # {{/ HELP_USAGE }}
#
# # {{ TPL_OPENSSL_CONF }}
#   # https://support.dnsimple.com/categories/ssl-certificates/
#   # https://www.openssl.org/docs/manmaster/man5/x509v3_config.html
#   # https://www.ibm.com/docs/en/ztpf/1.1.0.15?topic=gssccr-configuration-file-generating-self-signed-certificates-certificate-requests
#   # https://two-oes.medium.com/working-with-openssl-and-dns-alternative-names-367f06a23841
#   [req]
#   default_bits = 4096
#   prompt = no
#   default_md = sha256
#   distinguished_name = dn
#   x509_extensions = ca-ext
#   req_extensions = req-ext
#
#   [ca-ext]
#   subjectKeyIdentifier = hash
#   authorityKeyIdentifier = keyid, issuer
#   basicConstraints = CA:{{ is-ca }}
#
#   [req-ext]
#   authorityKeyIdentifier = keyid, issuer
#   basicConstraints = CA:{{ is-ca }}
#   keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
#   extendedKeyUsage = serverAuth, clientAuth
#   subjectAltName = @alt-names
#
#   [dn]
#   CN = {{ cn }}
#   # PH:DN_EXTRA
#
#   [alt-names]
#   # PH:ALT_NAMES
# # {{/ TPL_OPENSSL_CONF }}
#
# {{/ MYSSL_TEMPLATES }}

# Only source the conf
(return &>/dev/null) && ${MYSSL_EXECUTOR_Bg2VTs1Kyt-false} && return

# shellcheck disable=SC2317
myssl() (
  # shellcheck disable=SC2016
  declare -A DEFAULTS; DEFAULTS=(
    # myssl conf only defaults
    [conffile-dir]='$(realpath -- "$(dirname -- "${BASH_SOURCE[0]}")")'
    [conffile-name]='$(basename -s .sh -- "${BASH_SOURCE[0]}")'
    [dest-prefix]='${MYSSL_CONFFILE_DIR}/${MYSSL_CONFFILE_NAME}/${MYSSL_CONFFILE_NAME}'
    # common defaults
    [encrypt]=false
    [days]=365
    [cn]="Root CA"
    [issuer-cert]=""
    [issuer-key]=""
    [hosts]=""
    [merge]=false
    # extremely useless distinguished name props
    [country]=""
    [state]=""
    [locality]=""
    [org]=""
    [org-unit]=""
    [email]=""
  )
  declare -r SELF="${BASH_SOURCE[0]}"
  declare -r TOOL="${0}"

  get_confblock() {
    get_tpl_section CONFBLOCK < "${SELF}" \
    | template_compile DEFAULTS
  }

  get_conffile() {
    declare section_id=CONFBLOCK

    declare last_conf_lineno
    declare script_txt
    if last_conf_lineno="$(set -o pipefail
      grep -A 999 -n '^#\s*{{\s*'"${section_id}"'\s*}}\s*$' < "${SELF}" \
      | grep -B 999 '^[0-9]\+-#\s*{{/\s*'"${section_id}"'\s*}}\s*$' \
      | sed -n '1p; $p' | grep -o '^[0-9]\+' | tail -n 1
    )"; then
      script_txt="$(tail -n +"$(( last_conf_lineno + 1 ))" < "${SELF}")"
    else
      script_txt="$(tail -n +2 < "${SELF}")"
    fi

    printf -- '%s\n\n%s\n\n%s\n' \
      '#!/usr/bin/env bash' \
      "$(get_confblock)" \
      "$(grep -A 9999 -v '^\s*$' <<< "${script_txt}")"
  }

  get_openssl_conffile() {
    declare -A phs=(
      ['PH:ALT_NAMES']="${MYSSL_CONF[alt-names]}"
      ['PH:DN_EXTRA']="${MYSSL_CONF[dn-extra]}"
    )

    declare conf; conf="$(get_tpl_section TPL_OPENSSL_CONF < "${SELF}" \
      | untag_tpl_section | print_formatted \
      | template_compile MYSSL_CONF
    )"

    declare ph_lineno
    declare ph; for ph in "${!phs[@]}"; do
      ph_lineno="$(
        set -o pipefail
        grep -m 1 -nFx "# ${ph}" <<< "${conf}" | cut -d':' -f1
      )" || continue

      conf="$(
        head -n $((ph_lineno - 1)) <<< "${conf}"
        [[ -n "${phs[${ph}]}" ]] && echo "${phs[${ph}]}"
        tail -n +$((ph_lineno + 1)) <<< "${conf}"
      )"
    done

    echo "${conf}"
  }

  help_usage() {
    # shellcheck disable=SC2094
    get_tpl_section HELP_USAGE < "${SELF}" \
    | untag_tpl_section | print_formatted \
    | template_compile  tool="$(basename -- "${TOOL}")" \
                        conffile='./demo-cert.conf.sh'
  }

  #################
  #   TEMPLATES   #
  #################

  # USAGE:
  #   get_comment_section SECTION_ID < FILE
  get_comment_section() {
    declare -r section_id="${1}"

    grep -A 999 '^#\s*{{\s*'"${section_id}"'\s*}}\s*$' \
    | grep -B 999 '^#\s*{{/\s*'"${section_id}"'\s*}}\s*$'
  }

  # USAGE:
  #   get_tpl_section SECTION_ID < FILE
  get_tpl_section() {
    declare -r section_id="${1}"

    get_comment_section MYSSL_TEMPLATES \
    | sed -e 's/^#\s\?//' \
    | get_comment_section "${section_id}"
  }

  # USAGE:
  #   untag_tpl_section < TPL_SECTION_FILE
  untag_tpl_section() {
    # remove open and close tags
    sed '0,/^#\s*{{[^}]\+}}\s*$/d' | grep -A 999 -v '^#\s*$' \
    | tac | sed '0,/^#\s*{{\/[^}]\+\s*}}\s*$/d' | grep -A 999 -v '^#\s*$' | tac
  }

  # USAGE:
  #   # Using map
  #   declare -A mymap=([TPL_KEY]=RELACE_VALUE)
  #   template_compile mymap < TPL_FILE
  #
  #   # Using key-value args
  #   template_compile TPL_KEY=REPLACE_VALUE... < TPL_FILE
  template_compile() {
    declare sed_script

    if [[ "${1}" == *'='* ]]; then
      declare -A map
      declare kv; for kv in "${@}"; do map+=(["${kv%%=*}"]="${kv#*=}"); done
    else
      # shellcheck disable=SC2178
      declare -n map="${1}"
    fi

    declare k; for k in "${!map[@]}"; do
      # Skip multiline replacements
      [[ $(wc -l <<< "${map[$k]}") -gt 1 ]] && continue

      sed_script+="${sed_script:+$'\n'}s/"
      sed_script+='{{\s*'"${k}"'\s*}}/'
      sed_script+="$(sed_quote_replace "${map[$k]}")/g"
    done

    sed -f <(printf -- '%s\n' "${sed_script}")
  }

  ###############
  #   Loggers   #
  ###############

  log_info()  { _log_sth INFO   "${@}"; }
  log_warn()  { _log_sth WARN   "${@}"; }
  log_fatal() { _log_sth FATAL  "${@}"; }
  _log_sth()  { printf -- '['"${1}"'] %s\n' "${@:2}" >&2; }

  ###############
  #   Helpers   #
  ###############

  # shellcheck disable=SC2120
  print_formatted() {
    declare input; input="${1-$(cat)}"

    grep -v '^\s*$' <<< "${input}" \
    | sed -e 's/^\s\+//' -e 's/\s\+$//' \
          -e 's/^,//'
  }

  # USAGE:
  #   # RC=0 - files exist, existing files in the output
  #   # RC=1 - none of files exist, blank output
  #   files_exist FILE...
  files_exist() {
    declare -a exist

    declare f; for f in "${@}"; do
      [[ -e "${f}" ]] && exist+=("${f}")
    done

    [[ ${#exist[@]} -lt 1 ]] && return 1

    printf -- '%s\n' "${exist[@]}"
    return 0
  }

  sed_quote_replace() { sed -e 's/[\/&]/\\&/g' <<< "${1-$(cat)}"; }

  "${@}"
)

# Basic initialization before generating certs
myssl_gencerts_init() {
  MYSSL_CONF+=(
    ['is-ca']=false
    ['alt-names']=""
    ['dn-extra']=""
  )

  # Prettify hosts list, remove empty lines and comments
  MYSSL_CONF[hosts]="$(
    myssl print_formatted "${MYSSL_CONF[hosts]}" | grep -v -e '^\s*$' -e '^#' \
    | sort -n | uniq
  )"

  # Detect if is CA and ensure hosts
  grep -qv '^$' <<< "${MYSSL_CONF[hosts]}" || {
    MYSSL_CONF['is-ca']=true
    MYSSL_CONF['hosts']=localhost
  }

  # Generate alt names text for openssl conffile
  declare matches
  declare ip_rex='^\([0-9]\+\.\)\{1,3\}[0-9]\{1,3\}$'
  matches="$(grep -- "${ip_rex}" <<< "${MYSSL_CONF[hosts]}")" && {
    MYSSL_CONF['alt-names']+="${MYSSL_CONF['alt-names']:+$'\n'}$(
      cat -n <<< "${matches}" | sed -e 's/^\s*\([0-9]\+\)\s*/IP.\1 = /'
    )"
  }
  matches="$(grep -v -- "${ip_rex}" <<< "${MYSSL_CONF[hosts]}")" && {
    MYSSL_CONF['alt-names']+="${MYSSL_CONF['alt-names']:+$'\n'}$(
      cat -n <<< "${matches}" | sed -e 's/^\s*\([0-9]\+\)\s*/DNS.\1 = /'
    )"
  }

  # Generate distinguished name text for openssl conffile
  declare -A dn_map=(
    [country]=C
    [state]=ST
    [locality]=L
    [org]=O
    [org-unit]=OU
    [email]=emailAddress
  )
  declare i; for i in "${!dn_map[@]}"; do
    [[ -n "${MYSSL_CONF[${i}]}" ]] || continue

    MYSSL_CONF['dn-extra']+="${MYSSL_CONF[dn-extra]:+$'\n'}"
    MYSSL_CONF['dn-extra']+="${dn_map[${i}]} = ${MYSSL_CONF[${i}]}"
  done

  # Export PK passphrase
  export MYSSL_PKPASS
}

# Stop here if the file is sourced
(return &>/dev/null) && return 0

##############
#   ACTION   #
##############

# Mark self as an executor
MYSSL_EXECUTOR_Bg2VTs1Kyt=true

[[ "${1}" =~ ^(-\?|-h|--help)$ ]] && {
  myssl help_usage
  exit
}

[[ "${1+x}" ]] || {
  myssl log_fatal "COMMAND required. For help issue:" "  $(basename -- "${0}") --help"
  exit 1
}

declare -a FLAGS=(
  [force]=false
)
declare -a ARGS_IN=("${@}")
declare CONFFILE
parse_common_args() {
  declare arg
  declare ix; for ix in "${!ARGS_IN[@]}"; do
    arg="${ARGS_IN[${ix}]}"

    case "${arg}" in
      -f|--force  )
        FLAGS[force]=true
        unset "ARGS_IN[$ix]"
        ;;
      *           )
        [[ -n "${CONFFILE+x}" ]] && continue
        CONFFILE="${arg}"
        unset "ARGS_IN[$ix]"
        ;;
    esac
  done
}

if [[ "${ARGS_IN[0]}" == gen-conffile ]]; then
  unset "ARGS_IN[0]"

  parse_common_args

  [[ -z "${CONFFILE+x}" ]] && {
    myssl get_conffile
    exit 0
  }

  myssl files_exist "${CONFFILE}" >/dev/null && ! "${FLAGS[force]}" && {
    myssl log_fatal "Can't override existing file ${CONFFILE}. For help issue:" "  $(basename -- "${0}") --help"
    exit 1
  }

  declare conffile_dir; conffile_dir="$(dirname -- "${CONFFILE}")"

  (set -x; mkdir -p -- "${conffile_dir}") || exit
  (set -o pipefail; myssl get_conffile | (set -x; tee -- "${CONFFILE}" >/dev/null)) || exit
  (set -x; chmod +x "${CONFFILE}")

  exit
fi

if [[ "${ARGS_IN[0]}" == gen-certs ]]; then
  unset "ARGS_IN[0]"

  [[ -n "${2+x}" ]] || {
    myssl log_fatal "Argument required. For help issue:" "  $(basename -- "${0}") --help"
    exit 1
  }

  # Validate CONFFILE can be read
  (set -x; cat -- "${2}" >/dev/null) || exit 1

  unset MYSSL_CONF

  # shellcheck disable=SC1090
  . "${2}" || exit

  declare -p MYSSL_CONF &>/dev/null || {
    myssl log_fatal "Can't detect MYSSL_CONF configuration variable in ${2}." \
                    "For help issue:" "  $(basename -- "${0}") --help"
    exit 1
  }

  # Initialize some important values
  myssl_gencerts_init

  # Generate openssl conffile
  declare OPENSSL_CONF; OPENSSL_CONF="$(myssl get_openssl_conffile)" || exit 1

  declare PK
  {
    ###############
    # Generate PK #
    ###############

    # [export MYSSL_PKPASS=KEY_PASSWORD]
    # openssl genpkey -algorithm RSA -outform PEM \
    #   -pkeyopt rsa_keygen_bits:4096 [-aes256 [-pass env:MYSSL_PKPASS]]
    declare -a pk_cmd=(
      openssl genpkey -algorithm RSA -outform PEM
      -pkeyopt rsa_keygen_bits:4096
    )

    if ${MYSSL_CONF[encrypt]}; then
      pk_cmd+=(-aes256)
      [[ -n "${MYSSL_PKPASS+x}" ]] && pk_cmd+=(-pass env:MYSSL_PKPASS)
    fi

    PK="$(
      (set -x; "${pk_cmd[@]}")
    )" || exit 1
  } # Generate PK

  declare CERT
  if [[ -z "${MYSSL_CONF[issuer-cert]}" ]]; then
    ###########################
    # Create self-signed cert #
    ###########################

    # [export MYSSL_PKPASS=KEY_PASSWORD]
    # openssl req -new -x509 -days DAYS \
    #   -key PK_FILE -config OPENSSL_CONFFILE \
    #   [-passin env:MYSSL_PKPASS]
    declare -a cert_cmd=(openssl req -new -x509 -days "${MYSSL_CONF[days]}")

    if ${MYSSL_CONF[encrypt]}; then
      [[ -n "${MYSSL_PKPASS+x}" ]] && cert_cmd+=(-passin env:MYSSL_PKPASS)
    fi

    CERT="$(
      set -o pipefail
      (
        (
          set -x
          "${cert_cmd[@]}" \
            -key    <(set +x; key="${PK}" printenv key) \
            -config <(set +x; config="${OPENSSL_CONF}" printenv config)
        ) 3>&2 2>&1 1>&3- \
        | grep -v '^+\+\s\+set\s+x$'
      ) 3>&2 2>&1 1>&3-
    )" || exit 1
  fi # Create self-signed cert

  {
    ###################
    # Verify key-cert #
    ###################

    # https://digicert.leaderssl.fr/articles/462-how-to-verify-compliance-of-a-private-key-with-the-ssl-certificate-and-csr
    # https://www.ssl247.com/knowledge-base/detail/how-do-i-verify-that-a-private-key-matches-a-certificate-openssl-1527076112539/ka03l0000015hscaay/

    declare pk_modulus_hash cert_modulus_hash
    declare pk_modulus_cmd=(
      openssl rsa -modulus -noout
    )

    if ${MYSSL_CONF[encrypt]}; then
      [[ -n "${MYSSL_PKPASS+x}" ]] && pk_modulus_cmd+=(-passin env:MYSSL_PKPASS)
    fi

    pk_modulus_hash="$(
      "${pk_modulus_cmd[@]}" -in <(key="${PK}" printenv key) \
      | openssl sha256 | cut -d' ' -f2-
    )"
    cert_modulus_hash="$(
      openssl x509 -modulus -noout -in <(cert="${CERT}" printenv cert) \
      | openssl sha256 | cut -d' ' -f2-
    )"

    [[ "${pk_modulus_hash}" == "${cert_modulus_hash}" ]] || {
      myssl log_fatal "Cert and PK checksum comparison failed."
      exit 1
    }
  } # Verify key-cert

  {
    #################
    # Install files #
    #################

    declare -A install_map=(
      # [EXT:MODE]=FILE_CONTENT
      ['crt:0644']="${CERT}"
      ['key:0600']="${PK}"
    )

    ${MYSSL_CONF[merge]} && {
      install_map=(['pem:0600']="${CERT}${CERT:+$'\n'}${PK}")
    }

    # Create destination directory
    declare dest_dir; dest_dir="$(dirname -- "${MYSSL_CONF[dest-prefix]}")"
    (set -x; mkdir -p -- "${dest_dir}") || exit 1

    # TODO: check for files overwrite

    declare ext mode
    declare k; for k in "${!install_map[@]}"; do
      ext="${k%%:*}"; mode="${k##*:}"

      content="${install_map[${k}]}" printenv content | (
        set -o pipefail
        (
          set -x; install --mode="${mode}" -- <(cat) "${MYSSL_CONF[dest-prefix]}.${ext}"
        ) 3>&2 2>&1 1>&3- \
        | grep -v '^+\+\s\+cat$'
      ) 3>&2 2>&1 1>&3- || exit 1
    done
  } # Install files

  exit
fi

myssl log_fatal "Invalid command ${1}. For help issue:" "  $(basename -- "${0}") --help"
exit 1
