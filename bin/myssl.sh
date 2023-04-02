#!/usr/bin/env bash

# {TPL_MYSSL_CONF}
# # {CONFBLOCK}
# # Configuration block. Ignored by force confgen
#
# BASE_DIR="{{ base-dir }}"
# CERTS_DIR="{{ certs-dir }}"
# CA_DIR="{{ ca-dir }}"
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
#   #
#   # EXTRA DISTINGUISHED NAME
#   #
#   # ISO 3166-1 country code. Example: US
#   [country]="{{ country }}"
#   # State or Province name. Example: New York
#   [state]="{{ state }}"
#   # Locality name. Example: New York
#   [locality]="{{ locality }}"
#   # Organization name. Example: Second hand vacuum clener corp
#   [org]="{{ org }}"
#   # Organization unit name. Example: marketing
#   [org-unit]="{{ org-unit }}"
#   # Spam destination
#   [email]="{{ email }}"
# )
#
# ## If you generated this configuration with a system wide
# ## installed myssl tool, probably you'll want to use it
# ## instead of stand alone code under CONFBLOCK.
# ## In this case uncomment sourcing line below and remove
# ## everything after CONFBLOCK.
# # . "{{ self-path }}"
#
# # {/CONFBLOCK}
# {/TPL_MYSSL_CONF}

# {TPL_OPENSSL_CONF}
# # https://support.dnsimple.com/categories/ssl-certificates/
# # https://www.openssl.org/docs/manmaster/man5/x509v3_config.html
# # https://www.ibm.com/docs/en/ztpf/1.1.0.15?topic=gssccr-configuration-file-generating-self-signed-certificates-certificate-requests
# # https://two-oes.medium.com/working-with-openssl-and-dns-alternative-names-367f06a23841
# [req]
# default_bits = 4096
# prompt = no
# default_md = sha256
# distinguished_name = dn
# x509_extensions = ca-ext
# req_extensions = req-ext
#
# [ca-ext]
# subjectKeyIdentifier = hash
# authorityKeyIdentifier = keyid, issuer
# basicConstraints = CA:{{ is-ca }}
#
# [req-ext]
# authorityKeyIdentifier = keyid, issuer
# basicConstraints = CA:{{ is-ca }}
# keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
# extendedKeyUsage = serverAuth, clientAuth
# subjectAltName = @alt-names
#
# [dn]
# CN = {{ cn }}
# # DN_EXTRA_PH
#
# [alt-names]
# {/TPL_OPENSSL_CONF}

# {TPL_HELP_USAGE}
# USAGE
# =====
# ```sh
# # View help or help sections.
# # Available sections:
# # description, usage, opts, env, demo, import
# {{ tool }} -h [SECTION...]
#
# # Generate configuration to DEST files or to stdout if
# # no DEST specified
# {{ tool }} --confgen [-f] [--] [DEST...]
#
# # Generate certificates based on configuration in
# # {{ tool }}
# {{ tool }} [-f] [--passfile PASSFILE] \
#   [--ca-passfile CA_PASSFILE]
#
# # Generate certificates based on configuration in
# # {{ tool }} to PREFIX with inline overrides,
# # see EXTENDED OPTIONS under OPTIONS help menu
# {{ tool }} [-f] [--passfile PASSFILE] \
#   [--ca-passfile CA_PASSFILE] [--encrypt] \
#   [--days DAYS] [--cn CN] \
#   [--issuer-cert ISSUER_CERT] \
#   [--issuer-key ISSUER_KEY] \
#   [--host HOST...] [--merge] PREFIX
# ```
# {/TPL_HELP_USAGE}
#
# {TPL_HELP_OPTS}
# OPTIONS
# =======
# BASIC options are used in conjunction with conffile,
# while EXTENDED and DN EXTRAS are meant to override
# conffile values
#   BASIC
# =======
# --confgen       Generate configuration file.
#                 Basically the script just copies
#                 itself with minor modification
# -f, --force     Force override files if exist
# --passfile      Key password file. Only takes effect
#                 when certificate key file is
#                 configured to be encrypted. See
#                 MYSSL_KEYPASS env variable for
#                 replacement
# --ca-passfile   CA key password file. See
#                 MYSSL_CA_KEYPASS env variable for
#                 replacement
# -h, -?, --help  Print help
#   EXTENDED
# ==========
# --encrypt       Encrypt key. In this case you either
#                 will be prompted for pass or provide
#                 PASSFILE
# --days          Number of days cert is valid for.
#                 Defaults to '{{ days }}'
# --cn            Common name. Defaults to '{{ cn }}'
# --issuer-cert   CA issuer cert file. I.e. if this
#                 option is used the certificate won't
#                 be self-signed
# --issuer-key    CA issuer key file. Ignored without
#                 ISSUER_CERT. When ISSUER_CERT is set
#                 but ISSUER_KEY is not ISSUER_CERT
#                 will be used. See MYSSL_CA_KEY env
#                 variable for replacement
# --host          Domain or IP for SAN
# --merge         Merge key and cert into a *.pem file
#   DN EXTRAS
# ===========
# --country     ISO 3166-1 country code
# --state       State or Province name
# --locality    Locality name
# --org         Organization name
# --org-unit    Organization unit name
# --email       Email
# {/TPL_HELP_OPTS}
#
# {TPL_HELP_ENV_VARS}
# ENV VARS
# ========
# Alternative way to pass sencitive data is via env
# variables. It's convinient when you keep this data
# in a file in encrypted form. The following
# environment variables are supported:
# * MYSSL_CA_KEY      - issuer key text
# * MYSSL_KEYPASS     - key password
# * MYSSL_CA_KEYPASS  - issuer key password
# {/TPL_HELP_ENV_VARS}
#
# {TPL_HELP_DEMO}
# DEMO
# ====
# ```sh
# # Generate configuration
# {{ tool }} --confgen ./my-cert-conf.sh
#
# # Edit the CONF section
# vim ./my-cert-conf.sh
#
# # Run the configuration to generate CA
# ./my-cert-conf.sh
#
# # Assuming you're generating a cert signed by CA
# # with encrypted key
# MYSSL_CA_KEY="$(cat ./ca.key)" \
# MYSSL_CA_KEYPASS=qwerty \
#   ./my-cert-conf.sh
# ```
# {/TPL_HELP_DEMO}
#
# {TPL_HELP_IMPORT}
# IMPORT
# ======
# Certificate import options:
# * Google Chrome
#   chrome://settings/certificates -> Authorities tab -> Import
# * Firefox
#   about:preferences#privacy -> Certificates section
#   -> Certificates section -> View Certificates ...
# * Android
#   Settings -> Security & Lock Screen
#   -> Encryption & Credentials -> Install a certificate
# * Debian / Ubuntu
#   ```sh
#   sudo cp "${CERTFILE}" /usr/local/share/ca-certificates
#   sudo update-ca-certificates
#   ```
# {/TPL_HELP_IMPORT}

LOG_TOOLNAME="$(basename -- "${0}")"
# {SHLIB_GEN}
  ##### {CONF}
  #####
  #
  # Tool name to be used in log prefix.
  # Leave blank to use only log type for prefix
  LOG_TOOLNAME="${LOG_TOOLNAME:-}"
  #
  # This three are used for logging (see logs functions description)
  # Available values:
  # * none    - don't log
  # * major   - log only major
  # * minor   - log everything
  # If not defined or values misspelled, defaults to 'major'
  LOG_INFO_LEVEL="${LOG_INFO_LEVEL-major}"
  LOG_WARN_LEVEL="${LOG_WARN_LEVEL-major}"
  LOG_ERR_LEVEL="${LOG_ERR_LEVEL-major}"
  #
  # Profiler
  PROFILER_ENABLED="${PROFILER_ENABLED-false}"
  #
  #####
  ##### {/CONF}

  # FUNCTIONS:
  # * file2dest [-f] [--tag TAG] [--tag-prefix TAG_PREFIX] [--] SOURCE [DEST...]
  # * print_stderr MSG...               (stdin MSG is supported)
  # * print_stdout MSG...               (stdin MSG is supported)
  # * log_* [-t LEVEL_TAG] [--] MSG...  (stdin MSG is supported)
  # * text_ltrim TEXT...    (stdin TEXT is supported)
  # * text_rtrim TEXT...    (stdin TEXT is supported)
  # * text_trim TEXT...     (stdin TEXT is supported)
  # * text_rmblank TEXT...  (stdin TEXT is supported)
  # * text_clean TEXT...    (stdin TEXT is supported)
  # * text_decore TEXT...   (stdin TEXT is supported)
  # * trap_help_opt ARG...
  # * trap_fatal [--decore] [--] RC [MSG...]
  # * tag_node_set [--prefix PREFIX] [--suffix SUFFIX] [--] TAG CONTENT TEXT...
  #   (stdin TEXT is supported)
  # * tag_node_get [--prefix PREFIX] [--suffix SUFFIX] [--strip] [--] TAG TEXT...
  #   (stdin TEXT is supported)
  # * tag_node_rm [--prefix PREFIX] [--suffix SUFFIX] [--] TAG TEXT...
  #   (stdin TEXT is supported)
  # * rc_add INIT_RC ADD_RC
  # * rc_has INIT_RC CHECK_RC
  # * check_bool VALUE
  # * check_unix_login VALUE
  # * check_ip4 VALUE
  # * check_loopback_ip4 VALUE
  # * gen_rand [--len LEN] [--num] [--special] [--uc]
  # * uniq_ordered [-r] -- FILE...      (stdin FILE_TEXT is supported)
  # * template_compile [-o] [-f] [-s] [--KEY VALUE...] [--] FILE...
  #   (stdin FILE_TEXT is supported)
  # * sed_quote_pattern PATTERN         (stdin PATTERN is supported)
  # * sed_quote_replace REPLACE         (stdin REPLACE is supported)

  ##############################
  ##### PRINTING / LOGGING #####
  ##############################

  # Print SOURCE file to DEST files. Logging via stderr
  # with prefixed DEST. Prefixes:
  # '{{ success }}' - successfully generated
  # '{{ skipped }}' - already exists, not overridden
  # '{{ failed }}'  - failed to generate files
  #
  # OPTIONS
  # =======
  # --            End of options
  # -f, --force   Force override if DEST exists
  # --tag         Tag to put content to
  # --tag-prefix  Prefix for tag, must be comment symbol, defaults to '#'
  #
  # USAGE:
  #   file2dest [-f] [--tag TAG] [--tag-prefix TAG_PREFIX] [--] SOURCE [DEST...]
  # RC:
  #   * 0 - all is fine
  #   * 1 - some of destinations are skipped
  #   * 2 - some of destinations are not created
  #   * 4 - source can't be read, fatal, provides no output
  # DEMO:
  #   # copy to files and address all kinds of logs
  #   file2dest ./lib.sh ./libs/lib{0..9}.sh /dev/null/subzero ~/.bashrc \
  #   2> >(
  #     tee \
  #       >(template_compile -o -f --success 'Success: ' | log_info) \
  #       >(template_compile -o -f --skipped 'Skipped: ' | log_warn) \
  #       >(template_compile -o -f --failed 'Failed: ' | log_err) \
  #       >/dev/null
  #   ) | cat
  file2dest() {
    local source
    local SOURCE_TXT
    local -a DESTS
    local FORCE=false
    local TAG
    local TAG_PREFIX='#'

    local endopts=false
    local arg; while :; do
      [[ -n "${1+x}" ]] || break
      ${endopts} && arg='*' || arg="${1}"

      case "${arg}" in
        --            ) endopts=true ;;
        -f|--force    ) FORCE=true ;;
        --tag         ) shift; TAG="${1}" ;;
        --tag-prefix  ) shift; TAG_PREFIX="${1}" ;;
        *             )
          [[ -z "${source+x}" ]] \
            && source="${1}" || DESTS+=("${1}")
        ;;
      esac

      shift
    done

    SOURCE_TXT="$(cat -- "${source}" 2>/dev/null)" || return 4

    [[ ${#DESTS[@]} -lt 1 ]] && DESTS+=(/dev/stdout)

    local dir
    local real
    local dest_content
    local rc=0
    local f; for f in "${DESTS[@]}"; do
      real="$(realpath -m -- "${f}" 2>/dev/null)"

      ! ${FORCE} && [[ -f "${real}" ]] && {
        rc=$(rc_add ${rc} 1)
        print_stderr "{{ skipped }}${f}"
        continue
      }

      dir="$(dirname -- "${f}" 2>/dev/null)" \
      && mkdir -p -- "${dir}" 2>/dev/null

      [[ -n "${TAG}" ]] && {
        [[ -f "${f}" ]] && dest_content="$(cat "${f}" 2>/dev/null)"
        SOURCE_TXT="$(
          tag_node_set --prefix "${TAG_PREFIX} {" --suffix '}' \
            -- "${TAG}" "${SOURCE_TXT}" "${dest_content}"
        )"
      }

      (cat <<< "${SOURCE_TXT}" > "${f}") 2>/dev/null && {
        # don't bother logging for generated to stdout and other devnulls
        if [[ -f ${real} ]]; then print_stderr "{{ success }}${f}"; fi
      } || {
        rc=$(rc_add ${rc} 2)
        print_stderr "{{ failed }}${f}"
        continue
      }
    done

    return ${rc}
  }

  print_stderr() {
    print_stdout "${@}" >/dev/stderr
  }

  print_stdout() {
    [[ ${#} -gt 0 ]] && printf -- '%s\n' "${@}" || cat
  }

  # Log to stderr prefixed with ${LOG_TOOLNAME} and log type
  #
  # OPTIONS
  # =======
  # --          End of options
  # -t, --tag   Log level tag. Available: major, minor
  #             Defaults to major
  #
  # USAGE
  #   log_* [-t LEVEL_TAG] [--] MSG...
  #   log_* [-t LEVEL_TAG] <<< MSG
  #   # combined with `text_decore`
  #   text_decore MSG... | log_* [-t LEVEL_TAG]
  # LEVELS
  #   # Configure level you want to log
  #   LOG_INFO_LEVEL=major
  #
  #   # ... some code here ...
  #
  #   # This will not log
  #   log_info -t minor "HELLO MINOR"
  #
  #   # And this will, as major is default
  #   log_info "HELLO MAJOR"
  #
  #   # This will never log
  #   LOG_INFO_LEVEL=none log_info "HELLO MAJOR"
  log_info() {
    LEVEL="${LOG_INFO_LEVEL}" \
    _log_type info "${@}"
  }
  log_warn() {
    LEVEL="${LOG_WARN_LEVEL}" \
    _log_type warn "${@}"
  }
  log_err() {
    LEVEL="${LOG_ERR_LEVEL}" \
    _log_type err "${@}"
  }

  _log_type() {
    local TYPE="${1}"
    local TAG=major
    local -a MSGS
    shift

    local endopts=false
    local arg; while :; do
      [[ -n "${1+x}" ]] || break
      ${endopts} && arg='*' || arg="${1}"

      case "${arg}" in
        --        ) endopts=true ;;
        -t|--tag  ) shift; TAG="${1:-${TAG}}" ;;
        *         ) MSGS+=("${1}") ;;
      esac

      shift
    done

    [[ "${TAG}" == none ]] && TAG=major
    LEVEL="${LEVEL:-major}"

    local -A level2num=( [none]=0 [major]=1 [minor]=2 )
    local req_level="${level2num["${LEVEL}"]:-${level2num[major]}}"
    local log_tag="${level2num["${TAG}"]:-${level2num[major]}}"

    # If reqired level is lower then current log tag, nothing to do here
    [[ ${req_level} -lt ${log_tag} ]] && return 0

    local prefix="${LOG_TOOLNAME:+"${LOG_TOOLNAME}:"}${TYPE}"
    print_stdout "${MSGS[@]}" | sed -e 's/^/['"${prefix}"'] /' | print_stderr
  }

  ################
  ##### TEXT #####
  ################

  text_ltrim() {
    print_stdout "${@}" | sed 's/^\s\+//'
  }

  text_rtrim() {
    print_stdout "${@}" | sed 's/\s\+$//'
  }

  text_trim() {
    print_stdout "${@}" | sed -e 's/^\s\+//' -e 's/\s\+$//'
  }

  # remove blank and space only lines
  text_rmblank() {
    print_stdout "${@}" | grep -vx '\s*'
    return 0
  }

  # apply trim and rmblank
  text_clean() {
    text_trim "${@}" | text_rmblank
    return 0
  }

  # Decoreate text:
  # * apply clean
  # * remove starting '.'
  # Prefix line with '.' to preserve empty line or offset
  #
  # USAGE
  #   text_decore MSG...
  #   text_decore <<< MSG
  text_decore() {
    text_clean "${@}" | sed 's/^\.//'
  }

  ####################
  ##### TRAPPING #####
  ####################

  # Detect one of help options: -h, -?, --help
  #
  # USAGE:
  #   trap_help_opt ARG...
  # RC:
  #   * 0 - help option detected
  #   * 1 - no help option
  #   * 2 - help option detected, but there are extra args,
  #         invalid args are printed to stdout
  trap_help_opt() {
    local is_help=false

    [[ "${1}" =~ ^(-h|-\?|--help)$ ]] \
      && is_help=true && shift

    local -a inval
    while :; do
      [[ -n "${1+x}" ]] || break
      inval+=("${1}")
      shift
    done

    ! ${is_help} && return 1

    ${is_help} && [[ ${#inval[@]} -gt 0 ]] && {
      print_stdout "${inval[@]}"
      return 2
    }

    return 0
  }

  # Exit with RC if it's > 0. If no MSG, no err message will be logged.
  # * RC is required to be numeric!
  # * not to be used in scripts sourced to ~/.bashrc!
  #
  # Options:
  #   --decore  - apply text_decore over input messages
  # USAGE:
  #   trap_fatal [--decore] [--] RC [MSG...]
  trap_fatal() {
    local rc
    local -a msgs
    local decore=false

    local endopts=false
    local arg; while :; do
      [[ -n "${1+x}" ]] || break
      ${endopts} && arg='*' || arg="${1}"
      case "${arg}" in
        --        ) endopts=true ;;
        --decore  ) decore=true ;;
        *         ) [[ -z "${rc+x}" ]] && rc="${1}" || msgs+=("${1}") ;;
      esac
      shift
    done

    [[ -n "${rc+x}" ]] || return 0
    [[ $rc -gt 0 ]] || return ${rc}

    [[ ${#msgs[@]} -gt 0 ]] && {
      local filter=(print_stdout)
      ${decore} && filter=(text_decore)
      "${filter[@]}" "${msgs[@]}" | _log_type fatal
    }

    exit ${rc}
  }

  ################
  ##### TAGS #####
  ################

  # USAGE:
  #   tag_node_set [--prefix PREFIX] [--suffix SUFFIX] \
  #     [--] TAG CONTENT TEXT...
  #   tag_node_set [--prefix PREFIX] [--suffix SUFFIX] \
  #     [--] TAG CONTENT <<< TEXT
  tag_node_set() {
    local tag
    local content
    local text
    local prefix
    local suffix

    local endopts=false
    local arg; while :; do
      [[ -n "${1+x}" ]] || break
      ${endopts} && arg='*' || arg="${1}"

      case "${arg}" in
        --        ) endopts=true ;;
        --prefix  ) shift; prefix="${1}" ;;
        --suffix  ) shift; suffix="${1}" ;;
        *         )
          if [[ -z "${tag+x}" ]]; then
            tag="${1}"
          elif [[ -z "${content+x}" ]]; then
            content="${1}"
          else
            text+="${text:+$'\n'}${1}"
          fi
          ;;
      esac

      shift
    done

    [[ -n "${text+x}" ]] || text="$(cat)"

    local open="$(_tag_mk_openline "${tag}" "${prefix}" "${suffix}")"
    local close="$(_tag_mk_closeline "${tag}" "${prefix}" "${suffix}")"

    local add_text
    add_text="$(printf '%s\n%s\n%s\n' \
      "${open}" "$(sed 's/^/  /' <<< "${content}")" "${close}")"

    local range
    range="$(_tag_get_lines_range "${open}" "${close}" "${text}")" || {
      printf '%s\n' "${text:+${text}$'\n'}${add_text}"
      return
    }

    head -n "$(( ${range%%,*} - 1 ))" <<< "${text}"
    printf '%s\n' "${add_text}"
    tail -n +"$(( ${range##*,} + 1 ))" <<< "${text}"
  }

  # USAGE:
  #   tag_node_get [--prefix PREFIX] [--suffix SUFFIX] \
  #     [--strip] [--] TAG TEXT...
  #   tag_node_get [--prefix PREFIX] [--suffix SUFFIX] \
  #     [--strip] [--] TAG <<< TEXT
  # RC:
  #   0 - all is fine content is returned
  #   1 - tag not found
  tag_node_get() {
    local tag
    local text
    local prefix
    local suffix
    local strip=false

    local endopts=false
    local arg; while :; do
      [[ -n "${1+x}" ]] || break
      ${endopts} && arg='*' || arg="${1}"

      case "${arg}" in
        --        ) endopts=true ;;
        --prefix  ) shift; prefix="${1}" ;;
        --suffix  ) shift; suffix="${1}" ;;
        --strip   ) strip=true ;;
        *         )
          [[ -n "${tag+x}" ]] \
            && text+="${text+$'\n'}${1}" \
            || tag="${1}"
          ;;
      esac

      shift
    done

    [[ -n "${text+x}" ]] || text="$(cat)"

    local open="$(_tag_mk_openline "${tag}" "${prefix}" "${suffix}")"
    local close="$(_tag_mk_closeline "${tag}" "${prefix}" "${suffix}")"

    local range
    range="$(_tag_get_lines_range "${open}" "${close}" "${text}")" || {
      return 1
    }

    local -a filter=(cat)
    ${strip} && filter=(sed -e '1d;$d;s/^  //')

    sed -e "${range}!d" <<< "${text}" | "${filter[@]}"
  }

  # USAGE:
  #   tag_node_rm [--prefix PREFIX] \
  #     [--suffix SUFFIX] [--] TAG TEXT...
  #   tag_node_rm [--prefix PREFIX] \
  #     [--suffix SUFFIX] [--] TAG <<< TEXT
  # RC:
  #   0 - all is fine content is returned
  #   1 - tag not found
  tag_node_rm() {
    local tag
    local text
    local prefix
    local suffix

    local endopts=false
    local arg; while :; do
      [[ -n "${1+x}" ]] || break
      ${endopts} && arg='*' || arg="${1}"

      case "${arg}" in
        --        ) endopts=true ;;
        --prefix  ) shift; prefix="${1}" ;;
        --suffix  ) shift; suffix="${1}" ;;
        *         )
          [[ -n "${tag+x}" ]] \
            && text+="${text+$'\n'}${1}" \
            || tag="${1}"
          ;;
      esac

      shift
    done

    [[ -n "${text+x}" ]] || text="$(cat)"

    local open="$(_tag_mk_openline "${tag}" "${prefix}" "${suffix}")"
    local close="$(_tag_mk_closeline "${tag}" "${prefix}" "${suffix}")"

    local range
    range="$(_tag_get_lines_range "${open}" "${close}" "${text}")" || {
      print_stdout "${text}"
      return 1
    }

    sed -e "${range}d" <<< "${text}"
  }

  # RC > 0 or comma separated open and close line numbers
  _tag_get_lines_range() {
    local open="${1}"
    local close="${2}"
    local text="${3}"

    local close_rex
    close_rex="$(sed_quote_pattern "${close}")"

    local lines_numbered
    lines_numbered="$(
      grep -m 1 -n -A 9999999 -Fx "${open}" <<< "${text}" \
      | grep -m 1 -B 9999999 -e "^[0-9]\+-${close_rex}$"
    )" || return $?

    sed -e 's/^\([0-9]\+\).*/\1/' -n -e '1p;$p' <<< "${lines_numbered}" \
    | xargs | tr ' ' ','
  }

  _tag_mk_openline() {
    local tag="${1}"
    local prefix="${2}"
    local suffix="${3}"
    printf -- '%s' "${prefix}${tag}${suffix}"
  }

  _tag_mk_closeline() {
    local tag="${1}"
    local prefix="${2}"
    local suffix="${3}"
    printf -- '%s' "${prefix}/${tag}${suffix}"
  }

  #######################
  ##### RETURN CODE #####
  #######################

  rc_add() {
    echo $(( ${1} | ${2} ))
  }

  rc_has() {
    [[ $(( ${1} & ${2} )) -eq ${2} ]]
  }

  ######################
  ##### VALIDATION #####
  ######################

  check_bool() {
    [[ "${1}" =~ ^(true|false)$ ]]
  }

  check_unix_login() {
    # https://unix.stackexchange.com/questions/157426/what-is-the-regex-to-validate-linux-users
    local rex='[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)'
    grep -qEx -- "${rex}" <<< "${1}"
  }

  check_ip4() {
    local seg_rex='(0|[1-9][0-9]*)'

    grep -qxE "(${seg_rex}\.){3}${seg_rex}" <<< "${1}" || return 1

    local segments
    mapfile -t segments <<< "$(tr '.' '\n' <<< "${1}")"
    local seg; for seg in "${segments[@]}"; do
      [[ "${seg}" -gt 255 ]] && return 1
    done

    return 0
  }

  check_loopback_ip4() {
    check_ip4 "${1}" && grep -q '^127' <<< "${1}"
  }

  #####################
  ##### PROFILING #####
  #####################

  profiler_init() {
    ${PROFILER_ENABLED-false} || return
    [[ -n "${PROFILER_TIMESTAMP}" ]] && return

    PROFILER_TIMESTAMP=$(( $(date +%s%N) / 1000000 ))
    export PROFILER_TIMESTAMP
  }

  profiler_run() {
    ${PROFILER_ENABLED-false} || return
    [[ -n "${PROFILER_TIMESTAMP}" ]] || return

    local message="${1}"

    local time=$(( ($(date +%s%N) / 1000000) - ${PROFILER_TIMESTAMP} ))

    {
      printf '%6s.%03d' $(( time / 1000 )) $(( time % 1000 ))
      [[ -n "${message}" ]] \
        && printf ' %s\n' "${message}" \
        || printf '\n'
    } | _log_type profile
  }

  ################
  ##### MISC #####
  ################

  # Generate a random value, lower case latters only by default
  # https://unix.stackexchange.com/a/230676
  #
  # OPTIONS
  # =======
  # --len       Value length, defaults to 10
  # --num       Include numbers
  # --special   Include special characters
  # --uc        Include upper case
  #
  # USAGE:
  #   gen_rand [--len LEN] [--num] [--special] [--uc]
  gen_rand() {
    local len=10
    local num=false
    local special=false
    local uc=false
    local filter='a-z'

    while :; do
      [[ -n "${1+x}" ]] || break
      case "${1}" in
        --len     ) shift; len="${1}" ;;
        --num     ) num=true ;;
        --special ) special=true ;;
        --uc      ) uc=true ;;
      esac
      shift
    done

    ${num} && filter+='0-9'; ${uc} && filter+='A-Z'
    ${special} && filter+='!"#$%&'\''()*+,-./:;<=>?@[\]^_`{|}~'
    LC_ALL=C tr -dc "${filter}" </dev/urandom | fold -w "${len}" | head -n 1
  }

  # Get unique lines preserving lines order. By default top unique
  # lines are prioritized
  #
  # OPTIONS
  # =======
  # --              End of options
  # -r, --reverse   Prioritize bottom unique values
  #
  # USAGE:
  #   uniq_ordered [-r] -- FILE...
  #   uniq_ordered [-r] <<< FILE_TEXT
  uniq_ordered() {
    local -a revfilter=(cat)
    local -a files

    local endopts=false
    local arg; while :; do
      [[ -n "${1+x}" ]] || break
      ${endopts} && arg='*' || arg="${1}"

      case "${arg}" in
        --            ) endopts=true ;;
        -r|--reverse  ) revfilter=(tac) ;;
        *             ) files+=("${1}") ;;
      esac

      shift
    done

    # https://unix.stackexchange.com/a/194790
    cat "${files[@]}" | "${revfilter[@]}" \
    | cat -n | sort -k2 -k1n | uniq -f1 | sort -nk1,1 | cut -f2- \
    | "${revfilter[@]}"
  }

  # Compile template FILE replacing '{{ KEY }}' with VALUE.
  # In case of duplicated --KEY option last wins. Nothing
  # happens if FILE path is invalid.
  # Limitations:
  # * multiline KEY and VALUE are not allowed
  #
  # OPTIONS
  # =======
  # --  End of options
  # -o  Only output affected lines
  # -f  Substitute KEY only when it's first thing in the line
  # -s  Substitute only single occurrence
  #
  # USAGE:
  #   template_compile [-o] [-f] [-s] [--KEY VALUE...] [--] FILE...
  #   template_compile [-o] [-f] [-s] [--KEY VALUE...] <<< FILE_TEXT
  # Demo:
  #   # outputs: "account=varlog, password=changeme"
  #   template_compile --user varlog --pass changeme \
  #     <<< "login={{ user }}, password={{ pass }}"
  template_compile() {
    local -a files
    local -A kv
    local first=false
    local single=false
    local only=false

    local endopts=false
    local arg; while :; do
      [[ -n "${1+x}" ]] || break
      ${endopts} && arg='*' || arg="${1}"

      case "${arg}" in
        --  ) endopts=true ;;
        -o  ) only=true ;;
        -f  ) first=true ;;
        -s  ) single=true ;;
        --* ) shift; kv[${arg:2}]="${1}" ;;
        *   ) files+=("${1}") ;;
      esac

      shift
    done

    local key
    local value
    for key in "${!kv[@]}"; do
      value="$(sed_quote_replace "${kv["${key}"]}")"
      kv["${key}"]="${value}"
    done

    local template
    template="$(cat -- "${files[@]}" 2>/dev/null)"

    local -a filter
    local expression
    if ${only}; then
      for key in "${!kv[@]}"; do
        # https://www.cyberciti.biz/faq/unix-linux-sed-print-only-matching-lines-command/
        filter=(sed)
        key="$(sed_quote_pattern "${key}")"
        expression="{{\s*${key}\s*}}/${kv["${key}"]}"
        ${first} && expression="^${expression}"
        expression="s/${expression}/"
        ! ${single} && expression+='g'
        ${only} && filter+=(-n) && expression+='p'
        filter+=("${expression}")

        template="$("${filter[@]}" <<< "${template}")"
      done
    else
      # lighter than with ONLY option

      # initially passthrough filter
      filter=(sed -e 's/^/&/')

      for key in "${!kv[@]}"; do
        key="$(sed_quote_pattern "${key}")"
        expression="{{\s*${key}\s*}}/${kv["${key}"]}"
        ${first} && expression="^${expression}"
        filter+=(-e "s/${expression}/g")
      done

      template="$("${filter[@]}" <<< "${template}")"
    fi

    [[ -n "${template}" ]] && cat <<< "${template}"
  }

  # https://gist.github.com/varlogerr/2c058af053921f1e9a0ddc39ab854577#file-sed-quote
  sed_quote_pattern() {
    sed -e 's/[]\/$*.^[]/\\&/g' <<< "${1-$(cat)}"
  }
  sed_quote_replace() {
    sed -e 's/[\/&]/\\&/g' <<< "${1-$(cat)}"
  }

  ##########################
  ##### OVERRIDES DEMO #####
  ##########################

  # ## In most cases it's the first candidate for override
  #
  # eval "$(typeset -f file2dest | sed '1s/ \?(/_overriden_ (/')"
  # file2dest() {
  #   # https://unix.stackexchange.com/a/43536
  #   file2dest_overriden_ "${@}" \
  #   2> >(
  #     tee \
  #       >(template_compile -o -f --success 'Success: ' | log_info) \
  #       >(template_compile -o -f --skipped 'Skipped: ' | log_warn) \
  #       >(template_compile -o -f --failed 'Failed: ' | log_err) \
  #       >/dev/null
  #   ) | cat
  #
  #   # https://unix.stackexchange.com/a/73180
  #   return "${PIPESTATUS[0]}"
  # }

  # ## A lighter version of tags, less secure, but fine for personal data
  # ## sets. Disregards suffix and prefix, suffix is hardcoded to '#'
  #
  #_tag_mk_openline() { printf -- '%s' "#${1}"; }
  #_tag_mk_closeline() { printf -- '%s' "#${1}"; }
  #_tag_get_lines_range() {
  #  local open="${1}"
  #  local close="${2}"
  #
  #  local lines_numbered
  #  lines_numbered="$(grep -m 2 -n -Fx "${open}" <<< "${text}")" || return $?
  #
  #  sed -e 's/^\([0-9]\+\).*/\1/' -n -e '1p;$p' <<< "${lines_numbered}" \
  #  | xargs | tr ' ' ','
  #}
# {/SHLIB_GEN}

# {SHLIB_OVERRIDES}
eval "$(typeset -f file2dest | sed '1s/ \?(/_overriden_ (/')"
file2dest() {
  file2dest_overriden_ "${@}" \
  2> >(
    tee \
      >(template_compile -o -f --success 'Success: ' | log_info) \
      >(template_compile -o -f --skipped 'Skipped: ' | log_warn) \
      >(template_compile -o -f --failed 'Failed: ' | log_err) \
      >/dev/null
  ) | cat

  return "${PIPESTATUS[0]}"
}
# {/SHLIB_OVERRIDES}

declare SELF_PATH
declare SELF_TXT
SELF_PATH="$(realpath "${BASH_SOURCE[0]}")"
SELF_TXT="$(cat -- "${SELF_PATH}")" || {
  echo "${SELF_PATH} is unreadable"
  exit 1
}

declare -A DEF=(
  # myssl conf only defaults
  [self-path]="$(realpath -- "${0}")"
  [base-dir]='$(dirname -- "${0}")'
  [certs-dir]='${BASE_DIR}/certs'
  [ca-dir]='${BASE_DIR}/ca'
  [out-prefix]='${CERTS_DIR}/$(basename -s .sh -- "${0}")'
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

# tag and template functions
{
  # USAGE:
  #   tag_comment_get TAG TEXT...
  #   tag_comment_get TAG <<< TEXT
  tag_comment_get() {
    local tag="${1}"
    shift
    tag_node_get --prefix '# {' --suffix '}' -- "${tag}" "${@}"
  }

  # USAGE:
  #   tag_comment_strip_filter TAG <<< TEXT
  tag_comment_strip_filter() {
    local tag="${1}"
    local tag_pattern="$(sed_quote_pattern "# {${tag}${suffix}}")"
    sed -e '1s/^'"${tag_pattern}"'$/#&/' \
        -e '$s/^'"${tag_pattern}"'$/#&/' \
        -e 's/^# \?//' -e '1d;$d'
  }

  get_body() {
    local txt="${1}"
    local ignore_tag='# {TPL_MYSSL_CONF}'

    grep -A 999999 -Fx -- "${ignore_tag}" <<< "${txt}"
  }
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
    local overkeys_rex="$(text_decore "
      issuer-key
      issuer-cert
      days
      cn
      country
      state
      locality
      org
      org-unit
      email
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
      && trap_fatal --decore -- 1 "
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

[[ ${#ERRBAG} -lt 1 ]] || trap_fatal --decore -- $? "
    Unsupported or conflicting arguments:
    $(printf -- '* %s\n' "${ERRBAG[@]}" | sort -n | uniq)
   .
    Issue \`${0} -h\` for help
  "

help_description() {
  text_decore "Generate certificates"
}

help_usage() {
  local tool="$(basename -- "${0}")"
  local tag=TPL_HELP_USAGE
  tag_comment_get "${tag}" "${SELF_TXT}" \
  | tag_comment_strip_filter "${tag}" \
  | template_compile --tool "${tool}"
}

help_opts() {
  local tag=TPL_HELP_OPTS
  tag_comment_get "${tag}" "${SELF_TXT}" \
  | tag_comment_strip_filter "${tag}" \
  | template_compile --days "${DEF[days]}" --cn "${DEF[cn]}"
}

help_env() {
  local tag=TPL_HELP_ENV_VARS
  tag_comment_get "${tag}" "${SELF_TXT}" \
  | tag_comment_strip_filter "${tag}"
}

help_demo() {
  local tool="$(basename -- "${0}")"
  local tag=TPL_HELP_DEMO
  tag_comment_get "${tag}" "${SELF_TXT}" \
  | tag_comment_strip_filter "${tag}" \
  | template_compile --tool "${tool}"
}

help_import() {
  local tag=TPL_HELP_IMPORT
  tag_comment_get "${tag}" "${SELF_TXT}" \
  | tag_comment_strip_filter "${tag}"
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

  local -a f2d_opts
  ${2} && f2d_opts+=(--force)

  shift; shift
  local -a dests=("${@}")
  local shebang='#!/usr/bin/env bash'
  local self_confblock
  local self_body
  local -a tpl_opts

  local k; for k in "${!DEF[@]}"; do
    tpl_opts+=("--${k}" "${DEF[$k]}")
  done

  self_body="$(get_body "${SELF_TXT}")"
  self_confblock="$(
    tag=TPL_MYSSL_CONF
    tag_comment_get "${tag}" "${self_body}" \
    | tag_comment_strip_filter "${tag}" \
    | template_compile "${tpl_opts[@]}"
  )"

  [[ ${#dests[@]} -gt 0 ]] || dests+=(/dev/stdout)

  local confblock
  local real
  for dest in "${dests[@]}"; do
    real="$(realpath -m -- "${dest}" 2>/dev/null)"

    [[ -f "${real}" ]] && confblock="$(
      cat -- "${dest}" 2>/dev/null \
      | tag_comment_get CONFBLOCK
    )"
    confblock="${confblock:-${self_confblock}}"

    file2dest "${f2d_opts[@]}" -- <(
      printf -- '%s\n\n%s\n\n%s\n' \
        "${shebang}" "${confblock}" "${self_body}"
    ) "${dest}"

    [[ ! -f "${real}" ]] && continue

    chmod 0755 -- "${dest}" 2>/dev/null \
      || log_warn "Can't chmod 0755: ${dest}"
  done

  exit 0
}; _confgen "${OPTS_CONFGEN[@]}" || exit $?

[[ -n "${CONF[out-prefix]}" ]] || trap_fatal --decore -- $? "
    Can't generate certificates.
    1. If you're using this script installed system wide:
   .  * Option 1: Use PREFIX argument of the command.
   .  * Option 2: generate a configuration, configure and
   .    execute it.
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

TMPDIR="$(/bin/mktemp -d --suffix "-$(basename -- "${0}")")" \
  || trap_fatal -- $? "Error creating temp directory"

[[ "${CONF[encrypt]}" =~ ^(true|false)$ ]] \
  || trap_fatal -- $? "Invalid ENCRYPT value: ${CONF[encrypt]}"
[[ "${CONF[merge]}" =~ ^(true|false)$ ]] \
  || trap_fatal -- $? "Invalid MERGE value: ${CONF[merge]}"

CONF[hosts]="$(text_clean "${CONF[hosts]}")"
CONF[issuer-key]="${CONF[issuer-key]:-${CONF[issuer-cert]}}"

OUTDIR="$(dirname -- "${CONF[out-prefix]}")"
TMPKEYFILE="${TMPDIR}/${filename}.key"
TMPCERTFILE="${TMPDIR}/${filename}.crt"
TMPREQFILE="${TMPDIR}/${filename}.csr"

KEYFILE="${OUTDIR}/${filename}.key"
CERTFILE="${OUTDIR}/${filename}.crt"
MERGEFILE="${OUTDIR}/${filename}.pem"

declare IS_CA=true
[[ -n "${CONF[hosts]}" ]] && IS_CA=false

declare -a check_files=("${KEYFILE}" "${CERTFILE}")
${CONF[merge]} && check_files=("${MERGEFILE}")

declare f; for f in "${check_files[@]}"; do
  ${CONF[force]} && break
  [[ -e "${f}" ]] && ERRBAG+=("${f}")
done

[[ ${#ERRBAG[@]} -lt 1 ]] || trap_fatal --decore -- $? "
  Files already exist:
  $(printf -- '* %s\n' "${ERRBAG[@]}")
"

MYSSL_KEYPASS="${MYSSL_KEYPASS-$(
  cat -- "${CONF[passfile]}" 2>/dev/null
)}" && CONF[passfile]=true

MYSSL_CA_KEYPASS="${MYSSL_CA_KEYPASS-$(
  cat -- "${CONF[ca_passfile]}" 2>/dev/null
)}" && CONF[ca_passfile]=true

trap "rm -f '${TMPDIR}'/*" SIGINT

# COMPOSE CONFFILE
declare TMPCONFFILE_CRT="${TMPDIR}/crt.cfg"
declare TMPCONFFILE_REQ="${TMPDIR}/req.cfg"
_mk_openssl_conffile() {
  unset _mk_openssl_conffile

  local -A dn_map=(
    [country]=C
    [state]=ST
    [locality]=L
    [org]=O
    [org-unit]=OU
    [email]=emailAddress
  )

  local -a dn_arr

  local i
  for i in "${!dn_map[@]}"; do
    [[ -n "${CONF[$i]}" ]] && dn_arr+=("${dn_map[$i]} = ${CONF[$i]}")
  done

  local conffile_txt
  conffile_txt="$(
    tag=TPL_OPENSSL_CONF
    tag_comment_get "${tag}" "${SELF_TXT}" \
    | tag_comment_strip_filter "${tag}" \
    | template_compile --is-ca "${IS_CA^^}" --cn "${CONF[cn]}"
  )"

  local lineno
  lineno="$(grep -m 1 -nFx '# DN_EXTRA_PH' <<< "${conffile_txt}")"
  [[ $? -lt 1 ]] && {
    conffile_txt="$(
      head -n $((${lineno%%:*} -1)) <<< "${conffile_txt}"
      [[ ${#dn_arr[@]} -gt 0 ]] && printf -- '%s\n' "${dn_arr[@]}"
      tail -n +$((${lineno%%:*} +1)) <<< "${conffile_txt}"
    )"
  }

  ${IS_CA} && {
    # CA certificate still needs an entry under SAN section
    # for valid conffile
    conffile_txt+=$'\n'"DNS.1 = localhost"
  } || {
    declare ips
    declare domains

    local -a vals
    [[ -n "${CONF[hosts]}" ]] && mapfile -t vals <<< "${CONF[hosts]}"
    local val; for val in "${vals[@]}"; do
      check_ip4 "${val}" && {
        ips+="${ips+$'\n'}${val}"
        continue
      }
      domains+="${domains+$'\n'}${val}"
    done

    conffile_txt+="${domains:+$'\n'$(
      cat -n <<< "${domains}" \
      | sed -E 's/^\s*([0-9]+)\s*/DNS.\1 = /')}${ips:+$'\n'$(
      cat -n <<< "${ips}" \
      | sed -E 's/^\s*([0-9]+)\s*/IP.\1 = /')}"
  }

  tee "${TMPCONFFILE_CRT}" <<< "${conffile_txt}" >/dev/null 2>&1 \
    || trap_fatal -- $? "Error creating temp cert conffile: ${TMPCONFFILE_CRT}"

  # there is no authority parameters while creating a request file
  grep -Ev '^authorityKeyIdentifier =' <<< "${conffile_txt}" \
  | tee "${TMPCONFFILE_REQ}" >/dev/null 2>&1 \
    || trap_fatal -- $? "Error creating temp req conffile: ${TMPCONFFILE_REQ}"
}; _mk_openssl_conffile

# CREATE KEY
_mk_pk() {
  unset _mk_pk

  log_info "Generating key ..."

  local -a cmd_key=(
    openssl genpkey -algorithm RSA -outform PEM
    -pkeyopt rsa_keygen_bits:4096 -out "${TMPKEYFILE}"
  )
  ${CONF[encrypt]} && cmd_key+=(-aes256)

  if [[ -n "${CONF[passfile]+x}" ]]; then
    "${cmd_key[@]}" -pass file:<(pass="${MYSSL_KEYPASS}" printenv pass)
  else
    "${cmd_key[@]}"
  fi
  trap_fatal -- $? "Couldn't generate key"
}; _mk_pk

if [[ -n "${CONF[issuer-cert]}" ]]; then
  # CREATE SCR AND SIGNED BY ISSUER CERT

  # in case CA key is passed via env var
  MYSSL_CA_KEY="${MYSSL_CA_KEY-$(cat -- "${CONF[issuer-key]}" 2>/dev/null)}"

  cmd_req=(
    openssl req -new -key "${TMPKEYFILE}"
    -out "${TMPREQFILE}" -config "${TMPCONFFILE_REQ}"
  )
  cmd_cert=(
    openssl x509 -req -in "${TMPREQFILE}"
    -CA "${CONF[issuer-cert]}" -CAcreateserial
    -out "${TMPCERTFILE}" -days "${CONF[days]}"
    -extfile "${TMPCONFFILE_CRT}"
  )
  # either server cert or intermediate
  ${IS_CA} \
    && cmd_cert+=(-extensions 'ca-ext') \
    || cmd_cert+=(-extensions 'req-ext')

  {
    log_info "Generating CSR file ..."
    if [[ -n "${CONF[passfile]+x}" ]]; then
      "${cmd_req[@]}" -passin file:<(cat - <<< "${MYSSL_KEYPASS}")
    else
      "${cmd_req[@]}"
    fi
    trap_fatal -- $? "Couldn't generate CSR file"
  }

  {
    log_info "Generating cert ..."
    if [[ -n "${CONF[ca_passfile]+x}" ]]; then
      "${cmd_cert[@]}" \
        -CAkey <(cat - <<< "${MYSSL_CA_KEY}") \
        -passin file:<(cat - <<< "${MYSSL_CA_KEYPASS}")
    else
      "${cmd_cert[@]}" -CAkey <(cat - <<< "${MYSSL_CA_KEY}")
    fi
    trap_fatal -- $? "Couldn't generate cert"
  }

  {
    log_info "Creating certificate bundle ..."
    # https://serverfault.com/a/755815
    issuer_pkcs7="$(openssl crl2pkcs7 -nocrl -certfile "${CONF[issuer-cert]}")"
    trap_fatal -- $? "Can't parse ISSUER_CERT"

    openssl pkcs7 -print_certs <<< "${issuer_pkcs7}" | grep -v \
      -e '^\s*$' -e '\s=\s' -e '^\s*subject=[^=]' -e '^\s*issuer=[^=]' \
    | tee -a "${TMPCERTFILE}" >/dev/null
    trap_fatal -- $? "Couldn't create bundle"
  }

  log_info "Vertifying cert against CA ..."
  openssl verify -CAfile "${CONF[issuer-cert]}" "${TMPCERTFILE}"
  trap_fatal -- $? "Verification failed"
else
  # CREATE SELF-SIGNED CERT

  cmd_cert=(
    openssl req -new -x509 -key "${TMPKEYFILE}"
    -days "${CONF[days]}" -out "${TMPCERTFILE}"
    -config "${TMPCONFFILE_CRT}"
  )
  ${IS_CA} || cmd_cert+=(-extensions 'req-ext')

  {
    log_info "Generating cert ..."
    if [[ -n "${CONF[passfile]+x}" ]]; then
      "${cmd_cert[@]}" -passin file:<(cat - <<< "${MYSSL_KEYPASS}")
    else
      "${cmd_cert[@]}"
    fi
    trap_fatal -- $? "Couldn't generate cert"
  }
fi

_final() {
  unset _final

  [[ (-f "${TMPCERTFILE}" && -f "${TMPKEYFILE}") ]] || return 1

  mkdir -p -- "${OUTDIR}"
  trap_fatal -- $? "Couldn't create destination directory: ${OUTDIR}"

  if ${CONF[merge]}; then
    log_info "Merging key into cert ..."
    cat -- "${TMPKEYFILE}" >> "${TMPCERTFILE}"
    trap_fatal -- $? "Couldn't merge to ${TMPCERTFILE}"
    chmod 0600 -- "${TMPCERTFILE}"
    trap_fatal -- $? "Couldn't chmod 0600 ${TMPCERTFILE}"
    CERTFILE="${MERGEFILE}"
  else
    chmod 0600 -- "${TMPKEYFILE}"
    mv -- "${TMPKEYFILE}" "${KEYFILE}"
    trap_fatal -- $? "Couldn't move to ${KEYFILE}"
  fi
  mv -- "${TMPCERTFILE}" "${CERTFILE}"
  trap_fatal -- $? "Couldn't move to ${CERTFILE}"

  rm -f "${TMPDIR}"/*

  text_decore "
    Generated to $(realpath -- "${OUTDIR}")
    DONE
  " | log_info
}; _final || trap_fatal -- $? "Something went wrong"

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
