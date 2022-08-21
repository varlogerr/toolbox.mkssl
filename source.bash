_source_bash_() {
  unset _source_bash_
  [[ -n "${BASH_VERSION+x}" ]] || return

  local self="$(realpath "${BASH_SOURCE[0]}")"
  local BIND_DIR="$(dirname "${self}")/bin"

  [[ ":${PATH}:" == *":${BIND_DIR}:"* ]] && return

  [[ "${1}" == '--prepend' ]] \
    && PATH="${BIND_DIR}${PATH:+:${PATH}}" \
    || PATH+="${PATH:+:}${BIND_DIR}"
}; _source_bash_ "${@}"
