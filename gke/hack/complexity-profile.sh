#!/bin/sh -e

script_dir="$(dirname -- "$0")"
kernel_version="$1"
[ -z "$kernel_version" ] && kernel_version="$(uname -r | cut -d'.' -f1,2)"
dirs="$(find $script_dir/../../bpf/complexity-tests -maxdepth 1 -mindepth 1 -type d ! -name netnext -printf '%f\n')"
profiles="$(printf '%s' "$dirs" | sed 's/./&./' | sort -V -r)"

# fails if left version < right version
vercomp_ge() {
  for i in $(seq 1 2); do
    v1s=$(echo $1 | cut -d '.' -f $i)
    v2s=$(echo $2 | cut -d '.' -f $i)
    if [ $v1s -gt $v2s ]; then
      return 0
    elif [ $v1s -lt $v2s ]; then
      return 1
    fi
  done
  return 0
}

complexity_profile() {
  for p in $profiles; do
    if vercomp_ge $1 $p; then
      echo "$p"
      return 0
    fi
  done
  # fallback to the oldest kernel profile
  echo $profiles | awk '{print $NF}'
}

complexity_profile $kernel_version | tr -d '.'
