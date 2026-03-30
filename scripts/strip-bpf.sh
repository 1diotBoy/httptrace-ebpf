#!/usr/bin/env bash
set -euo pipefail

obj="${@: -1}"

llvm-strip -g "$obj"
llvm-objcopy \
  --remove-section .BTF \
  --remove-section .rel.BTF \
  --remove-section .BTF.ext \
  --remove-section .rel.BTF.ext \
  "$obj"
