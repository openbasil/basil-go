_default:
    @just --list

# run all examples
run-examples:
    #!/usr/bin/env bash
    set -euo pipefail

    for script in examples/*/run.sh; do
      echo "== running ${script}"
      (cd "$(dirname "${script}")" && ./run.sh)
    done
