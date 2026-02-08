#!/usr/bin/env bash
set -euxo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
nginx -p "${SCRIPT_DIR}" -c "${SCRIPT_DIR}/nginx.conf"
