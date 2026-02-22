#!/usr/bin/env bash
set -euxo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
O_DIR="${SCRIPT_DIR}/out_network_strace"

mkdir -p "${O_DIR}"
S_LOG="${O_DIR}/server.log"
S_YML="${O_DIR}/server.yaml"
S_POL="${O_DIR}/server.pol"
C_LOG="${O_DIR}/client.log"
C_YML="${O_DIR}/client.yaml"
C_POL="${O_DIR}/client.pol"
S_RECEIVED="${O_DIR}/enforce_server_received.txt"
S_ERROR="${O_DIR}/enforce_server_error.txt"
C_RECEIVED="${O_DIR}/enforce_client_received.txt"
C_ERROR="${O_DIR}/enforce_client_error.txt"
FROM_SERVER="from_server"
FROM_CLIENT="from_client"
S_CMD="nc -l 127.0.0.1 31337"
C_CMD="nc 127.0.0.1 31337"

ROOT="${SCRIPT_DIR}/../"

if ! command -v nc >/dev/null 2>&1; then
    echo "SKIP: test_network_strace — nc not installed"
    exit 0
fi
if ! command -v strace >/dev/null 2>&1; then
    echo "SKIP: test_network_strace — strace not installed"
    exit 0
fi

echo "${FROM_SERVER}" | strace -f -o "${S_LOG}" -s 1500 -- ${S_CMD} &
SR_PID=$!
sleep 1
echo "${FROM_CLIENT}" | strace -f -o "${C_LOG}" -s 1500 -- ${C_CMD} &
CR_PID=$!
sleep 1
S_PID=$(pgrep -f "^${S_CMD}")
C_PID=$(pgrep -f "^${C_CMD}")
ps -ef | grep nc | grep 127.0.0.1
sleep 2

set +e
kill -TERM "${C_PID}" "${S_PID}"
wait "${CR_PID}" "${SR_PID}"
set -e

"${ROOT}"target/release/scmm-extract -i "${S_LOG}" -o "${S_YML}" --non-interactive
"${ROOT}"target/release/scmm-compile -i "${S_YML}" -o "${S_POL}"
"${ROOT}"target/release/scmm-extract -i "${C_LOG}" -o "${C_YML}" --non-interactive
"${ROOT}"target/release/scmm-compile -i "${C_YML}" -o "${C_POL}"

echo "${FROM_SERVER}" | "${ROOT}"target/release/scmm-enforce -p "${S_POL}" -- \
    ${S_CMD} > "${S_RECEIVED}" 2> "${S_ERROR}" &
SE_PID=$!
sleep 1
echo "${FROM_CLIENT}" | "${ROOT}"target/release/scmm-enforce -p "${C_POL}" -- \
    ${C_CMD} > "${C_RECEIVED}" 2> "${C_ERROR}" &
CE_PID=$!
sleep 1

S_PID=$(pgrep -f "^${S_CMD}")
C_PID=$(pgrep -f "^${C_CMD}")

set +e
kill -TERM "${C_PID}" "${S_PID}"
wait "${CE_PID}" "${SE_PID}"
set -e

grep "${FROM_CLIENT}" "${S_RECEIVED}"
grep "${FROM_SERVER}" "${C_RECEIVED}"

WRONG_PORT_S_CMD="${S_CMD/31337/31338}"
WRONG_PORT_C_CMD="${C_CMD/31337/31338}"

echo "${FROM_SERVER}" | "${WRONG_PORT_S_CMD}" > "${S_RECEIVED}" 2> "${S_ERROR}" &
S_PID=$!
sleep 1
echo "${FROM_CLIENT}" | "${ROOT}"target/release/scmm-enforce -p "${C_POL}" -- \
    ${WRONG_PORT_C_CMD} > "${C_RECEIVED}" 2> "${C_ERROR}" &
CE_PID=$!
sleep 1

set +e
C_PID=$(pgrep -f "^${WRONG_PORT_C_CMD}")
set -e

if [ -n "${C_PID}" ]; then
  echo "Client should have died because of forbidden port."
  exit 1
fi

! grep "${FROM_SERVER}" "${C_RECEIVED}"

set +e
kill -TERM "${S_PID}"
wait "${S_PID}" "${CE_PID}"
set -e

echo "${FROM_SERVER}" | "${ROOT}"target/release/scmm-enforce -p "${S_POL}" -- \
    ${WRONG_PORT_S_CMD} > "${S_RECEIVED}" 2> "${S_ERROR}" &
SE_PID=$!
sleep 1

echo "${FROM_CLIENT}" | ${WRONG_PORT_C_CMD} &
C_PID=$!
sleep 1

set +e
S_PID=$(pgrep -f "^${WRONG_PORT_S_CMD}")
set -e

if [ -n "${S_PID}" ]; then
  echo "Server should have died because of forbidden port."
  exit 1
fi

! grep "${FROM_CLIENT}" "${S_RECEIVED}"

set +e
kill -TERM "${C_PID}"
wait "${C_PID}" "${SE_PID}"
set -e
