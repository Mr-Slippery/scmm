#!/usr/bin/env bash
set -euxo pipefail

../../target/release/scmm-compile -i policy.yaml -o policy.scmm-pol
../../target/release/scmm-enforce -vv -p policy.scmm-pol -- nginx -p . -c conf/nginx.conf
