#!/bin/bash

set -e

STARTTIME=$(date +%s)
CODE_ROOT=$(dirname "${BASH_SOURCE}")/..
source "${CODE_ROOT}/hack/common.sh"
echo "Detected go version: $(go version)"

go get -u github.com/LK4D4/vndr

ret=$?; ENDTIME=$(date +%s); echo "$0 took $(($ENDTIME - $STARTTIME)) seconds"; exit "$ret"
