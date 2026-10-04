#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# For a guest that reports its own exit status on the console instead of
# through semihosting (see PL011_CONSOLE in tests/tcg/aarch64/system/boot.S):
# QEMU's exit code then says nothing about the test, so read the verdict from
# the "exit status N" line the guest prints last.

set -uo pipefail

if [ $# -lt 1 ]; then
    echo "run_and_check_exit_status: cmd [args]..." 1>&2
    exit 1
fi
output=$("$@" 2>&1)
echo "$output"
if echo "$output" | grep -qx "exit status 0"; then
    exit 0
fi
echo "guest did not report exit status 0" 1>&2
exit 1
