#!/bin/bash
# Records what the old programs print (#123 Part 1, Acceptance 3): run once,
# on origin/console 42e3572, BEFORE their code moved to internal/cli:
#
#   go build -o BIN/ ./cmd/sbxkey ./cmd/sbxverify ./cmd/sbxapi
#   internal/cli/keycmd/testdata/record-legacy.sh BIN
#
# Each case runs with argv[0] the program's name, in a clean environment
# (HOME=/nonexistent XDG_CONFIG_HOME= SBXKEY_DIR=), stdin /dev/null, from /.
# Its stdout, stderr and exit status go to internal/cli/*/testdata/legacy,
# which TestLegacyOutput in each package compares byte for byte with what
# the programs built now print. The recorded files are never re-recorded to
# make a test pass: the code is changed until it prints them.
set -u
B=${1:?usage: record-legacy.sh BINDIR}
cli=$(cd "$(dirname "$0")/../.." && pwd)
run() { # run PACKAGE CASE TOOL ARGS...
	local o=$cli/$1/testdata/legacy name=$2 tool=$3; shift 3
	mkdir -p "$o"
	(cd / && env -i PATH=/usr/bin:/bin HOME=/nonexistent XDG_CONFIG_HOME= SBXKEY_DIR= \
		/bin/bash -c 'exec -a "$0" "$@"' "$tool" "$B/$tool" "$@") </dev/null >"$o/$name.stdout" 2>"$o/$name.stderr"
	echo $? >"$o/$name.code"
}
run keycmd sbxkey sbxkey
run keycmd sbxkey-h sbxkey -h
run keycmd sbxkey-start sbxkey start
run keycmd sbxkey-keys sbxkey keys
run keycmd sbxkey-unlock-web sbxkey unlock web
run verifycmd sbxverify-h sbxverify -h
run verifycmd sbxverify sbxverify
run verifycmd sbxverify-x sbxverify -x
run apicmd sbxapi sbxapi
run apicmd sbxapi-exec-h sbxapi exec -h
run apicmd sbxapi-cp-h sbxapi cp -h
