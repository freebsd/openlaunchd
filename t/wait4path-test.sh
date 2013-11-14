#!/bin/sh

describe "wait4path"

COMMAND=./wait4path/wait4path
USAGE="usage: ${COMMAND} <object on mount point>"

runit() {
    ${COMMAND} 2>&1 $@
}

validate_usage() {
    test "$1" = "$USAGE"
}

it_shows_usage_by_default() {
    validate_usage "$(runit)"
}
