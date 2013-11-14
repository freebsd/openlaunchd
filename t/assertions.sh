#!/bin/sh

assert_empty() {
    test "$1" = ""
}

assert_success() {
    test $1 = 0
}

runit() {
    ${COMMAND} 2>&1 $@
}

