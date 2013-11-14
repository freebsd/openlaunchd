#!/bin/sh

describe "wait4path"

it_shows_usage_by_default() {
    test "$(runit)" = "usage: ${COMMAND} <object on mount point>"
}

it_exits_for_existing_paths() {
    output=$(runit wait4path)
    assert_success $?
    assert_empty $output
}
it_exits_for_existing_mounts() {
    output=$(runit /)
    assert_success $?
    assert_empty $output
}

it_should_wait_for_mount() {
    # mkdir /tmp/foo && mdmfs -s 32m md /tmp/foo
    true
}

################################################################################

COMMAND=./wait4path/wait4path
source "t/assertions.sh"
