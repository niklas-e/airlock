#!/usr/bin/env bats

load helpers

setup_file() {
    require_vm_support
    if [[ ! -x "$AIRLOCK" ]]; then
        echo "airlock binary not found at $AIRLOCK" >&2
        return 1
    fi
}

setup() {
    require_vm_support
}

@test "dropped files are imported read-only through the raw terminal" {
    run python3 "$REPO_ROOT/tests/vm/attachments.py" "$AIRLOCK" raw
    assert_success
}

@test "dropped files are imported read-only through the monitor" {
    run python3 "$REPO_ROOT/tests/vm/attachments.py" "$AIRLOCK" monitor
    assert_success
}

@test "dropped files are imported read-only through airlock exec" {
    run python3 "$REPO_ROOT/tests/vm/attachments.py" "$AIRLOCK" exec
    assert_success
}
