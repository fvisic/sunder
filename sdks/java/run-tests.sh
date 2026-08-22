#!/usr/bin/env bash
# Compiles the SDK and its test suite with plain javac and runs the
# main-method test runner — no Maven, no dependencies (Java 17+).
set -euo pipefail
cd "$(dirname "$0")"

OUT=target/classes
TEST_OUT=target/test-classes
rm -rf target
mkdir -p "$OUT" "$TEST_OUT"

echo "== compiling main sources (release 17)"
javac --release 17 -Xlint:all -Werror -d "$OUT" $(find src/main/java -name '*.java')

echo "== compiling test sources"
javac --release 17 -Xlint:all -Werror -cp "$OUT" -d "$TEST_OUT" $(find src/test/java -name '*.java')

echo "== running test suite"
java -cp "$OUT:$TEST_OUT" io.sunderid.client.SunderClientTest
