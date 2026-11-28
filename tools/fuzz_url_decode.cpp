// SPDX-License-Identifier: MIT
// libFuzzer harness for text_util.h's url_decode() (ROADMAP.md Phase 3,
// "parser fuzzing" - see docs/adr/0007-parser-fuzzing.md). This is one of
// two hand-rolled, byte-level string functions LogParser::parse() runs
// every url_decode-flagged field (e.g. nginx-access.yaml's `path`) through
// - exactly the kind of manual index arithmetic fuzzing is good at
// catching an off-by-one in. Narrow and fast on purpose: no YAML, no
// regex, just the function itself, so this can run many more iterations
// per second than tools/fuzz_log_parser.cpp's full-pipeline harness.
//
// Build: make fuzz-url-decode
// Run:   ./tools/fuzz-url-decode -max_total_time=60
#include <cstdint>
#include <cstddef>
#include <string>

#include "../text_util.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string input(reinterpret_cast<const char*>(data), size);
    std::string decoded = url_decode(input);
    // No specific property beyond "doesn't crash, doesn't hang, and never
    // grows the string" - url_decode only ever shrinks or holds length
    // steady (each 3-byte "%XX" collapses to 1 byte; anything else is
    // copied through unchanged).
    if (decoded.size() > input.size()) __builtin_trap();
    return 0;
}
