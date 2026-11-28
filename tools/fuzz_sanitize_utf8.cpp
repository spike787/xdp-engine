// SPDX-License-Identifier: MIT
// libFuzzer harness for text_util.h's sanitize_utf8() (ROADMAP.md Phase 3,
// "parser fuzzing" - see docs/adr/0007-parser-fuzzing.md). Every field
// LogParser::parse() extracts from a raw, attacker-reachable log line is
// passed through this before anything else sees it - it's the one
// function in this codebase doing manual UTF-8 byte-sequence validation
// (continuation-byte checks, overlong/surrogate/out-of-range rejection),
// so it's the highest-value target for the kind of off-by-one or
// out-of-bounds read fuzzing is good at catching. Narrow and fast on
// purpose, same reasoning as fuzz_url_decode.cpp.
//
// Build: make fuzz-sanitize-utf8
// Run:   ./tools/fuzz-sanitize-utf8 -max_total_time=60
#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>

#include "../text_util.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string_view input(reinterpret_cast<const char*>(data), size);
    std::string out = sanitize_utf8(input);
    // sanitize_utf8 documents a hard 128-byte output cap regardless of
    // input length - a real, checkable invariant, not just "didn't crash".
    if (out.size() > 128) __builtin_trap();
    return 0;
}
