CLANG ?= clang
CXX   ?= g++

# Ubuntu keeps architecture-specific headers (asm/types.h) in a multiarch directory.
ARCH_INC := $(firstword $(wildcard /usr/include/$(shell uname -m)-linux-gnu))

# Stage 1 flags: -O2 is REQUIRED (the verifier rejects unoptimized code with function calls),
# -g emits debug info from which BTF is generated, -target bpf selects the BPF backend.
BPF_CFLAGS := -g -O2 -Wall -target bpf
ifneq ($(ARCH_INC),)
BPF_CFLAGS += -I$(ARCH_INC)
endif

all: xdp_prog.bpf.o engine engine-cli local-api bouncer-xdp bouncer-nft bench replay-cli

# Stage 1: C -> BPF bytecode inside an ELF object
xdp_prog.bpf.o: xdp_prog.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Stage 2: C++20 -> native executable, linked against libbpf and yaml-cpp
engine: engine.cpp rule_engine.cpp rule_engine.h storage.cpp storage.h playbook_runner.cpp playbook_runner.h notifier.cpp notifier.h http_detector.cpp http_detector.h
	$(CXX) -std=c++20 -O2 -Wall -Wextra -pthread engine.cpp rule_engine.cpp storage.cpp playbook_runner.cpp notifier.cpp http_detector.cpp -o $@ -lbpf -lelf -lz -lyaml-cpp -lsqlite3 -lcurl

engine-cli: engine-cli.cpp
	$(CXX) -O2 -Wall -Wextra engine-cli.cpp -o $@

# bouncer-xdp (ADR-0002): the enforcement component. Loads xdp_prog.bpf.c,
# attaches it, pins the maps, and polls Local API's /decisions to keep
# blocked_ips in sync. Needs libbpf (attach/pin) and libcurl (poll), not
# yaml-cpp/sqlite3 - it has no rule engine or storage of its own.
bouncer-xdp: bouncer_xdp.cpp bouncer_diff.h common.h
	$(CXX) -std=c++20 -O2 -Wall -Wextra -pthread bouncer_xdp.cpp -o $@ -lbpf -lelf -lz -lcurl

# bouncer-nft (ADR-0004): the second Remediation Component. Enforces the
# same /decisions feed as bouncer-xdp but via an nftables set, so it works
# on hosts without a BPF/XDP-capable NIC or kernel. Needs libcurl (poll)
# but no libbpf/sqlite3/yaml-cpp - no rule engine or BPF maps of its own.
# The actual enforcement is the `nft` binary, invoked as a subprocess
# (see bouncer_nft.cpp) rather than linked against libnftables.
bouncer-nft: bouncer_nft.cpp nft_bouncer_core.h bouncer_diff.h
	$(CXX) -std=c++20 -O2 -Wall -Wextra -pthread bouncer_nft.cpp -o $@ -lcurl

bench: tools/bench_flood.c
	gcc -O3 -Wall -Wextra tools/bench_flood.c -o tools/bench_flood -pthread

# replay-cli (ROADMAP.md phase 2): feeds a captured log file through a
# parsers/s01-parse/*.yaml + rules.yaml and reports what would have fired.
# No BPF/root/kernel dependency at all - just yaml-cpp (RuleEngine,
# LogParser) and nlohmann json (--format json, Alert::to_json).
replay-cli: tools/replay_cli.cpp replay_core.h http_classifier.h log_parser.h rule_engine.h rule_engine.cpp
	$(CXX) -std=c++20 -O2 -Wall -Wextra tools/replay_cli.cpp rule_engine.cpp -o tools/$@ -lyaml-cpp

# Local API: the shared control plane (ROADMAP.md phase 1). No BPF/libcurl
# dependency — it only needs the storage layer and an HTTP server.
HTTPLIB_FLAGS := $(shell pkg-config --cflags --libs cpp-httplib 2>/dev/null)
local-api: local_api.cpp storage.cpp storage.h
	$(CXX) -std=c++20 -O2 -Wall -Wextra -pthread local_api.cpp storage.cpp -o $@ -lsqlite3 $(HTTPLIB_FLAGS)

clean:
	rm -f xdp_prog.bpf.o engine engine-cli local-api bouncer-xdp bouncer-nft tools/bench_flood tools/replay-cli

# Stage 3: Unit Tests
test: tests/test_logic.cpp tests/test_storage.cpp tests/test_bouncer_diff.cpp tests/test_log_parser.cpp tests/test_http_classifier.cpp tests/test_replay_core.cpp tests/test_nft_bouncer_core.cpp rule_engine.cpp http_detector.cpp storage.cpp
	$(CXX) -std=c++20 -O2 -Wall -Wextra -pthread $^ -o test_logic -lgtest -lgtest_main -lyaml-cpp -lsqlite3
	./test_logic

# Stage 4: Sanitizer build
ASAN_FLAGS := -fsanitize=address,undefined -g -O1
engine_asan: engine.cpp rule_engine.cpp storage.cpp playbook_runner.cpp notifier.cpp http_detector.cpp
	$(CXX) -std=c++20 $(ASAN_FLAGS) -Wall -Wextra -pthread $^ -o $@ -lbpf -lelf -lz -lyaml-cpp -lsqlite3 -lcurl

asan: engine_asan
