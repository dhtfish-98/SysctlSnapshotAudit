> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# SysctlSnapshotAudit

Version **0.1.2**.

New implementation author: **dhtfish98**. Copyright (c) 2026 dhtfish98 applies to the new implementation code. Upstream policy data, original notices and source references retain their original attribution.

Persistent and observed sysctl snapshot drift audit. A complete independent new-scope defensive project; upstream-wide rewriting and equivalence are not claimed.

Input: `{ "files": {"/etc/sysctl.d/99-policy.conf": "key=value"}, "observed": {"kernel.kptr_restrict": 2} }`. Complete new scope: 26 explicit non-routing workstation controls covering ASLR, pointer/log exposure, ptrace/BPF/perf, protected links/FIFOs/files/core dumps, IPv4/IPv6 forwarding/source routes/redirects/rp_filter and SYN cookies. Higher-priority directories mask same-named lower-priority files; selected filenames then apply lexically and repeated integer assignments use the last value. Policy values are project choices grounded in documented kernel meanings, not a claim of official universal guidance. Missing persistent or observed values are OPEN; non-integer observations are ERROR; runtime/persistent disagreements FAIL. Slash/glob/exclusion syntax is OPEN. Per-interface combined kernel semantics, sysctl.conf imports, network routing requirements, boot effects and unsupported kernels are outside the implemented scope.

## Use

Install the wheel in `artifacts/`, then run `sysctl-snapshot-audit examples/good.json`. Or use `python -m sysctl_snapshot_audit examples/good.json`. JSON input is limited to 2 MiB, 32 nesting levels and 100000 nodes; duplicate keys, non-finite values, changed files, symlinks and non-regular files are rejected. Findings are capped at 20000. No network requests, host collection, policy changes or shell execution occur.

## Output and verification

Each finding includes check, PASS/FAIL/OPEN, evidence location and explanation. Overall status is FAIL if a check fails; otherwise OPEN for incomplete/unsupported input; otherwise PASS for only this declared static scope. Exit codes: PASS 0, FAIL 1, ERROR 2, OPEN 3. See `examples/expectations.json`, `tests/`, `VALIDATION.md`, `ORIGIN.md`, `NOTICE` where present, and exact `artifacts/validation.json`.

Snapshot results do not prove runtime security, actual authorization, upstream equivalence or CVP qualification/approval.


The file CLI requires non-following, non-blocking descriptor support (`O_NOFOLLOW` and `O_NONBLOCK`). Missing capabilities return controlled ERROR without weakening safe-file reads. This profile targets capable macOS/Linux environments; native Windows file-CLI behavior has not been verified. Windows observations remain supplied JSON data.

The selected sysctl.d parser consumes physical newline-separated records and full values, matching the frozen systemd callback. Backslash continuations and inline #/semicolon comment spellings are not integer declarations and remain OPEN. Whole-line # comments are supported; extra whitespace forms outside the ASCII physical-line profile remain OPEN.
