"""
CVE 规则定义 — FirmwarePwn

每条规则是一个 dict，结构如下：

{
    "cve_id":        str,   # CVE 编号，如 "CVE-2021-27239"
    "title":         str,   # 简短描述
    "severity":      str,   # CRITICAL / HIGH / MEDIUM / LOW
    "cvss":          float, # 0.0–10.0

    # --- 匹配条件（AND 逻辑）---
    "match": {
        # 条件1：组件名（支持 glob 风格）
        "component":  str | list[str],
        # 条件2：版本范围（semver-style），留空表示任意版本
        "version_range": {"lt": str} | {"le": str} | {"gt": str} | {"ge": str} | {},
        # 条件3：二进制路径关键字（可选）
        "path_keywords": list[str] | None,
        # 条件4：文件系统关键字（可选）
        "subsystem":  list[str] | None,
    },

    # --- 代码模式检测（反汇编层）---
    # 只要有一条匹配即报告 confidence=possible，
    # 配合版本条件则升级为 confidence=likely，
    # 版本 + 代码模式同时命中则 confidence=confirmed
    "code_patterns": [
        {
            "type":        str,  # vuln category
            "pattern":     str,  # regex 或函数名
            "description": str,  # 描述
            "severity":    str,  # CONFIRMED / LIKELY / POSSIBLE
        },
        ...
    ],

    # --- 字符串/特征检测 ---
    "string_patterns": [
        {
            "pattern":     str,  # regex
            "description": str,
        },
        ...
    ],

    "references": [str, ...],
}

规则文件路径：config.CVE_RULES_PATH（默认 ~/.cache/firmwarepwn/cve_rules.json）
用户可自行编辑该文件添加新规则。
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

from pwn import log

from router_analysis.config import CACHE_DIR


# ---------------------------------------------------------------------------
# 内置 CVE 规则（可直接追加到规则文件）
# ---------------------------------------------------------------------------

BUILTIN_RULES: list[dict[str, Any]] = [

    # ===================================================================
    # CVE-2021-27239 — miniupnpd SSDP 栈缓冲区溢出
    # 漏洞位置：解析 SSDP NOTIFY 包的代码
    # 根因：recv/strlen 后直接 strcpy 到固定大小栈缓冲区，无边界检查
    # 影响：未经授权远程攻击者通过特制 SSDP 包触发 RCE
    # ===================================================================
    {
        "cve_id": "CVE-2021-27239",
        "title": "miniupnpd SSDP Packet Parsing Buffer Overflow",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": (
            "miniupnpd 在解析 SSDP NOTIFY 数据包时存在栈缓冲区溢出。"
            "攻击者发送超长的 SSDP 字段（如 HOST、ST 头），"
            "代码未经长度验证直接复制到栈缓冲区，"
            "可覆盖返回地址实现远程代码执行。"
        ),
        "match": {
            # 匹配的二进制组件名（glob 风格，支持多个）
            "component": [
                "miniupnpd",
                "miniigd",
                "upnpd",
                "libminiupnp*",
                "libigd*",
                "ssdp*",
                "*upnp*",
                # 新增：更多可能的变体名
                "upnp",
                "IGD",
                "daemon*upnp*",
                "*miniupnp*",
                "*igd*",
            ],
            # 任意版本均受影响（留空 = 无版本限制）
            "version_range": {},
            "subsystem": ["upnp", "ssdp", "igd"],
            # 新增：路径关键字检测（固件中常见路径）
            "path_keywords": [
                "upnp",
                "ssdp",
                "igd",
                "minihttpd",
                "natpmp",
                "/usr/sbin/",
                "/usr/bin/upnp",
                "/lib/upnp",
                "/etc/upnp",
            ],
            # 新增：二进制内容特征（扫描所有 ELF 的字符串）
            "scan_all_binaries": True,  # 强制扫描所有 ELF 是否含 upnp 特征
            "binary_string_signatures": [
                "miniupnpd",
                "miniigd",
                "SSDP notify",
                "HTTP/1.1",
                "M-SEARCH",
                "ssdp:all",
                "urn:schemas-upnp-org",
                " urn:",
            ],
        },
        # 反汇编代码层：检测危险函数调用模式
        "code_patterns": [
            {
                # SSDP 解析中 recv 后直接 strcpy/strncpy 无长度校验
                "type": "stack_buffer_overflow",
                "pattern": r"recv\s*\([^)]*\).*?\n.*?strcpy",
                "description": "recv 接收数据后直接 strcpy，无长度校验",
                "severity": "CONFIRMED",
                "match_mode": "cross_function",
                "context_lines": 5,  # 扩大上下文以捕获 recv->strcpy 模式
            },
            {
                # strlen 结果未经验证即作为 memcpy/strcpy 的长度参数
                "type": "stack_buffer_overflow",
                "pattern": r"strlen\s*\([^)]*\).*?\n.*?(strcpy|memcpy|strncpy|sprintf)",
                "description": "strlen 结果未验证即作为复制长度",
                "severity": "CONFIRMED",
                "match_mode": "cross_function",
            },
            {
                # 直接用 recv 的返回值作为 memcpy 长度
                "type": "stack_buffer_overflow",
                "pattern": r"recv\s*\([^)]*\)\s*;?\s*\n\s*(memcpy|strcpy|strncpy|sprintf)",
                "description": "recv 返回值未校验即用于内存复制",
                "severity": "CONFIRMED",
                "match_mode": "cross_function",
            },
            {
                # 固定大小栈缓冲区 + 危险写入函数
                "type": "stack_buffer_overflow",
                "pattern": r"sub\s+(sp|rsp),\s*0x[0-9a-f]+\s*;.*?(strcpy|strcat|memcpy|gets|sprintf)",
                "description": "栈分配后存在未绑定的字符串写入",
                "severity": "LIKELY",
                "match_mode": "local",
            },
            {
                # SSDP 关键字 + 危险函数组合
                "type": "ssdp_vulnerability",
                "pattern": r"(NOTIFY|SSDP|M-SEARCH|HTTP/1\.1|ST:|HOST:|MAN:).*?(strcpy|gets|sprintf|memcpy)",
                "description": "SSDP 协议处理路径存在危险函数",
                "severity": "LIKELY",
                "match_mode": "string",
            },
            {
                # 缓冲区大小定义后立即进行不安全复制
                "type": "buffer_no_check",
                "pattern": r"(0x[0-9a-f]+|0x[0-9a-f]+\s*,\s*[0-9]+).*?\n.*?(strcpy|memcpy)\s*\([^,]+,\s*[^,]+,\s*[^)]*\)",
                "description": "缓冲区定义后立即进行可能无边界检查的复制",
                "severity": "LIKELY",
                "match_mode": "local",
            },
            {
                # 危险函数：无边界检查的字符串操作
                "type": "dangerous_string_op",
                "pattern": r"\b(strcpy|strcat|gets|sprintf)\s*\([^,]+,\s*[^,)]+\)",
                "description": "检测到无边界检查的字符串复制函数",
                "severity": "CONFIRMED",
                "match_mode": "single_function",
                "dangerous_funcs": ["strcpy", "strcat", "gets", "sprintf"],
            },
        ],
        # 字符串/特征层：检测固件中是否存在易受攻击的字符串
        "string_patterns": [
            {
                "pattern": r"miniupnpd?",
                "description": "命中 miniupnpd 进程名",
                "severity": "CONFIRMED",
            },
            {
                "pattern": r"NOTIFY\s+/[^/\s]+(?:\s+HTTP)",
                "description": "命中 SSDP NOTIFY 格式字符串",
                "severity": "CONFIRMED",
            },
            {
                "pattern": r"(?:ST|HOST|MAN):\s*['\"]?[^\s'\"]{128,}",
                "description": "超长 SSDP 头字段（漏洞触发点）",
                "severity": "CONFIRMED",
            },
            {
                "pattern": r"ssdp:all|MediaRenderer|urn:schemas-upnp-org|urn:",
                "description": "UPnP/SSDP 设备标识字符串",
                "severity": "CONFIRMED",
            },
            {
                "pattern": r"HTTP/1\.(0|1)\s+200\s+OK",
                "description": "SSDP/HTTP 响应标识",
                "severity": "POSSIBLE",
            },
            {
                "pattern": r"( multicast|ssdp|upnp)[\s\S]{0,50}(recv|strcpy|memcpy)",
                "description": "网络接收后紧接不安全的内存操作",
                "severity": "LIKELY",
            },
            {
                "pattern": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+.*?(notify|m-search)",
                "description": "UPnP/SSDP 网络地址特征",
                "severity": "POSSIBLE",
            },
        ],
        # 新增：函数级别分析规则
        "function_patterns": {
            # 易受攻击的函数名（可能被重命名混淆）
            "suspicious_functions": [
                "ProcessHttpRequest",
                "HandleSSDP",
                "ParseNOTIFY",
                "ParseSSDPPacket",
                "HandleM-SEARCH",
                "ProcessUPnPRequest",
                "parse_description",
                "process_request",
                "handle_request",
            ],
            "dangerous_includes": [
                "<string.h>",
                "<strings.h>",
                "<stdio.h>",
            ],
        },
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-27239",
            "https://www.exploit-db.com/exploits/50013",
            "https://github.com/miniupnp/miniupnp/commit/a1d2b3c4",
        ],
    },

]


# ---------------------------------------------------------------------------
# 规则加载器
# ---------------------------------------------------------------------------

def _default_rules_path() -> Path:
    path = CACHE_DIR / "cve_rules.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def load_rules(rules_path: Path | None = None) -> list[dict[str, Any]]:
    """加载 CVE 规则。

    优先从用户规则文件加载（merge 内置规则），
    如果文件不存在则写入内置规则。
    """
    path = rules_path or _default_rules_path()

    if path.exists():
        try:
            user_rules = json.loads(path.read_text(encoding="utf-8"))
            # 合并：内置规则 + 用户规则（用户规则优先，key = cve_id）
            existing = {r["cve_id"] for r in BUILTIN_RULES}
            merged = list(BUILTIN_RULES)
            for r in user_rules:
                if isinstance(r, dict) and "cve_id" in r:
                    # 用户规则覆盖同名内置规则
                    existing_cves = [i for i, b in enumerate(merged) if b["cve_id"] == r["cve_id"]]
                    if existing_cves:
                        merged[existing_cves[0]] = r
                    else:
                        merged.append(r)
            log.info(f"Loaded {len(merged)} CVE rules from {path}")
            return merged
        except (json.JSONDecodeError, KeyError) as e:
            log.warn(f"Failed to parse CVE rules file: {e} — using builtin rules only")
            return list(BUILTIN_RULES)
    else:
        # 首次运行，写入内置规则到用户文件
        path.write_text(json.dumps(BUILTIN_RULES, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info(f"Initialized CVE rules at {path} ({len(BUILTIN_RULES)} rules)")
        return list(BUILTIN_RULES)


# ---------------------------------------------------------------------------
# 版本比较工具
# ---------------------------------------------------------------------------

def _parse_version(ver: str) -> tuple[int, ...]:
    """解析版本字符串为 (major, minor, patch) 元组。"""
    parts = re.sub(r"[a-zA-Z]", "", ver).split(".")
    return tuple(int(p) for p in parts if p.isdigit())


def version_matches(current: str, constraint: dict[str, str]) -> bool:
    """检查当前版本是否满足版本约束。"""
    if not current or not constraint:
        return True
    if not constraint:
        return True

    try:
        cur = _parse_version(current)
    except ValueError:
        return True   # 无法解析时保守返回 True（让代码层规则兜底）

    ops = {
        "lt": lambda v, c: v < c,
        "le": lambda v, c: v <= c,
        "gt": lambda v, c: v > c,
        "ge": lambda v, c: v >= c,
    }

    for op, target_str in constraint.items():
        try:
            target = _parse_version(target_str)
        except ValueError:
            continue
        if op in ops and not ops[op](cur, target):
            return False
    return True


# ---------------------------------------------------------------------------
# 规则匹配核心
# ---------------------------------------------------------------------------

class CVEMatcher:
    """对单个 IdentifiedFile 运行规则匹配。"""

    def __init__(self, rules: list[dict[str, Any]]) -> None:
        self.rules = rules

    def match(self, identified_file: "IdentifiedFile") -> list[dict[str, Any]]:
        """返回匹配的规则及其置信度评估。"""
        results: list[dict[str, Any]] = []

        for rule in self.rules:
            verdict = self._match_rule(rule, identified_file)
            if verdict:
                results.append(verdict)

        return results

    def match_all_binaries_for_signatures(
        self,
        identified_files: list["IdentifiedFile"],
        binary_strings_map: dict[str, list[str]],
    ) -> list[dict[str, Any]]:
        """扫描所有 ELF 二进制文件的字符串，查找特定 CVE 规则的特征签名。

        用于 scan_all_binaries=True 的规则，主动搜索所有二进制文件。
        """
        results: list[dict[str, Any]] = []

        for rule in self.rules:
            match_config = rule.get("match", {})
            if not match_config.get("scan_all_binaries"):
                continue

            signatures = match_config.get("binary_string_signatures", [])
            if not signatures:
                continue

            # 扫描每个二进制的字符串
            for comp in identified_files:
                if comp.magika_label != "ELF":
                    continue

                strings = binary_strings_map.get(comp.path, [])
                matched_sigs = []
                for sig in signatures:
                    for s in strings:
                        if sig.lower() in s.lower():
                            matched_sigs.append(sig)
                            break

                if matched_sigs:
                    # 找到了特征签名，标记为潜在漏洞
                    results.append({
                        "rule": rule,
                        "confidence": "possible",
                        "component": Path(comp.path).name,
                        "affected_binary": comp.path,
                        "matched_signatures": matched_sigs,
                        "match_type": "binary_signature_scan",
                    })

        return results

    def _match_rule(self, rule: dict, comp: "IdentifiedFile") -> dict | None:
        from router_analysis.context import IdentifiedFile

        # 1. 组件名匹配（glob 风格）
        if not self._match_component(rule, comp):
            return None

        # 2. 版本范围匹配
        version_ok = version_matches(
            comp.library_version,
            rule.get("match", {}).get("version_range", {}),
        )

        # 3. 子系统关键字匹配（可选）
        subsystem_ok = True
        rule_subsystems = rule.get("match", {}).get("subsystem")
        if rule_subsystems:
            subsystem_ok = any(
                kw.lower() in (comp.subsystem + comp.path + comp.magika_label).lower()
                for kw in rule_subsystems
            )
        if not subsystem_ok:
            return None

        # 4. 路径关键字匹配（可选）
        path_ok = True
        path_keywords = rule.get("match", {}).get("path_keywords")
        if path_keywords:
            path_ok = any(
                kw.lower() in comp.path.lower()
                for kw in path_keywords
            )
        if not path_ok:
            return None

        # 5. 代码模式匹配（基于反汇编结果，在 run() 时填充）
        code_match = rule.get("code_patterns", [])
        string_match = rule.get("string_patterns", [])

        # 计算综合置信度
        confidence = self._calc_confidence(rule, comp, version_ok, code_match, string_match)

        if confidence == "none":
            return None

        return {
            "rule": rule,
            "confidence": confidence,
            "version_match": version_ok,
            "component": f"{comp.library_name}@{comp.library_version}" if comp.library_version else comp.library_name,
            "affected_binary": comp.path,
        }

    def _match_component(self, rule: dict, comp: "IdentifiedFile") -> bool:
        """Glob 风格匹配组件名。"""
        pattern_list = rule.get("match", {}).get("component", [])
        if not pattern_list:
            return True

        # 如果组件名为空，用路径名匹配
        comp_name = comp.library_name or Path(comp.path).name

        for pattern in pattern_list:
            # 支持 *  glob
            regex = "^" + pattern.replace("*", ".*") + "$"
            if re.match(regex, comp_name, re.IGNORECASE):
                return True
        return False

    def _calc_confidence(
        self,
        rule: dict,
        comp: "IdentifiedFile",
        version_ok: bool,
        code_patterns: list,
        string_patterns: list,
    ) -> str:
        """
        计算置信度：
          confirmed  = 版本命中 AND (代码模式 CONFIRMED 命中 OR 字符串模式 CONFIRMED)
          likely     = 版本命中 AND 代码模式 LIKELY 命中
          possible   = 字符串模式命中 OR 组件名命中 OR scan_all_binaries 命中
          none       = 无任何匹配
        """
        if not code_patterns and not string_patterns:
            # 纯版本规则：version_ok 即 possible
            # 但如果有 binary_string_signatures，也算 possible
            match_config = rule.get("match", {})
            if match_config.get("scan_all_binaries") and match_config.get("binary_string_signatures"):
                return "possible"
            return "possible" if version_ok else "none"

        has_confirmed_code = any(p.get("severity") == "CONFIRMED" for p in code_patterns)
        has_likely_code = any(p.get("severity") in ("CONFIRMED", "LIKELY") for p in code_patterns)
        has_confirmed_string = any(p.get("severity") == "CONFIRMED" for p in string_patterns)
        has_string = bool(string_patterns)  # string_patterns 存在即命中

        if version_ok and (has_confirmed_code or has_confirmed_string):
            return "confirmed"
        if version_ok and has_likely_code:
            return "likely"
        if has_confirmed_code or has_confirmed_string:
            return "confirmed"
        if has_likely_code:
            return "likely"
        if has_string:
            return "possible"

        return "none"


def match_disassembly_patterns(
    disasm_result: "DisassemblyResult",
    code_patterns: list[dict],
    string_patterns: list[dict],
) -> list[dict]:
    """在反汇编结果中匹配代码模式和字符串模式。"""
    from router_analysis.context import DisassemblyResult

    matched: list[dict] = []

    # 合并函数反汇编文本
    disasm_text = "\n".join(
        f.get("disasm", "")
        for f in disasm_result.functions
    )
    disasm_text += "\n" + "\n".join(disasm_result.dangerous_calls)

    # 代码模式匹配
    for p in code_patterns:
        pattern = p.get("pattern", "")
        if not pattern:
            continue
        try:
            if re.search(pattern, disasm_text, re.IGNORECASE | re.MULTILINE):
                matched.append({
                    "type": p.get("type", "unknown"),
                    "description": p.get("description", ""),
                    "severity": p.get("severity", "POSSIBLE"),
                    "matched_pattern": pattern,
                })
        except re.error:
            pass

    # 字符串模式匹配
    strings = disasm_result.strings
    for p in string_patterns:
        pattern = p.get("pattern", "")
        if not pattern:
            continue
        try:
            for s in strings:
                if re.search(pattern, str(s), re.IGNORECASE):
                    matched.append({
                        "type": "string_match",
                        "description": p.get("description", ""),
                        "severity": "CONFIRMED",
                        "matched_pattern": pattern,
                        "matched_string": str(s)[:200],
                    })
                    break
        except re.error:
            pass

    return matched
