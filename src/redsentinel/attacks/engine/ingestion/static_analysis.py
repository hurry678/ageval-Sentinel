from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StaticAnalysisFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    file_path: str = Field(min_length=1)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    code_snippet: str = Field(default="")
    description: str = Field(min_length=1)
    recommendation: str = Field(default="")
    evidence: dict[str, Any] = Field(default_factory=dict)


class FrameworkDetection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework: str = Field(min_length=1)
    version: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class SensitiveDataPattern(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pattern: str = Field(min_length=1)
    category: str = Field(min_length=1)
    matches: list[dict[str, Any]] = Field(default_factory=list)


class StaticAnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root_path: str = Field(min_length=1)
    files_scanned: int = Field(ge=0)
    files_skipped: int = Field(ge=0)
    framework: FrameworkDetection | None = None
    findings: list[StaticAnalysisFinding] = Field(default_factory=list)
    sensitive_data: list[SensitiveDataPattern] = Field(default_factory=list)
    risk_surfaces: list[str] = Field(default_factory=list)
    tool_signatures: list[dict[str, Any]] = Field(default_factory=list)
    node_candidates: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    notes: list[str] = Field(default_factory=list)


_SENSITIVE_PATTERNS = [
    (r"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key)", "API_KEY"),
    (r"(?i)(password|passwd|pwd)", "PASSWORD"),
    (r"(?i)(secret|secret_key|secret_token)", "SECRET"),
    (r"(?i)(database[_-]?url|db[_-]?url|connection[_-]?string)", "DATABASE_CREDENTIAL"),
    (r"(?i)(ssh[_-]?key|private[_-]?key)", "PRIVATE_KEY"),
    (r"(?i)(jwt[_-]?secret|oauth[_-]?token)", "AUTH_TOKEN"),
    (r"(?i)(phone|mobile|tel|phone_number)", "PHONE"),
    (r"(?i)(email|mail|user[_-]?email)", "EMAIL"),
    (r"(?i)(address|location|street)", "ADDRESS"),
    (r"(?i)(credit[_-]?card|cc[_-]?number|payment[_-]?token)", "CREDIT_CARD"),
]

_FRAMEWORK_PATTERNS = [
    ("langgraph", ["import langgraph", "from langgraph", "langgraph.StateGraph"]),
    ("langchain", ["import langchain", "from langchain", "langchain.llms", "langchain.chains"]),
    ("autogen", ["import autogen", "from autogen", "autogen.AssistantAgent"]),
    ("crewai", ["import crewai", "from crewai", "crewai.Agent"]),
    ("llamaindex", ["import llama_index", "from llama_index", "llama_index.LLM"]),
    ("streamlit", ["import streamlit", "st.", "streamlit run"]),
    ("fastapi", ["import fastapi", "from fastapi", "FastAPI()"]),
    ("flask", ["import flask", "from flask", "Flask(__name__)"]),
]

_RISK_KEYWORDS = {
    "prompt_injection": ["prompt", "injection", "jailbreak", "override"],
    "knowledge_poisoning": ["rag", "retrieve", "document", "inject"],
    "tool_tampering": ["tool", "execute", "call", "action"],
    "memory_poisoning": ["memory", "store", "remember", "recall"],
    "goal_drift": ["goal", "objective", "task", "drift"],
    "pii_leakage": ["pii", "sensitive", "private", "leak"],
    "unauthorized_retrieval": ["retrieve", "search", "query", "access"],
}

_EXCLUDE_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build", ".eggs"}


class CodeStaticAnalyzer:
    def __init__(self, root_path: str | Path, *, exclude_dirs: set[str] | None = None) -> None:
        self.root = Path(root_path).resolve()
        self.exclude_dirs = exclude_dirs or _EXCLUDE_DIRS

    def analyze(self) -> StaticAnalysisResult:
        files = self._collect_python_files()
        findings: list[StaticAnalysisFinding] = []
        sensitive_data: list[SensitiveDataPattern] = []
        risk_surfaces: set[str] = set()
        tool_signatures: list[dict[str, Any]] = []
        node_candidates: list[dict[str, Any]] = []
        framework = None

        for path in files:
            try:
                content = path.read_text(encoding="utf-8")
                tree = ast.parse(content)
            except (SyntaxError, UnicodeDecodeError):
                continue

            findings.extend(self._analyze_file(path, content, tree))
            sensitive_data.extend(self._detect_sensitive_patterns(path, content))
            risk_surfaces.update(self._detect_risk_surfaces(path, content, tree))
            tool_signatures.extend(self._extract_tool_signatures(path, tree))
            node_candidates.extend(self._identify_node_candidates(path, tree))

            if framework is None:
                framework = self._detect_framework(content)

        return StaticAnalysisResult(
            root_path=str(self.root),
            files_scanned=len(files),
            files_skipped=0,
            framework=framework,
            findings=findings,
            sensitive_data=sensitive_data,
            risk_surfaces=sorted(risk_surfaces),
            tool_signatures=tool_signatures,
            node_candidates=node_candidates,
            confidence=self._calculate_confidence(findings, node_candidates, framework),
            notes=self._generate_notes(files, findings, framework),
        )

    def _collect_python_files(self) -> list[Path]:
        if not self.root.exists():
            return []
        if self.root.is_file():
            return [self.root] if self.root.suffix == ".py" else []

        files: list[Path] = []
        for path in self.root.rglob("*.py"):
            if self._should_skip(path):
                continue
            files.append(path)
        return sorted(files)

    def _should_skip(self, path: Path) -> bool:
        return any(part in self.exclude_dirs for part in path.parts)

    def _analyze_file(self, path: Path, content: str, tree: ast.AST) -> list[StaticAnalysisFinding]:
        findings: list[StaticAnalysisFinding] = []
        findings.extend(self._check_unsafe_patterns(path, content))
        findings.extend(self._check_dynamic_code_execution(path, tree))
        findings.extend(self._check_external_api_calls(path, tree))
        return findings

    def _check_unsafe_patterns(self, path: Path, content: str) -> list[StaticAnalysisFinding]:
        findings: list[StaticAnalysisFinding] = []
        lines = content.split("\n")

        unsafe_patterns = [
            (r"(?i)exec\(", "EXEC_STATEMENT", "high", "Dynamic code execution using exec()"),
            (r"(?i)eval\(", "EVAL_STATEMENT", "high", "Dynamic code evaluation using eval()"),
            (r"(?i)subprocess\.Popen", "SUBPROCESS_POPEN", "medium", "Subprocess execution"),
            (r"(?i)os\.system", "OS_SYSTEM", "high", "OS command execution"),
            (r"(?i)pickle\.loads", "PICKLE_LOADS", "high", "Unsafe deserialization"),
            (r"(?i)yaml\.unsafe_load", "YAML_UNSAFE_LOAD", "high", "Unsafe YAML loading"),
            (r"(?i)json\.loads.*eval", "JSON_EVAL", "medium", "Potential eval injection"),
        ]

        import re

        for pattern, code, severity, desc in unsafe_patterns:
            for idx, line in enumerate(lines, start=1):
                if re.search(pattern, line):
                    findings.append(
                        StaticAnalysisFinding(
                            finding_id=f"{code}-{path.stem}-{idx}",
                            category="code_security",
                            severity=severity,
                            file_path=str(path),
                            line_start=idx,
                            line_end=idx,
                            code_snippet=line.strip(),
                            description=desc,
                            recommendation="Review and replace with safer alternatives",
                        )
                    )
        return findings

    def _check_dynamic_code_execution(self, path: Path, tree: ast.AST) -> list[StaticAnalysisFinding]:
        findings: list[StaticAnalysisFinding] = []
        exec_node_types = tuple(
            getattr(ast, cls_name)
            for cls_name in ["Exec", "Eval"]
            if hasattr(ast, cls_name)
        )
        for node in ast.walk(tree):
            if exec_node_types and isinstance(node, exec_node_types):
                findings.append(
                    StaticAnalysisFinding(
                        finding_id=f"DYNAMIC_EXEC-{path.stem}-{node.lineno}",
                        category="code_security",
                        severity="high",
                        file_path=str(path),
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        description="Direct dynamic code execution",
                        recommendation="Remove or replace with safe alternatives",
                    )
                )
        return findings

    def _check_external_api_calls(self, path: Path, tree: ast.AST) -> list[StaticAnalysisFinding]:
        findings: list[StaticAnalysisFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in {"requests", "urllib", "http.client", "aiohttp"}:
                        findings.append(
                            StaticAnalysisFinding(
                                finding_id=f"EXTERNAL_API-{path.stem}-{node.lineno}",
                                category="network_access",
                                severity="medium",
                                file_path=str(path),
                                line_start=node.lineno,
                                line_end=node.lineno,
                                description=f"External HTTP client imported: {alias.name}",
                                recommendation="Ensure network access is properly controlled",
                            )
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module in {"requests", "urllib", "aiohttp"}:
                    findings.append(
                        StaticAnalysisFinding(
                            finding_id=f"EXTERNAL_API-{path.stem}-{node.lineno}",
                            category="network_access",
                            severity="medium",
                            file_path=str(path),
                            line_start=node.lineno,
                            line_end=node.lineno,
                            description=f"External HTTP client imported: {node.module}",
                            recommendation="Ensure network access is properly controlled",
                        )
                    )
        return findings

    def _detect_sensitive_patterns(self, path: Path, content: str) -> list[SensitiveDataPattern]:
        patterns: list[SensitiveDataPattern] = []
        import re

        for pattern, category in _SENSITIVE_PATTERNS:
            matches = list(re.finditer(pattern, content))
            if matches:
                pattern_matches: list[dict[str, Any]] = []
                for match in matches:
                    line_num = content.count("\n", 0, match.start()) + 1
                    pattern_matches.append({
                        "line": line_num,
                        "start": match.start(),
                        "end": match.end(),
                        "matched": match.group(),
                    })
                patterns.append(
                    SensitiveDataPattern(
                        pattern=pattern,
                        category=category,
                        matches=pattern_matches,
                    )
                )
        return patterns

    def _detect_risk_surfaces(self, path: Path, content: str, tree: ast.AST) -> set[str]:
        surfaces: set[str] = set()
        lowered = content.lower()

        for surface, keywords in _RISK_KEYWORDS.items():
            if any(keyword in lowered for keyword in keywords):
                surfaces.add(surface)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name_lower = node.name.lower()
                for surface, keywords in _RISK_KEYWORDS.items():
                    if any(keyword in name_lower for keyword in keywords):
                        surfaces.add(surface)

        return surfaces

    def _extract_tool_signatures(self, path: Path, tree: ast.AST) -> list[dict[str, Any]]:
        signatures: list[dict[str, Any]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params = []
                for arg in node.args.args:
                    params.append(arg.arg)
                signatures.append({
                    "name": node.name,
                    "path": str(path),
                    "line_start": node.lineno,
                    "line_end": getattr(node, "end_lineno", node.lineno),
                    "parameters": params,
                    "is_async": isinstance(node, ast.AsyncFunctionDef),
                })
        return signatures

    def _identify_node_candidates(self, path: Path, tree: ast.AST) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        node_keywords = [
            ("input_node", ["input", "normalize", "parse", "request"]),
            ("rag_retriever", ["retrieve", "search", "rag", "document"]),
            ("tool_node", ["tool", "execute", "call", "action", "api"]),
            ("memory_node", ["memory", "store", "remember", "recall"]),
            ("output_node", ["output", "format", "render", "respond"]),
            ("llm_node", ["agent", "llm", "chat", "invoke", "run"]),
        ]

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name_lower = node.name.lower()
                for node_type, keywords in node_keywords:
                    if any(keyword in name_lower for keyword in keywords):
                        candidates.append({
                            "id": node.name.lower().replace("__", "_"),
                            "type": node_type,
                            "name": node.name,
                            "path": str(path),
                            "line_start": node.lineno,
                            "line_end": getattr(node, "end_lineno", node.lineno),
                            "reason": f"Function name matches {node_type} keywords",
                        })
                        break
        return candidates

    def _detect_framework(self, content: str) -> FrameworkDetection | None:
        for framework, patterns in _FRAMEWORK_PATTERNS:
            evidence: list[str] = []
            for pattern in patterns:
                if pattern in content:
                    evidence.append(pattern)
            if evidence:
                confidence = min(1.0, len(evidence) / len(patterns))
                return FrameworkDetection(
                    framework=framework,
                    confidence=confidence,
                    evidence=evidence,
                )
        return None

    def _calculate_confidence(self, findings: list[StaticAnalysisFinding], candidates: list[dict], framework) -> float:
        base = 0.4
        if framework:
            base += 0.1 * framework.confidence
        if findings:
            base += min(0.2, len(findings) * 0.05)
        if candidates:
            base += min(0.2, len(candidates) * 0.05)
        return round(min(1.0, base), 4)

    def _generate_notes(self, files: list[Path], findings: list[StaticAnalysisFinding], framework) -> list[str]:
        notes = [f"Static analysis completed on {len(files)} Python files."]
        if framework:
            notes.append(f"Detected framework: {framework.framework} (confidence: {framework.confidence})")
        high_severity = [f for f in findings if f.severity == "high"]
        if high_severity:
            notes.append(f"Found {len(high_severity)} high-severity security issues.")
        if not findings:
            notes.append("No security issues detected.")
        return notes


def analyze_source_static(root_path: str | Path, *, exclude_dirs: set[str] | None = None) -> StaticAnalysisResult:
    analyzer = CodeStaticAnalyzer(root_path, exclude_dirs=exclude_dirs)
    return analyzer.analyze()
