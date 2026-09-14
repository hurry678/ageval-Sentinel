"""Tool / Plugin Integrity Verification — Ed25519签名 + Manifest校验。

防止工具篡改、插件投毒、供应链污染。

工作流:
  1. generate_keypair() → 生成 Ed25519 密钥对
  2. sign_tool(tool_path) → sha256 + Ed25519签名 → 生成 manifest.json + signature.sig
  3. verify_tool_integrity(tool_path) → 校验hash + 验签 + 校验manifest
  4. 失败 → 拒绝加载 + 审计日志

manifest.json 格式:
  {
    "tool_name": "db_query",
    "version": "1.0.0",
    "sha256": "abc123...",
    "signer": "security-team",
    "permission_scope": ["db_query.read", "db_query.write"],
    "signed_at": "2026-05-08T..."
  }
"""

import os
import json
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


# ============================================================
# 密钥管理
# ============================================================

def generate_keypair(save_dir: str = None) -> tuple:
    """Generate an Ed25519 keypair for tool signing.

    Args:
        save_dir: Directory to save private key and public key files.
                  If None, keys are only returned, not saved.

    Returns:
        (private_key, public_key_bytes) tuple
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    if save_dir:
        os.makedirs(save_dir, exist_ok=True)
        priv_path = os.path.join(save_dir, "tool_signing_key.pem")
        pub_path = os.path.join(save_dir, "tool_signing_key.pub")

        with open(priv_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(pub_path, "wb") as f:
            f.write(public_bytes)

    return private_key, public_bytes


def load_private_key(path: str):
    """Load Ed25519 private key from PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key_bytes(path: str) -> bytes:
    """Load Ed25519 public key from raw bytes file."""
    with open(path, "rb") as f:
        return f.read()


# ============================================================
# 签名
# ============================================================

def compute_file_hash(path: str) -> str:
    """Compute SHA256 hash of a file."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            sha.update(chunk)
    return sha.hexdigest()


def sign_tool(tool_path: str, private_key, signer: str = "security-team",
              version: str = "1.0.0", permission_scope: list = None,
              output_dir: str = None) -> dict:
    """Sign a tool file and generate manifest.json + signature.sig.

    Args:
        tool_path: Path to the tool Python file
        private_key: Ed25519 private key
        signer: Identity of the signer
        version: Tool version string
        permission_scope: List of permission strings
        output_dir: Directory for manifest.json and signature.sig.
                    Defaults to same directory as tool.

    Returns:
        manifest dict
    """
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(tool_path))

    tool_name = os.path.splitext(os.path.basename(tool_path))[0]
    file_hash = compute_file_hash(tool_path)

    if permission_scope is None:
        permission_scope = [f"{tool_name}.execute"]

    # Build manifest
    manifest = {
        "tool_name": tool_name,
        "version": version,
        "sha256": file_hash,
        "signer": signer,
        "permission_scope": permission_scope,
        "signed_at": datetime.now().isoformat(),
        "tool_path": os.path.basename(tool_path),
    }

    # Write manifest
    manifest_path = os.path.join(output_dir, f"{tool_name}.manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    # Sign manifest content
    manifest_bytes = json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode("utf-8")
    signature = private_key.sign(manifest_bytes)

    sig_path = os.path.join(output_dir, f"{tool_name}.signature.sig")
    with open(sig_path, "wb") as f:
        f.write(signature)

    return manifest


# ============================================================
# 验签与完整性校验
# ============================================================

def verify_tool_integrity(tool_path: str, public_key_bytes: bytes,
                          manifest_dir: str = None) -> dict:
    """Verify a tool's integrity: hash + Ed25519 signature + manifest.

    Checks:
      1. manifest.json exists and is well-formed
      2. signature.sig exists
      3. File SHA256 matches manifest.sha256
      4. Ed25519 signature of manifest is valid

    Returns:
        dict with {valid, checks: {hash_match, signature_valid, manifest_valid},
                   manifest, failures: [...]}
    """
    if manifest_dir is None:
        manifest_dir = os.path.dirname(os.path.abspath(tool_path))

    tool_name = os.path.splitext(os.path.basename(tool_path))[0]
    manifest_path = os.path.join(manifest_dir, f"{tool_name}.manifest.json")
    sig_path = os.path.join(manifest_dir, f"{tool_name}.signature.sig")

    result = {
        "valid": False,
        "tool_name": tool_name,
        "checks": {},
        "manifest": None,
        "failures": [],
    }

    # Check 1: manifest.json exists
    if not os.path.exists(manifest_path):
        result["failures"].append("manifest_missing")
        return result

    # Load manifest
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        result["manifest"] = manifest
        result["checks"]["manifest_valid"] = True
    except (json.JSONDecodeError, Exception) as e:
        result["failures"].append(f"manifest_parse_error: {e}")
        result["checks"]["manifest_valid"] = False
        return result

    # Check 2: signature.sig exists
    if not os.path.exists(sig_path):
        result["failures"].append("signature_missing")
        result["checks"]["signature_exists"] = False
        return result

    result["checks"]["signature_exists"] = True

    # Check 3: File hash matches manifest
    actual_hash = compute_file_hash(tool_path)
    expected_hash = manifest.get("sha256", "")
    hash_match = actual_hash == expected_hash
    result["checks"]["hash_match"] = hash_match
    if not hash_match:
        result["failures"].append(
            f"hash_mismatch: expected={expected_hash[:16]}..., actual={actual_hash[:16]}..."
        )

    # Check 4: Ed25519 signature verification
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        with open(sig_path, "rb") as f:
            signature = f.read()
        manifest_bytes = json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode("utf-8")
        public_key.verify(signature, manifest_bytes)
        result["checks"]["signature_valid"] = True
    except Exception:
        result["checks"]["signature_valid"] = False
        result["failures"].append("signature_invalid")

    # Final verdict
    result["valid"] = len(result["failures"]) == 0
    return result


# ============================================================
# 加载时校验 + 审计集成
# ============================================================

def verify_and_load(tool_path: str, public_key_bytes: bytes,
                    manifest_dir: str = None) -> tuple:
    """Verify tool integrity before loading. Refuse to load if invalid.

    This is the function to call at Agent startup time.
    On failure, writes audit log and refuses to load.

    Returns:
        (allowed: bool, reason: str)
    """
    result = verify_tool_integrity(tool_path, public_key_bytes, manifest_dir)

    if result["valid"]:
        return True, f"Tool '{result['tool_name']}' integrity verified."

    # Write audit log on failure
    try:
        from redsentinel.defenses.engine.security.audit import write_audit_log
        failure_reasons = "; ".join(result["failures"])
        write_audit_log(
            user_id="system",
            role="admin",
            operation="工具完整性校验失败",
            input_content=f"tool={result['tool_name']}",
            result=f"FAILED: {failure_reasons[:150]}",
            risk_level="critical",
        )
    except ImportError:
        pass

    reason = f"TOOL_INTEGRITY_FAILED: {', '.join(result['failures'])}"
    return False, reason


def batch_verify_tools(tool_paths: list, public_key_bytes: bytes) -> dict:
    """Verify multiple tools at once. Returns per-tool results."""
    results = {}
    all_valid = True
    for path in tool_paths:
        r = verify_tool_integrity(path, public_key_bytes)
        results[os.path.basename(path)] = r
        if not r["valid"]:
            all_valid = False
    return {"all_valid": all_valid, "tools": results}
