import argparse
import os
from collections.abc import Callable, Sequence


def run_cli(
    *,
    input_func: Callable[[str], str],
    output_func: Callable[[str], None],
    graph_invoke_func: Callable[..., str],
    clear_history_func: Callable[[str], None],
    role_permissions: dict[str, dict[str, str]],
    get_role_info_func: Callable[[str], dict[str, str]],
    default_role: str,
    read_audit_log_func: Callable[[int], str],
) -> int:
    output_func("=" * 70)
    output_func("AI Security Agent | 企业级终版 | 全链路安全防护")
    output_func(f"当前角色：{get_role_info_func(default_role)['name']} | {get_role_info_func(default_role)['desc']}")
    output_func("q退出 | clear清空记忆 | role切换角色 | log查看审计日志")
    output_func("=" * 70)

    current_role = default_role
    current_user_id = "cli_user"

    while True:
        user_input = input_func("\n请输入问题：").strip()
        command = user_input.lower()
        if command == "q":
            output_func("程序已退出，感谢使用！")
            return 0
        if command == "clear":
            clear_history_func(current_user_id)
            output_func("[OK] 对话记忆已清空（SQLite 持久化状态已重置）")
            continue
        if command == "role":
            output_func("\n可选角色列表：")
            for role_key, role_info in role_permissions.items():
                output_func(f"- {role_key}：{role_info['name']} | {role_info['desc']}")
            new_role = input_func("请输入角色代码：").strip().lower()
            if new_role in role_permissions:
                current_role = new_role
                clear_history_func(current_user_id)
                output_func(f"[OK] 已切换为【{role_permissions[current_role]['name']}】，记忆已清空")
            else:
                output_func("[X] 无效角色代码")
            continue
        if command == "log":
            line_count = input_func("请输入要查看的日志条数（默认20）：").strip()
            count = int(line_count) if line_count.isdigit() else 20
            output_func("\n【最新审计日志】")
            output_func(read_audit_log_func(count))
            continue
        if not user_input:
            output_func("请输入有效问题")
            continue

        try:
            answer = graph_invoke_func(
                user_input=user_input,
                role=current_role,
                user_id=current_user_id,
            )
        except Exception as exc:
            output_func(f"\n【系统错误】：{type(exc).__name__}: {exc}")
            continue
        output_func(f"\n【Agent回答】： {answer}")


def main(
    argv: Sequence[str] | None = None,
    input_func: Callable[[str], str] = input,
    output_func: Callable[[str], None] = print,
) -> int:
    parser = argparse.ArgumentParser(description="Run the interactive RedSentinel defense agent.")
    parser.parse_args(None if argv is None else list(argv))
    os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
    from redsentinel.defenses.engine.agent.graph import clear_history, graph_invoke
    from redsentinel.defenses.engine.security.audit import read_audit_log
    from redsentinel.defenses.engine.security.permission import DEFAULT_ROLE, ROLE_PERMISSIONS, get_role_info

    return run_cli(
        input_func=input_func,
        output_func=output_func,
        graph_invoke_func=graph_invoke,
        clear_history_func=clear_history,
        role_permissions=ROLE_PERMISSIONS,
        get_role_info_func=get_role_info,
        default_role=DEFAULT_ROLE,
        read_audit_log_func=read_audit_log,
    )


if __name__ == "__main__":
    raise SystemExit(main())
