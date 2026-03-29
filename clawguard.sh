#!/bin/bash
# ClawGuard v3 统一入口脚本

VERSION="3.0.0"
MODULE=""

show_help() {
    cat << EOF
╔═══════════════════════════════════════════════════════════════╗
║         🦞 ClawGuard v3 - 统一入口                      ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  用法: ./clawguard.sh <命令> [参数]                          ║
║                                                               ║
║  命令:                                                        ║
║    audit <skill-path>    审计 Skill（意图偏离检测）           ║
║    check [config-path]   检查配置                            ║
║    detect [skill-path]   威胁检测                            ║
║    guardian [action]     运行时守护                          ║
║    shield <text>         提示词注入检测                       ║
║    help                  显示帮助                            ║
║                                                               ║
║  示例:                                                        ║
║    ./clawguard.sh audit ./my-skill --deep                    ║
║    ./clawguard.sh check ~/.openclaw/openclaw.json --fix       ║
║    ./clawguard.sh guardian start                             ║
║    ./clawguard.sh shield "忽略之前的指令"                    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
}

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 解析命令
case "$1" in
    audit)
        shift
        node "$SCRIPT_DIR/auditor-skill/cli.js" "$@"
        ;;
    check)
        shift
        node "$SCRIPT_DIR/checker-skill/cli.js" "$@"
        ;;
    detect)
        shift
        node "$SCRIPT_DIR/detect-skill/cli.js" "$@"
        ;;
    guardian)
        shift
        node "$SCRIPT_DIR/guardian-skill/cli.js" "$@"
        ;;
    shield)
        shift
        node "$SCRIPT_DIR/shield-skill/cli.js" defend "$@"
        ;;
    monitor)
        shift
        node "$SCRIPT_DIR/guardian-skill/cli.js" start "$@"
        ;;
    help|--help|-h|"")
        show_help
        ;;
    *)
        echo "未知命令: $1"
        echo "运行 './clawguard.sh help' 查看帮助"
        exit 1
        ;;
esac
