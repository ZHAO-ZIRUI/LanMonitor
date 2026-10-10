#!/bin/zsh -f
set -eu
set -o pipefail

source_dir=${0:A:h}
python=''
python_given=0
index=1

# 保留原参数交给 Python 校验；帮助在没有 Python 时也能查看。
while (( index <= $# )); do
    case "${argv[index]}" in
        -h|--help)
            cat <<'HELP'
用法：sudo ./macos_install.zsh [选项]
安装 macOS 系统服务，开机运行，进程使用指定普通用户身份。

  --user 用户          运行用户，默认使用 SUDO_USER
  --python 绝对路径    Python 3.9+，应使用长期保留的解释器
  --host 地址          首次默认 127.0.0.1，升级沿用
  --port 端口          首次默认 25400，升级沿用
  --import-data 目录   首次导入数据，须先停止源服务
  --dry-run            只检查并显示安装计划，无需 sudo
  -h, --help           显示帮助

程序：/Library/Application Support/LanMonitor
服务：/Library/LaunchDaemons/io.github.zhao-zirui.lanmonitor.plist
HELP
            exit 0
            ;;
        --python)
            (( index += 1 ))
            if (( index > $# )); then
                print -u2 -- '错误：--python 需要解释器路径。'
                exit 2
            fi
            python=${argv[index]}
            python_given=1
            ;;
        --python=*)
            python=${argv[index]#--python=}
            python_given=1
            ;;
    esac
    (( index += 1 ))
done

if (( ! python_given )); then
    for candidate in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
        if [[ -x "$candidate" && ! -d "$candidate" ]]; then
            python=$candidate
            break
        fi
    done
fi

if [[ "$python" != /* || ! -x "$python" || -d "$python" ]]; then
    print -u2 -- '错误：找不到可执行的 Python 3，请通过 --python 指定 Python 3.9+ 路径。'
    exit 2
fi

exec "$python" -I "$source_dir/macos_install.py" "$@"
