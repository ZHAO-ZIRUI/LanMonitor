# LAN Monitor

无第三方运行依赖的内网监测器，支持 Python 3.9+、macOS / Linux。固定监测 `192.168.100.0/24`；页面展示完整 256 格，`.0` 和 `.255` 不参与采集和管理。

## 源码运行

```sh
python3 app.py                       # http://127.0.0.1:25400
python3 manage.py start              # 后台运行
python3 manage.py status
python3 manage.py restart
python3 manage.py stop
```

内网访问可执行 `python3 manage.py restart --host 192.168.100.254`。监听地址及端口保存后沿用，可用 `--port` 调整。服务没有登录认证，能访问服务的设备也能管理记录。

直接运行支持 `--no-scan` 暂停采集、`--database 路径` 和 `--settings 路径`。Linux 采集需要 `iproute2` 和 `iputils-ping`。`Ctrl-C` 或 `SIGTERM` 会正常关闭服务。后台日志按 5 MiB 轮转，保留 3 份归档。`manage.py` 仅管理源码目录的服务。

## macOS 安装

使用长期保留的 Python 3.9+，在源码目录执行：

```sh
./macos_install.zsh --user "$(id -un)" --python "$(command -v python3)" --dry-run
sudo ./macos_install.zsh --user "$(id -un)" --python "$(command -v python3)"
```

安装为系统 LaunchDaemon，开机即运行，无需登录；程序使用指定普通用户身份。首次默认访问 `http://127.0.0.1:25400`，内网访问可加 `--host 192.168.100.254`，端口可加 `--port`。服务没有登录认证，请按实际访问范围选择监听地址。

程序安装到 `/Library/Application Support/LanMonitor`，`current` 指向当前版本，数据独立保存在 `data/`，日志为 `data/server.log`，按 5 MiB 轮转并保留 3 份归档。更新源码后再次运行安装命令即可升级，沿用数据与监听配置。

首次从源码服务迁移数据，先停止源服务，再导入：

```sh
python3 manage.py stop
sudo ./macos_install.zsh --user "$(id -un)" --python "$(command -v python3)" \
  --import-data "$PWD/data" --host 192.168.100.254
```

安装服务由 `launchctl` 管理；重启时依次停止、加载：

```sh
sudo launchctl print system/io.github.zhao-zirui.lanmonitor
sudo launchctl bootout system/io.github.zhao-zirui.lanmonitor
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.zhao-zirui.lanmonitor.plist
```

## 使用与数据

- 绿色表示最近确认在线；黄色表示历史记录；洋红色表示基础设施；斜线表示手动预留。DHCP 池默认 `.5–.99`，可在 Settings 调整。
- 点击地址可查看详情、管理标记及设备备注。备注最多 200 字，按 MAC 关联，设备换 IP 后继续显示。
- 在线依据为 Ping、设备直接返回的名称查询回应或本机接口；ARP 历史缓存只计入“出现过”。未响应不能证明地址空闲。
- 自动清理默认开启：同一 MAC 确认在线后，清除其离线旧地址及标记，保留其他在线地址和备注。
- 删除地址或清空 DHCP 历史会保留备注；清空全部历史会同时清除备注。旧缓存不会恢复已删除记录，后续实际在线证据可以重新记录。
- `data/lanmonitor.sqlite3` 保存设备记录、备注与标记；`data/settings.json` 保存监测设置，`data/server.json` 保存后台监听配置。备份前停止服务，或使用 SQLite 在线备份；运行中的 WAL 数据库不宜只复制主文件。

采集最多并发 4 个 Ping、每秒发起 4 次；缓存和任务队列有界，HTTP 最多 32 个并发请求且连接限时 5 秒。每个数据库只允许一个服务实例。程序只保存最新观测状态，不累计逐次探测日志，也不修改网络接口、路由或 DHCP 配置。

## Host 网络兼容性

原生 Linux Docker Engine 的 host 模式共享宿主机网络命名空间，适合现有采集方式。需满足以下条件：

- 宿主机有已启用的 `192.168.100.1–254` IPv4 接口，容器安装上述系统工具，并允许 Ping 使用 ICMP socket（受用户权限、`ping_group_range` 或 `NET_RAW` 能力影响）。
- 网络允许 mDNS 组播 `224.0.0.251:5353` 与设备单播回复；主路由名称查询使用 `192.168.100.1:53`。设备不提供 PTR 名称或被防火墙阻断时，名称可能为空。
- Web 默认仅监听 `127.0.0.1:25400`；内网访问应绑定宿主机的实际内网 IPv4 地址。host 模式不使用端口映射。
- 数据库与设置所在目录需要可写并持久保存，SQLite 的 WAL、SHM 和锁文件应与数据库放在同一目录。容器内以前台 `app.py` 运行，便于接收停止信号。
- 本机设备名称取运行环境的 hostname；需要显示宿主机名称时，应显式设置容器 hostname。同网段多接口时采用首个匹配接口，需要确认宿主路由与该接口一致。

Docker Desktop 的 host 网络仅提供 TCP/UDP 层面的互通，不能直接访问 macOS/Windows 的宿主接口；当前采集器可能因此暂停采集。兼容性以原生 Linux 的实际接口和网络权限为准。参见 [Docker host 网络说明](https://docs.docker.com/engine/network/drivers/host/)。

## 开发与验证

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python check.py
```

完整检查需要 Node.js 18+（在 `PATH` 中，或通过 `NODE=/路径/node` 指定）。检查包含 Python 3.9 语法兼容、Ruff、Bandit、后端回归、前端语法与异步状态测试。仅运行后端测试可用 `python3 -m unittest discover -s tests -v`。测试使用临时数据、模拟采集和本机随机端口。

入口为 `app.py`，存储、采集、HTTP 分别位于 `store.py`、`scanner.py`、`http_api.py`；维护约束见 [AGENTS.md](AGENTS.md)。
