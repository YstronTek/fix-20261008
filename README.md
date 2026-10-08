# games 后门清理与 SSH 凭据更换

交互式、单机运行的修复工具。针对系统账号 `games`（UID 5）被改成 `/root` 家目录、可登录 shell、管理员组成员，并通过 `/etc/sudoers.d/games` 获得免密 sudo 的后门。

**在要修复的服务器上运行，不是在管理电脑上运行。先保存云平台磁盘快照，并确认有可信控制台 / 救援模式。** root 权限失陷后，清除这个入口不能证明整台系统可信；仍应考虑从干净镜像重建、轮换应用与数据库等其他凭据。

## 运行要求

- Debian 或 Ubuntu，Python 3.9+，systemd 管理的 `ssh.service` 或 `sshd.service`；无需 pip 依赖。
- 本地 root 账号的家目录为 `/root`；普通 SSH 服务模式，非 socket activation。
- 已安装 OpenSSH server/client、sudo、passwd、procps、util-linux、tar、systemd。缺少命令时脚本报错，不自动安装软件。
- 交互终端、至少一个可用的新 SSH 公钥，以及管理员电脑上对应的私钥。
- 源码方式需保留整个 `tools/` 目录；单文件方式只需发布的 `fix-games.sh`。不要运行未知来源或未审查的 root 脚本。

脚本不包含任何服务器地址、既有密码、GitHub 账号或预设管理员公钥，也不访问网络获取密钥。

## GitHub raw 一键运行

仓库根目录的 `fix-games.sh` 是自包含入口，内含全部修复模块，不会再逐个下载 Python 文件。下面的地址对应仓库 `miaovpscn/fix-20261008` 的 `main` 分支；需先提交并推送此文件。长期使用时推荐将 URL 中的 `main` 替换为审核过的提交 SHA。

在目标服务器的 Bash 终端中执行：

```bash
set -o pipefail; curl --proto '=https' --tlsv1.2 -fsSL 'https://raw.githubusercontent.com/miaovpscn/fix-20261008/main/fix-games.sh' | sudo bash
```

已经是 root 时，将末尾 `sudo bash` 改为 `bash`。参数同样可传递：

- 只读检查：末尾改为 `sudo bash -s -- --check`。
- 从公钥文件读取：末尾改为 `sudo bash -s -- --key-file /root/new-admin-keys.pub`。
- 查看帮助：末尾改为 `bash -s -- --help`。

启动器从 `/dev/tty` 获取交互输入，因此 `curl` 管道不会吞掉密码或公钥输入。修复仍需用户输入新密码、公钥、`APPLY`，以及在新窗口完成密钥登录后输入 `CONFIRM`，并非无人值守自动执行。没有交互终端时会拒绝修复；请先通过 `ssh -t` 登录目标机。

代码解包到 `0700` 临时目录，以隔离模式启动 Python，退出后清理临时代码；证据备份和已设置的安全恢复任务不依赖这个临时目录。损坏的内嵌归档会在运行修复前被拒绝。**内部 SHA256 只是损坏检查，不是发布者签名，不能替代对下载地址和源码的信任。**

运行前确认 raw 地址可以访问。尚未推送或匿名请求私有仓库时可能返回 404；启动器不负责 GitHub 身份认证，也不会改变仓库可见性。

## 源码运行

在服务器上的本仓库目录中，先检查：

```bash
sudo python3 tools/fix_games_backdoor.py --check
```

`--check` 不修改账号、SSH 配置或授权公钥，不建立备份；正常查询可能产生系统审计记录。这只是针对已知入口及 SSH 策略的检查，不是完整入侵排查。

执行修复并交互粘贴公钥：

```bash
sudo python3 tools/fix_games_backdoor.py
```

也可以指定提前上传的**公钥**文件，支持一行一把：

```bash
sudo python3 tools/fix_games_backdoor.py --key-file /root/new-admin-keys.pub
```

流程：

1. 隐藏输入新的 root 密码，并再次输入确认。至少 12 个字符，不接受换行、NUL 或控制字符。请选择未在其他机器使用过的随机强密码。
2. 未指定 `--key-file` 时，粘贴完整公钥，每行一把，最后输入空行。
3. 检查显示的公钥指纹，输入 `APPLY` 才开始修改。
4. 脚本建立备份、清理后门、设置新密码与新公钥，然后切换 SSH 为仅公钥认证。SSH 端口保持原配置。
5. **保持原连接，在 10 分钟内另开一个终端，按脚本显示的命令用新私钥建立全新 SSH 连接。** 示例：

```bash
ssh -o ControlMaster=no -o ControlPath=none \
  -o PreferredAuthentications=publickey -o PasswordAuthentication=no \
  -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 \
  -p 22 root@SERVER
```

将私钥路径、端口和服务器地址替换为实际值。私钥留在管理员电脑上，不要上传服务器；公钥 `.pub` 不能代替私钥登录。

6. 新连接登录成功后，回到原终端输入 `CONFIRM`。脚本还会检查切换后的 journal，必须存在使用本次指定公钥完成 root 公钥认证的记录，不能仅凭输入确认就提交。

**不要在验证窗口内重启服务器。** 恢复定时器是 systemd transient timer，不保证跨重启恢复；遇到掉电、磁盘故障等情况仍可能需要救援控制台。

## 修改范围

- `games` 存在时：确认其为本地 UID 5；禁用密码，移除所有附加组，恢复 `/usr/games` 与 `/usr/sbin/nologin`，终止 UID 5 的进程。不会移动 `/root` 的文件，也不会新建缺失的 `games` 账号。
- 将 `/etc/sudoers.d/games` 移到受保护的证据目录，检查 sudo 配置与该账号剩余授权。若其他位置仍有 sudo 授权则停止，要求人工调查，不尝试猜测复杂别名规则。
- root 密码通过 `chpasswd` 标准输入设置；不接受命令行密码参数，不把明文密码写进脚本、日志或备份。系统仍正常在 shadow 中保存密码哈希。
- **完全替换 root 的 `authorized_keys`，只保留本次输入的公钥**，而非向旧列表追加；目录 / 文件权限为 `0700` / `0600`。
- 清理主 SSH 配置及其 Include 图中的认证覆盖，包括 `Match` 中的密码例外。全局只允许公钥认证，禁用密码、键盘交互、主机认证及 GSSAPI；禁用外部公钥命令和受信 CA，只使用各用户的 `.ssh/authorized_keys`；禁止 `games` 登录。其他用户的公钥文件不修改。
- 只 reload SSH 服务，不重启 SSH 或业务服务，不清空 / 轮转日志，也不伪造文件时间。

公钥输入支持 Ed25519、RSA、ECDSA 和 OpenSSH FIDO 公钥。每一行都经真实 `ssh-keygen` 校验；重复密钥材料去重。私钥、证书、URL、`command=` / `from=` 等 authorized_keys 选项、混入的无效行均被拒绝。

### 对现有配置的影响

- 使用旧 root 密钥、root 密码、SSH CA 或外部公钥命令的自动化会失去原有认证方式，包括可能依赖这些方式的面板功能。运行前应确认新密钥持有人和自动化迁移方案。
- 新 root 密码在修复成功后**保留用于本机控制台**，但正常 SSH 不接受密码；这不是将 root 密码锁定的脚本。
- 为确保实际部署的 Include 图与预先验证的图相同，Include 通配符会冻结为当前匹配到的、显式排序的文件列表；当前无匹配项变为注释。后续新增 `.conf` 不会自动加载，需维护显式 Include 并重新执行 `sshd -t`。
- 不支持的配置会在变更前拒绝：配置路径符号链接、越出 `/etc/ssh` 的 Include、循环 / 超深嵌套、部分特殊路径语法、非空 `SSHD_OPTS`、运行中的 `sshd -o/-f/-p` 覆盖、socket activation、额外 UID 0 账号或异常 `games` UID。请先人工调查，不要为了绕过检查直接删除相关配置。

## 失败、取消与超时

输入 `APPLY` 前取消：不修改系统配置。

设置新密码之后发生错误、未输入 `CONFIRM`、未发现有效的新密钥登录，或者十分钟验证期限到达时，执行登录恢复：

- 仅对 root 恢复**新密码或新公钥**的 SSH 登录；其他用户仍为仅公钥。
- 不恢复旧 root 密码、旧公钥、`games` 登录能力或免密 sudo 后门。
- 恢复状态会保持，直到你修正问题并重新运行脚本成功完成密钥验证；它不会自行再次关闭密码登录。

清理阶段提前失败时，`games` 可能已被禁用，但 root 密码尚未更新；以脚本实际输出为准。若自动恢复也失败，不要断开现有连接，应通过可信控制台检查报出的恢复脚本与 SSH 配置。

成功提交与恢复操作使用同一个文件锁决定结果，避免超时恢复与用户确认同时覆盖配置。成功后停止恢复定时器，并删除恢复脚本及暂存恢复配置。脚本不生成或保留额外管理员私钥 / 后门密钥。

## 证据与退出码

每次实际修复独立创建 `/root/games-repair-*`（`0700`），其中包含：

- `before.tar`、SHA256：原账号文件及备份、sudo 配置、实际加载的 SSH 配置、原 root 授权公钥和存在的历史 / 登录记账文件。
- `metadata.json`：原文件权限、所有者及修改 / 元数据时间。
- `journal.export`：最近 1000 条 journal 记录；**不是完整日志或磁盘取证镜像**。
- `games.sudoers.quarantined`：发现的后门 sudo 文件。
- `COMPLETE` 或 `RECOVERED`：本次决策结果。

这些文件为 root 保护的数据；备份包含敏感密码哈希，不要公开。**不要直接全量恢复 `before.tar`，否则可能恢复后门。** 不打包常规 SSH 私钥文件。

| 退出码 | 含义 |
| --- | --- |
| `0` | 修复成功；或 `--check` 未发现检查范围内的异常 / 策略缺口 |
| `1` | 用户在 APPLY 前取消；或 `--check` 发现可疑配置 / 还不是仅公钥策略 |
| `2` | 修复未完成，查看具体错误及是否已进入新密码恢复状态 |

单文件启动器另使用 `65` 表示归档损坏 / 解包失败，`69` 表示缺少所需 Python 运行环境；这些情况下不会启动修复。

## 开发验证

每次修改修复模块后，重新生成并发布单文件入口，不要手工修改其中的编码内容：

```bash
python3 tools/build_standalone.py
bash -n fix-games.sh
```


普通用户运行行为测试，需要本机 `sshd` 和 `ssh-keygen`；测试自行生成临时主机密钥，不使用本机私钥：

```bash
python3 -m unittest discover -s tests -v
```

完整 CLI 冒烟使用一次性 Debian rootfs、完整 subordinate UID/GID 映射及独立 mount/PID/network namespace，**不要使用 sudo**：

```bash
python3 tests/fixtures/prepare_rootfs.py --output /tmp/games-smoke-rootfs
python3 tests/smoke_repair.py --rootfs /tmp/games-smoke-rootfs
python3 tests/smoke_repair.py --rootfs /tmp/games-smoke-rootfs --standalone
```

准备过程需要网络，下载官方 Debian OCI 镜像，并只在隔离根文件系统内安装依赖；不会安装本机软件。需要 `unshare`、`newuidmap`、`newgidmap`、`mount`、`ip` 与已配置的 subordinate IDs。

覆盖：真实 SSH 签名登录、真实密码哈希更换、games 进程终止和权限撤销、公钥文件与交互粘贴两条输入路径、重复轮换、旧凭据拒绝、虚假确认 / 主动取消 / 定时恢复，以及密码不回显。

`--standalone` 模式将发布脚本通过真实标准输入管道交给 Bash，并连接控制终端，验证交互密码 / 公钥输入、参数传递、退出状态以及成功 / 失败后的临时代码清理。它不依赖尚未发布的 GitHub URL。

验证边界：隔离测试中的 systemd / journal 传输是测试适配器，它启动真实 sshd、读取真实认证日志并执行生产恢复脚本；未覆盖完整 systemd/journald 集成。fixture 使用 `UsePAM no`，不覆盖 SSH PAM 会话模块；计时器场景提前触发真实恢复命令，不等待完整十分钟。
