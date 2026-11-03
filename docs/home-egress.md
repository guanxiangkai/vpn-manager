# 可选家庭 Internet 出口

家庭 Internet 出口默认关闭。启用后，只有同时满足以下条件的账户才会通过家庭网络访问公网：服务端 `home_internet.enabled=true`、账户拥有 `home` 网络授权、账户为 active/applied，且未被 quarantine。客户端所在局域网优先本地直连，其余已授权内网按隧道路由，Internet 默认流量走家庭出口；具体结果仍取决于客户端路由与分流设置。`work`-only 账户不会得到公网 child、源地址策略、NAT 或公网放行。

家庭出口依赖预先存在的路由表（默认表 150），其中必须同时存在家庭隧道默认路由和 blackhole 默认路由。表缺失、内容不精确或规则所有权冲突时，投影失败并保持隔离。

## 路由与隔离边界

实现只管理 protocol 186、priority 18000/18001 的自有 IPv4 `ip rule`：

- 对家庭授权地址池，非公网目的地仍查主路由表；公网默认目的地查家庭出口表。
- 撤权、隔离或投影失败时，仅删除本能力拥有的规则，不删除其他协议或优先级的规则。
- `home_internet` 未配置时不修改系统策略路由。

原生 IKEv2 的用户名密码不会替客户端修改“发送所有流量”或 DNS 设置。客户端侧的分流开关仍是独立条件。

## 发布与回滚

发布使用 `ops/home_egress_publish.py` 的四阶段事务：

1. `prepare`：部署者显式提供实际模块、附加模块、配置、状态目录、控制 socket、agent service、回滚 Python 和家庭 DNS；附加模块必须与 agent 模块同目录且命名为 `home_egress.py`，以保持相对导入。工具核验当前模块和配置的 SHA-256 基线、候选摘要、配置 JSON、控制 socket 中已应用的账户状态及现有地址池。缺少参数、相对路径、不可执行、Python 版本低于 3.11 或不是 Python 解释器的回滚程序，或无效 IPv4 DNS 均会拒绝。
2. `arm`：创建独立的 systemd 回滚 service/timer，并读回 timer 已激活及 service 精确命令后，才允许切换。timer 使用 `OnActiveSec=20min`；它是本次 unit 激活后的恢复窗口，不是跨 systemd 重启的绝对截止时间。
3. `apply`：再次核验旧 agent 实际就绪后，先安装 fail-closed 阻断规则，再停止并只重启 agent 服务，原子替换目标模块、附加模块和配置。候选 agent 对全部托管账户就绪后才解除阻断。任一失败均保留或调用独立回滚，不能把账户状态文件或凭据回退到旧副本。
4. `accept`：仅在实际业务验证通过后以 CAS 把 journal 标记为 accepted，再停止 timer 并读回其 inactive；如果停 timer 失败，后续 `accept` 必须继续收尾，不能把遗留 timer 视为成功。

例如，以下仅为文档保留地址和合成目录；不能直接用于任何部署：

```sh
python3 ops/home_egress_publish.py prepare \
  --txn-dir /srv/example-vpn/txn-demo \
  --candidate-module /srv/example-vpn/candidate/gateway_agent.py \
  --candidate-extra /srv/example-vpn/candidate/home_egress.py \
  --candidate-module-hash <sha256> --candidate-extra-hash <sha256> \
  --baseline-module-hash <sha256> --baseline-config-hash <sha256> \
  --module-path /srv/example-vpn/runtime/vpn_manager/gateway_agent.py \
  --extra-module-path /srv/example-vpn/runtime/vpn_manager/home_egress.py \
  --config-path /srv/example-vpn/config/gateway.json \
  --state-directory /srv/example-vpn/state \
  --agent-service example-vpn-agent.service \
  --control-socket-path /run/example-vpn/control \
  --rollback-python /usr/bin/python3 --home-dns 192.0.2.53
```

回滚程序独立于候选运行时代码，使用事务中的基线文件、路由规则所有权和控制 socket 读回恢复旧 agent。它不会重启原网关 charon、家庭 OpenVPN、工作 WireGuard 或管理 API。发布本身只会短暂重启受管账户所在的 agent。

### 必须核验实际运行时导入源

不要仅在交互 shell 中执行 venv import 后就认定 service 会加载同一模块。发布前应以 systemd agent 主进程为准，核对其命令行、实际 `PYTHONPATH` 和导入到的 `gateway_agent.py` 路径，再将发布目标的 agent 模块与同目录 `home_egress.py` 绑定到该实际来源，并对这两个文件做 SHA-256 CAS。

`prepare` 的服务存活和控制 socket 状态只是前置条件，不是家庭出口验收。`apply` 后、`accept` 前还必须逐个核验家庭授权地址池的 18000/18001 策略路由、家庭相关 nft 规则及 VICI child 投影；其中任一项缺失都必须回滚，不能接受事务。

## 验证边界

发布前后的 Python 单测、隔离环境检查和独立 rollback smoke 只能证明各自覆盖的代码路径；它们不替代真实运行时验收。公开测试的内网夹具仅使用文档或基准测试保留地址；namespace 场景的公网目的地址只配置在本机隔离 `lo`，绝不访问真实公网。验收应同时覆盖服务的实际导入源、策略路由、nft 规则、VICI child、控制 socket 状态，以及客户端的 DNS、分流和连通性。

macOS 可用绑定隧道接口的请求验证 DNS 和公网访问。Windows 的最近用户实测表明：关闭 `SplitTunneling`、清理 DNS 并重连后家庭出口恢复；这是客户端实测结果，不代替服务端或自动化的全量验收。一次 HTTP 或 TLS 探测失败也不能单独判定 HTTPS 路由失效，应结合目标服务端口、策略路由和重复请求判断。

### 保留的失败模式

若出现“配置已启用、账户显示 applied，但家庭 PBR/nft 投影缺失”，应视为发布失败并执行独立回滚。一个常见原因是发布目标与 systemd agent 实际 `PYTHONPATH` 导入源不一致；因此不得以 shell 中的 venv import 替代服务运行时来源核验。
