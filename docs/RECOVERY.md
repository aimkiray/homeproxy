# 断网恢复手册（meow-kernel 分支）

homeproxy **从不接管**目的为路由器本机的流量（`firewall.sh` `emit_local`：`--dst-type LOCAL -j RETURN` + RFC1918 私网 RETURN）。因此 **SSH(22) 与 Web UI(8910) 在 meow 全死时照常可达**——这是所有恢复手段的前提。

## 决策树

```text
断网（LAN 客户端上不了网）
│  ※ cron 看门狗已在跑：meow-c 持续死亡 → 先 restart 一次 → 仍死则自动降级为直连
│    （sticky 标记 hp_watchdog.degraded，不自愈回切）；恢复接管 = 人工 `homeproxy restart`
│    ※ 不想要全自动可 opt-out：uci set homeproxy.infra.watchdog=0 && uci commit homeproxy（tick 即退、全程静默）
│
├─ A. 路由器本机可达？（ping/SSH/http://<lan-ip>:8910）
│   ├─ 可达 ──→ B/C（几乎总是可达）
│   └─ 不可达（连 DHCP 都没有）──→ D
│
├─ B. Web UI（http://<lan-ip>:8910，无认证，独立 procd 服务）
│   └─ B1【推荐】主节点选 "— none (nil) —" → Apply
│         → start_service 早退 + stop 已全清 → 彻底恢复 (~10s)
│         ✓ nil+restart 已修正为定义内成功（rc=2），不再误报 "restart failed"（G9 已修）
│   ✓ "LAN proxy → disabled" 现亦撤 dnsmasq conf（G3 已修）——可止血，B1 仍最彻底
│
├─ C. SSH（root@<lan-ip>）
│   ├─ C1 标准止血:   homeproxy stop                    # 完整 teardown ~3s
│   ├─ C2 保留配置:   homeproxy main-node nil && homeproxy restart
│   ├─ C3 仅 DNS 坏:  uci set homeproxy.infra.dns_redirect=0 && uci commit homeproxy && homeproxy restart
│   ├─ C4 仅撤接管 / stop 没清干净时的手动补刀:
│   │     homeproxy firewall-stop   # flag→规则→dnsmasq conf 一键同序清除（meow 进程保留供诊断）
│   │     /etc/init.d/firewall reload                   # fw3 全刷兜底
│   │     # 附录·底层等价（firewall-stop 不可用时；顺序不可颠倒——必须先删 flag 再 stop）:
│   │     #   rm -f /var/run/homeproxy/firewall.active
│   │     #   sh /data/other_vol/homeproxy/lib/firewall.sh stop   # 标准包路径: /usr/lib/homeproxy/firewall.sh（resolve_fw fallback 链之一）
│   │     #   rm -f /tmp/dnsmasq.d/homeproxy_*.conf && /etc/init.d/dnsmasq restart
│   │     #   ip rule del fwmark 101 table 100; ip route flush table 100   # 兜底(firewall.sh stop 已含)
│   ├─ C5 永久禁用开机自启（`homeproxy disable` 本批次起在 MiWiFi 上真正生效）:
│   │     homeproxy disable   # = uci config.enabled=0 + commit + stop；
│   │     #                   #   boot_restore 见 enabled=0 不再拉起（web 仍起，留恢复通道）
│   │     # 附录·连钩子一起删（硬切除，disable 之外的更强手段）:
│   │     #   sed -i '/homeproxy\/boot_restore.sh/d' /data/auto_start.sh
│   │     #   crontab -l | grep -v 'homeproxy/boot_restore.sh' | crontab -
│   │     # 温和版: main-node nil + server.enabled=0 → 每次启动早退
│   └─ C6 升级后坏了: install.sh 不落在路由器上，需先拉再滚（本机出口不被接管，WAN 下载可用）:
│   │     curl -fsSL <URL>/install.sh -o /tmp/install.sh && sh /tmp/install.sh --rollback   # 有 BACKUP_TAR 时
│
├─ D. 断电重启（~1-2min，易失态全清）
│   ├─ 配置损坏/生成器坏/meow 坏 ──→ start 校验 abort ──→ ✅ 恢复（不接管）
│   ├─ 配置合法但节点死 ──→ ❌ 断网复现，回 B/C
│   └─ 重启前先 C5 `homeproxy disable`，否则 boot_restore+cron 会拉起
│
├─ E. MiWiFi reset 键（~8s）⚠ /data 大概率存活 → 旧配置复活，断网复现
│   └─ 正确做法：先 C5 `homeproxy disable` 再 reset（/data 存活的 enabled=0 让 boot_restore 不拉起）
│
└─ F. 刷机（官方 U盘救砖/Breed）→ 最终手段
```

## 死法与后果

| 死法 | LAN TCP | LAN UDP | LAN DNS | 自动恢复 |
|---|---|---|---|---|
| meow-c 崩溃且 respawn 用尽 | RST 快速拒绝 | ICMP unreachable | SERVFAIL | 看门狗 ~5-6min 降级直连* |
| meow-c 挂起（进程活 listener 死） | 同左（或 SYN 超时） | 同左 | 同左 | 看门狗 ~5-6min 降级直连* |
| meow-s 死 | 无影响 | 无影响 | 无影响 | procd respawn |
| 生成器/-t 失败 | 无接管 | 无接管 | 正常 | 启动即 abort ✅ |
| 节点死（meow 健康） | 经代理的目的地失败 | 同左 | 正常 | 换节点 |
| 跳点被 fw3 冲掉（meow 健康、flag 在） | 不接管（回落直连） | 同左 | 正常 | 看门狗下一 tick 自动重挂 firewall（不计 fails） |

\* 降级是 sticky 终态（`hp_watchdog.degraded`）：自动回直连后不再回切，人工 `homeproxy restart` 恢复接管（flag 重建即解除标记）。

## 已知缺口（审计 RR1/RR2；本批次已按 docs/spec-recovery-hardening.md 实施修复）

| # | 缺口 | 后果 | 修复落点 |
|---|---|---|---|
| G0 | meow 死后 steering 不回收（无看门狗） | 最常见的持久断网 | `scripts/watchdog.sh` + cron `#homeproxy_watchdog`：连失败→restart 一次→degrade(sticky) |
| G1 | stop teardown 依赖 `$LOG_PATH` 可写 → RUN_DIR 不可写时 firewall.sh stop 被跳过 | 部分清理→黑洞 | init.d `run_fw`：命令替换捕获输出，日志不可写不再阻断 teardown |
| G2 | teardown 依赖 env.sh 解析 firewall.sh 路径 → symlink 断时找不到 | 同上 | `resolve_fw` fallback 链 + flag 先行删除（§3.3 契约顺序） |
| G3 | `lan_proxy_mode=disabled` 只撤流量接管，DNS 仍转发死端口 | UI 误导性止血失败 | dnsmasq conf 加 lan_proxy 门控；stale conf 无条件清（含 nil 早退） |
| G4 | CLI 无 firewall-only teardown 子命令 | 只能记绝对路径 | `homeproxy firewall-stop`（委托 watchdog.sh degrade，含内联 fallback） |
| G5 | `homeproxy disable` 在 MiWiFi 上无效（rc.d 易失+boot_restore 不查 enabled） | 开机必拉起 | `config.enabled` 总开关，boot_restore/CLI 均尊重 |
| G9 | web `main_node=nil`+restart 报 "restart failed"（实际成功） | 误报让用户以为没救回来 | 早退改 rc=2（定义内空跑），web/boot_restore 视 0/2 为成功 |
| G10 | install 验证只看进程不看连通性 | "活着但流量黑"不回滚 | install.sh 验证段加经 mixed 口 generate_204 连通探测（`HP_INSTALL_SKIP_CONN=1` 逃逸） |
