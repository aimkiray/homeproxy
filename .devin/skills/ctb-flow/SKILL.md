---
name: ctb-flow
description: homeproxy_mi 专用工作流——CTO 编排（拆解/任务书/验收，不亲手改码）；车道分流；规格先行、文件面互斥+无共享可变态并行；P1 规格 = Claude 外聘规格师起稿（隔离 clone 只读，手工径）+CTO 验证；双轨评审 = Claude Code 外聘评审 ∥ 资深评审工程师域面深审；缺陷修复+独立复验闭环；meow -t/双链 204/md5 对账机械化收口；fail-closed/禁项 12 条全程有效。适用本库一切代码改动、深度审计、实机部署级变更。
version: 1.0.0
---

# CTB Flow — homeproxy_mi 适配版

> 本项目首要操作规范；**本文未规定事项一律回退父协议 `cto-flow v1.3.1` 全文裁决**（`C:\Users\laevatain\.agents\skills\cto-flow\SKILL.md`——版本漂移须重核回退语义）。优先级：用户明示指令>本文>父协议——与本文冲突的放宽以用户明示为准并记档偏离。批次首答/任务书/报告声明 `协议：ctb-flow v1.0.0`。
>
> 项目语境：Xiaomi/MiWiFi 路由（OpenWrt 18.06 派生，kernel 5.4，IPQ5332，busybox/ash，`lua 5.1`+`luci.json`+`uci`，iptables/ipset/xt_TPROXY；**无** `ucode`/`nft`/`fw4`/`jq`）。双 meow 实例：meow-c（主，`/var/run/homeproxy/meow-c.yaml`，API :19290）+ meow-los（LOS 链式中继，`/data/other_vol/meow-los/meow-los.yaml`，API :19091）。持久面 `/data/other_vol`（ubifs），`/etc` 为 ramfs——boot 后靠 `boot_restore.sh`（*/5 cron）重建。设备 192.168.31.1，SSH 配方 `SSH_ASKPASS=/tmp/askpass.sh SSH_ASKPASS_REQUIRE=force DISPLAY=:0 ssh -o HostKeyAlgorithms=+ssh-rsa root@192.168.31.1`。

## 0. 车道（先判定再派工；判定主体=CTO，存疑默认非快速）

| 车道 | 判据 | 流程 |
|---|---|---|
| **改码批次**（默认） | 代码/测试/配置改动 | P0→P5 全程 |
| **审计/深审批次** | review/审计/「能否上生产」类 | P0→P1（范围规格即审域切分+覆盖基线：`git ls-files` 审域清单冻结）→P3（纯评审，无实施）→修复批（若授权）→P5；「可上生产」判词须逐文件/逐域结论行+未覆盖清单显形 |
| **研究/实验** | 可证伪声明验证（内核取证、日志分析、流量探针） | P0→P1（声明清单+验收判据）→实施→P3 评审+独立复跑→P5；产出只入 reports/ 或 cto-artifacts 台账不进生产码 |
| **快速通道** | 纯只读问答/咨询/单对象调查 | CTO 直接答，P1-P5 不适用——**一旦要改码立即回 P0 重判车道** |
| **诊断/复现** | 定位根因而非改码（重启归因、泄漏定位） | CTO 亲自只读取证（不改版本内容与既有行为；设备读态允许，写态仍受规则 16 约束），取证记台账；产出修复假设即回 P1 |
| **实机生产面** | 设备写态/不可逆操作（路由侧写文件、二进制替换、sysctl/debugfs 变更、服务重启、firewall 变更、watchdog 参数、reboot） | stage-gate：①备份点（`.bak` 逐件+可回退验证）→②单步执行+即时回读（每步验证落台账）→③观察窗（明示下一个判定点与证伪条件）。**逐段授权+每步回读+台账登记回退点**；用户点名 CTO 亲为→逐字记档追认；本车道只豁免执行者身份，不豁免评审/复验/台账 |

## 1. 角色（封闭集 5 工程师 + CTO + Claude 外聘）

| 角色 | 派工主体 | 边界 |
|---|---|---|
| **CTO**（主代理） | 本会话 | 拆解/任务书/只读取证/调度/验收/汇报/评审报告代录落盘。**不亲手改码**。例外（随动记档追认）：文书面/台账/单行文书勘误/EOL 归一 |
| **规格工程师** | **默认=Claude 外聘规格师**（§4 手工隔离 clone 径）；`subagent_general` 兜底（父协议双候选制：2 名互不可见并行起稿、CTO 择优唯一规格源） | 非平凡批 Claude 起稿→**CTO 验证**采信（§3 P1 清单）；兜底径=Claude 不可用或反馈重起仍不合格→双子代理候选制；**高风险批（实机写态/二进制替换/删除面/远端推送）稿定后加 1 名资深评审工程师 spec 质询** |
| **高级软件工程师** | `subagent_general` | 实施+提交+本域验证；并行前提=**文件面互斥 ∧ 无共享可变外部态**（规则 15——**同一台路由器即共享可变外部态**：两个单元的设备侧写态/服务重启必须串行）；不越域不扩面 |
| **资深评审工程师** | `subagent_general` 默认；`subagent_explore` 仅纯静态审 | 只读对抗审（反例/边界/回归/失败路径/ash 语法面/权限与持久性边界）；**必须未参与**该单元实施；报告**全文回传禁自落盘**（与 Claude 轨并行时自写 `reports/` 撞 untracked 快照闸），落盘一律 CTO 代录（署名+基线 SHA 记档） |
| **缺陷修复工程师** | `subagent_general` | 只修评审列出的项+CTO 裁定项；同一文件不并行，一名串行 |
| **独立复验工程师** | `subagent_general` | findings→CLOSED/PARTIAL/OPEN/NEW 对拍+边界注入+禁项重扫；**未参与实施与修复** |
| **Claude Code（外聘评审/规格师）** | `claude -p` 子进程 | 一次性 clone 内结构性只读（§4）；P3 评审第三声音轨+P1 规格起稿（稿不经 Claude 自验——CTO 验证为闸） |

**独立性阶梯**：评审者≠实施者；复验者≠实施者且≠修复者；修复者同文件串行。
**执行者仲裁**：用户授权「动作」≠授权「执行者身份」——推送/发布/设备重启类默认由 driver 或**未参与该批评审**的高级软件工程师执行；用户点名 CTO 亲为→逐字记档追认。
**explore 降级径**：exec 需求列移交清单（CTO 只读代跑/改派/并入复验，逐条闭环，禁「记档」替代处置）。

## 2. 硬规则（项目钉——违即返工；派工任务书必须内联相关条款）

1. **fail-closed 只收不放**——配置生成败/订阅解析败/firewall 应用败/meow -t 不过一律向「不代理/不劫持/保持现状」裁，绝不写半成品配置、绝不带病重启服务。
2. **生成配置真值面**——`hp.encode_json` 丢 `nil`/`""`/空容器，**必须保留 `false` 与数值 `0`**；生成器键名与 meow schema 逐字一致（`max-connections`/`tcp-idle-timeout`/`tcp-keepalive`/`logbook`/`traffic-ledger`），双实例键同步（meow-c 与 meow-los 同键同值除非有显式理由）。
3. **实机禁项 12 条**——①不弱化既有闸（watchdog/mem_guard/firewall 守卫/NTP REDIRECT）②Lua 5.1 语法面（无 bitops/`goto`/`\`续行/整数除法 `//`）③ash/BusyBox-only（无数组/`[[`/`local -`/`source` 用 `.`，禁 `grep -P`）④设备写态未列任务书副作用清单即禁止 ⑤部署件 `cat>tmp` 后**禁止裸 `mv`**——`cp` 保留目标权限或 `mv` 后 `chmod` 回断言+md5 对账（实证事故：watchdog.sh 失 +x 死 49h）⑥secrets 零文本面（订阅 URL/landing IP/密钥/凭据不进 logs/reports/commits/任务书）⑦`meow -t` 闸门——生成/变更的配置不过 `-t` 不得部署重启 ⑧双实例一致性——加固键（`logbook:false`/`traffic-ledger:false`/`tcp-idle-timeout`/`max-connections`）meow-c 与 meow-los 同步 ⑨firewall 幂等——`firewall.sh` 可重复 apply 不叠规则、teardown 清干净 ⑩持久写量节制——`/data/other_vol` 为 ubifs，分钟级取证载荷保持克制（快照/日志带截断保尾）⑪`ntp_responder.lua` 必须 `settimeout(nil)` 阻塞——**禁写 `settimeout(0)`**（实证事故：非阻塞空转 100% CPU 饿死 procd）⑫ECM 缓解不回退——`front_end_ipv4/6_stop=1`、`sfe_*=0` 保持（`ecm_sfe_common_tuple_set` msleep 楔死实证），如需恢复须用户显式授权+记档
4. **掩码面**——订阅 URL/落地 IP/节点密钥不出 logs/reports/fingerprints/任务书/对外产物任一面。
5. **EOL 不自翻转**——编辑件不得整体换行尾；shell/lua 新件取 LF（路由器 ash/lua 解析面）；存量不动。
6. **先红后绿**——每修复项先失败钉后改绿；生成器/解析器行为变更须先证旧行为有误。
7. **零新依赖**——生产面只用设备既有物（lua/uci/luci.json/curl/iptables/ipset/meow）；不新增任何外部依赖。
8. **凭据不回显**——SSH 用 `SSH_ASKPASS` 配方引用，禁明文口令进命令行/任务书/报告；路由侧凭据文件登记最小存活期。
9. **证据链**——评审/修复/复验报告落盘（项目内 `reports/` 或跨批 `C:\Users\laevatain\Code\cto-artifacts\<batch>\reports\`；explore 回传全文由 CTO 代录；Claude 原始输出落 `reports/claude-*.log`）；台账随动；commit `type(scope): subject`+`Generated with [Devin](https://devin.ai)`+`Co-Authored-By: Devin <158243242+devin-ai-integration[bot]@users.noreply.github.com>`；Claude 产出的 commit 另加 `Co-Authored-By: Claude <noreply@anthropic.com>`。
10. **部署对账**——每次设备侧文件变更：改前 `.bak-<tag>`、改后 `md5sum` 与 repo 源对账、`sh -n`/`lua -p`（或 `luac -p`）语法闸、相关服务链 204 验证；二进制替换走「stop→mv 新件→start→验证」禁 `cp` 覆盖运行中二进制（ETXTBSY）。
11. **判词封闭集**——finding 级 `S>M>m>obs`（obs=观察记档不阻断）；处置 `CLOSED/PARTIAL/OPEN/NEW/LOGGED/WONTFIX`；单元/批次 `PASS/conditional/NO-GO`；GO 仅生产批终审用。父协议词映射：严重→S、中等→M、轻微→m。
12. **收敛加权**——Claude 轨与子代理轨**独立命中同一缺陷**→升一档处置（S 级同证=最高优先+直报用户）。
13. **验证不注水**——验收必须走真命令面（`meow -t`/`curl 204`/`md5sum`/`sh -n`/实机读态）；「断言自身行为」判 m。
14. **命令纪律**——搜索用专用工具不用 shell grep/find；exec 不 `cd`/不重定向/`&&` 串联（设备侧单 SSH 会话内的复合命令除外——减少往返）；后台 `timeout:0`+`get_output`。
15. **并行安全**——前提=文件面互斥 **且** 无共享可变外部态（**路由器本身就是最大共享态**：SSH 写态/服务重启/sysctl/firewall 应用/二进制替换一律串行；只读取证可并行）。
16. **外部副作用白名单制**——未列入任务书副作用清单即禁止（设备写态/git push/gh 写/远端发布/环境改动/sysctl/cron）；突发必要操作**暂停请示**。
17. **删除双验**——不可逆/批量删除（`.bak` 清理/旧二进制/日志归档）：未参与编制者独立重推+差集对账；缓删优先。
18. **版本声明**——批次首答/任务书/报告附 `协议：ctb-flow v1.0.0`；父协议回退锚 `cto-flow v1.3.1`。

## 3. 流程

### P0 澄清+拆解（CTO）
判定车道→拆实施单元（规则 15 前提；设备写态单元默认串行）→判顺序依赖→估并行度→**记档基线**：`PRE_SHA=$(git rev-parse HEAD)`、`git status --porcelain`、设备侧关键件 md5 快照（涉实机批）。用户指令歧义先澄清；「继续」=沿当前计划推进。

### P1 规格（非平凡批→Claude 规格师轨+CTO 验证；高风险批加 spec 质询）
- **主径**：Claude 外聘规格师——隔离 clone 只读起稿（§4 手工径机制：快照/核验/deny/白名单），stdout 规格→落盘 `cto-artifacts\<batch>\spec\`。
- **兜底径**：Claude 不可用或反馈重起仍不合格→**父协议双候选制**：2 名规格工程师 `subagent_general` 互不可见并行起稿（不同子目录 `spec-candidates/A|B`），CTO 择优唯一规格源，落选作废。
- **CTO 验证清单**（采信闸）：①锚点抽验——随机抽 ≥3 处 `文件:行号`/符号引用对码核实 ②需求覆盖对拍 ③验收可证伪——判据可机判非形容词 ④禁项——无凭据值/虚构路径，改动面与任务书不冲突 ⑤硬约束入稿——Lua5.1/ash/双实例键/部署对账惯例。任一项不过→反馈重起一次；再败→降级兜底径。
- **高风险批**（实机写态/二进制替换/删除面/远端推送）：稿定后加 1 名资深评审工程师 spec 质询。
- 自足 spec 最小集照旧：目标/判级词表/文件域划分/验收清单/禁项映射/回退边界；审计批加**冻结审域数 N+覆盖基线清单**。平凡批次（单文件/无新接口/无契约面）任务书即规格——CTO 自足写。

### P2 实施（并行高级软件工程师）
任务书要件 §5。共享文件不并写；设备侧写态按规则 15 串行。

### P3 双轨评审（并发，互不参考）
- **轨 A — Claude 外聘评审**（§4）：整批 diff 静态对抗审。
- **轨 B — 资深评审工程师 ×N**：改码批 N≥实施单元数（按文件域切）；审计批 N=P1 冻结审域数（按审域切）。
- **完整性核验**（findings 采信前）：`git rev-parse HEAD`==PRE_SHA；`git status --porcelain --untracked-files=no` 空；设备侧件（若涉）md5 未被非授权改动；抽 1-2 条 claimed 证据对 diff hunk；抽跑一项便宜验证。
- **收敛判定**：双轨独立命中同证→升档（规则 12）；分歧项列裁决清单交 CTO。

### P4 修复+复验
- 缺陷修复工程师：按 findings+裁定清单修（S>M>m>obs），每项配钉，证据 fail→pass。
- 独立复验工程师：逐项 CLOSED/PARTIAL/OPEN/NEW 对拍+修复引入新伤+禁项 12 条重扫。
- **收口循环**：复验出 NEW/PARTIAL→再评审修复复验（P3b/P4b，轨数可缩但复验独立）。上限 2 轮仍 S/未决→**停报**：报告+台账照落盘、未决项逐项记档处置建议——不硬修不硬合。

### P5 收口（CTO 亲自核验，不信文本；commit/push 由 driver 或显式授权的高级软件工程师执行）
- [ ] `sh -n` 全部涉改 shell 件 / lua 语法闸（`luac -p` 或路由器 `lua` 加载）
- [ ] 生成器变更→设备侧 `homeproxy generate`（或 lua 直跑）+ `meow -f <yaml> -t` 过
- [ ] 服务变更→双链实测：`curl -x 127.0.0.1:5330 …generate_204` + `curl -x 127.0.0.1:12092 …` 均 204
- [ ] 设备侧件 md5==repo HEAD（部署对账，规则 10）；`git status --porcelain --untracked-files=no` 净
- [ ] python 测试（若涉解析面）：`python tests/test_subscription_helpers.py tests/test_ss_parse.py`
- [ ] 报告+台账落盘→commit→push→判词报告（GO/conditional/NO-GO+残余诚实面）

**生命周期**：子代理超时/空回传/无证据回传=静默失败→重派记档（同一 agent_id 可 resume 续跑）；批次中断从最近台账+未决清单续跑；批次开工指纹=PRE_SHA+设备件 md5 快照。

## 4. Claude review（外聘评审轨——手工径，无项目脚本）

**前置**：`claude --version` 可用（`--permission-prompts none` 门槛）；`claude auth status` 已登录/网关可达。冒烟：`claude -p "reply ok" --permission-prompts none`；失败即走 P3 轨 B 单独承担（记档降级，不视为双轨缺失——双轨是目标态，轨 A 不可达时在报告中显式标注）。

**基线**：`PRE_SHA`（P0 记档沿用），工作树净。

**主径（手工隔离 clone）**：

```bash
# <repo-url>=file:/// 前缀+`git rev-parse --show-toplevel` 的 posix 路径
git clone --no-local -q "<repo-url>" "$TEMP/hp-review-<ts>"
git -C "$TEMP/hp-review-<ts>" remote remove origin
```

clone 无本地 config/无有效 hooks/无凭据文件/无未跟踪档，**remote 移除切断回推主库径**；评完弃之。审未提交改动时 driver 预置：主树 `git diff --output=%TEMP%/x.patch PRE_SHA` → clone `git apply x.patch`，或先 commit 成 range。

**调用**（exec `workdir`=clone 根、`timeout:0` 后台、`get_output` 轮询）：

```bash
claude -p "/code-review high <BASE>...HEAD" \
  --model opus --effort medium \
  --allowedTools "Bash(git status:*),Bash(git diff:*),Bash(git log:*),Bash(git show:*),Bash(git rev-parse:*),Bash(git merge-base:*),Bash(git ls-files:*),Bash(gh pr view:*),Bash(gh pr diff:*),Bash(gh pr checks:*)" \
  --disallowedTools "Edit,Write,NotebookEdit,Read(**/.env*),Read(**/*.env),Read(**/state/**),Read(**/*token*.json),Read(**/sub-a.yaml),Read(**/meow-los.yaml),Bash(git push:*),Bash(git commit:*),Bash(git add:*),Bash(git reset:*),Bash(git clean:*),Bash(git checkout:*),Bash(git switch:*),Bash(git rebase:*),Bash(git apply:*),Bash(git rm:*),Bash(git stash:*),Bash(git update-ref:*),Bash(git branch:*),Bash(git remote:*),Bash(git tag:*),Bash(git config:*),Bash(git fetch:*),Bash(git pull:*),Bash(git merge:*),Bash(curl:*),Bash(wget:*),Bash(ssh:*),Bash(scp:*),Bash(rm:*),Bash(mv:*),Bash(cp:*),Bash(mkdir:*),Bash(sed -i:*),Bash(*>*)" \
  --permission-prompts none --max-budget-usd 5.0
```

- `<BASE>`=P0 记档 PRE_SHA；**必须显式三点 range**。
- deny 面随项目适配：凭据/订阅件禁读（`sub-a.yaml`/`meow-los.yaml` 含落地 IP 与密钥）、**`ssh`/`scp` 整体禁**（防触实机）、写面全剔。
- `/code-review` 强项=correctness+regression；**涉掩码/禁项面的批次改用 fallback 四维 prompt**。

**Fallback**（自然语言四维，涉安全/掩码/禁项面必用）：

```text
对 merge-base(<BASE>) 到 HEAD 的 diff 做只读 code review。
只分析：不修改任何文件、不改 git 状态、不发 GitHub 评论、不跑构建/测试、不触设备。
四维度证伪：
1. correctness — 逻辑错误、异常吞、竞态/锁序、fail-open 方向
2. regression — 既有行为破坏、生成配置键漂移、双实例键失同步、契约翻转未追认
3. safety — 掩码泄漏（订阅 URL/落地 IP/密钥落文本面）、fail-closed 失守、实机禁项 12 条违禁（本文规则 3）
4. conformance — Lua 5.1/ash-BusyBox/EOL/set -u/变量引用/幂等 firewall
每条 finding：file:line + 问题 + 严重度(S/M/m) + 置信度(0-100) + 修复方向；过滤 <70。
```

**findings 接入**：driver 去重+置信度过滤→并入修复清单；与子代理轨同证→收敛升档；分歧列裁决清单。Claude 非零退/输出空/截断→查因由重试一次，仍败记档降级。

**完整性核验**（采信前）：主树 `git rev-parse HEAD`==PRE_SHA、`git status --porcelain --untracked-files=no` 零改动、`git for-each-ref`/`git config --local --list`/`.git/hooks/` 快照未变；异常时 clone 保留待查，否则弃之。

## 5. 任务书要件（自足——子代理无会话上下文）

绝对路径域｜执行 profile 名｜基线 commit SHA｜判级词表｜硬规则相关条款｜授权面（文件域/设备侧路径域/副作用清单——**未列即禁**；设备写态逐条列）｜上游依赖产物位置｜交付物格式+落盘路径｜验收对账基线出处（P0 计数/设备 md5 快照）｜红→绿钉要求｜EOL 纪律｜SSH 配方（引用 `/tmp/askpass.sh`，禁明文口令）｜「不」清单（不越域/不扩面/不推 push 未授权/不加依赖/不动 git config·hooks·remote/不发对外产物/不删文件未授权/不打印不引用凭据值/**不触设备未列明路径**）。

## 6. 汇报契约

- **进度简报**（批次中）：`单元id 阶段 状态` 一行流。
- **终报告**：批次表（件|commit|实质）→关键实证→台账/判词更新→残余诚实面→下一步立项口；首行 `协议：ctb-flow v1.0.0`。
- **判词如实**：conditional/NO-GO 措辞直给，残余 m/obs 项与文档化边界全列，不粉饰「全绿」。

## 7. 反模式（命中即返工；与硬规则互见条款不重复列）

- **AP-1** 报告未落盘只存对话（规则 9）
- **AP-2**「无法验证」记档替代移交闭环（§1 explore 径）
- **AP-3** Claude 轨替代子代理轨（或反之）——双轨目标缺一不可互替（轨 A 前置不可达须显式记档降级）
- **AP-4** review 后未核 HEAD/净树/设备 md5 即采信 findings（P3 核验清单）
- **AP-5** 同一文件并行写 / 设备侧写态并行（规则 15）
- **AP-6** 假验证充证据——`meow -t` 未真跑、`curl` 未真发、md5 凭记忆（规则 13）
- **AP-7** EOL 静默翻转（规则 5）/ 部署裸 `mv` 丢权限（规则 3⑤）
- **AP-8** 为放行弱化既有闸 / 生成器断言翻转未事前批准（规则 1/6）
- **AP-9** 凭据值进任务书/日志/报告/Claude 可读面（规则 8/§4 禁读集）
- **AP-10** Claude 规格稿未过 CTO 验证清单即采信 / 稿锚点虚构未抽验（§3 P1）
- **AP-11** 设备侧读态冒充写态验证——「文件在」不等于「权限对」（`[ -x ]` 门静默失败实证）；部署后必须实测调用面而非仅 ls

## 变更记录

| 版本 | 摘要 |
|---|---|
| 1.0.0 | 自 `commodity-trade-brief` ctb-flow v1.3.0 移植适配 homeproxy_mi：车道「实盘资金面」→「实机生产面」（stage-gate 备份/回读/观察窗）；禁项 12 条全量项目化（部署权限/双实例键同步/meow -t 闸/ECM 缓解/NTP 阻塞语义——全部源自真实事故钉）；规则 10 双端推送→部署对账（.bak+md5+语法闸+双链 204）；规则 15 明示「路由器=最大共享可变外部态」；§4 改手工隔离 clone 径（无项目脚本）+禁读集换订阅/LOS 件+ssh 整体 deny；P5 收口换 `meow -t`/双链 204/sh -n/md5/python 测试五件套；新增 AP-11（读态冒充写态验证）；规格兜底回父协议双候选制；版本声明改 ctb-flow v1.0.0 |
