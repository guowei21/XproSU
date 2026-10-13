# U验证 自建服务端 · 部署与对接文档

- 文档版本：2026-10-11（第 2 版，新增「试用」全链路、批量脚本、调试工具）
- 服务端对外地址：见 `server/gl-license/config.json` 的 `uverif.base_url`
  （CDN 回源 IP / 源站端口属于服务器内部信息，**不写进本文档**）
- 客户端工程：GhostLock（`D:\XM\免解\ghostlock-product`）
- 服务端源码：https://github.com/51154393/uverif （Apache-2.0，PHP + Uephp 框架）

---

## 1. 总览

| 项 | 值 |
| --- | --- |
| 后台地址 | 服务器内部记录，**不写进本文档** |
| 后台账号 / 密码 | 见密码管理器，**本文档不保存** |
| 应用名 | `GhostLock` |
| 应用 ID | 见 `config.json` 的 `uverif.app_id` |
| 应用密钥 | 见 `config.json` 的 `uverif.app_key` |
| 版本索引 | 见 `config.json` 的 `uverif.app_index` |
| 版本号 | 见 `config.json` 的 `uverif.app_ver` |
| AES 密钥 | 见 `config.json` 的 `uverif.aes_key`（16 字节） |
| 数据库 | 库 `uverif`，用户 `uverif`，密码见 `/opt/uverif/.dbpass` |
| 表前缀 | `uss_` |

> **为什么这里不写明文凭据**：本文档位于交付工程目录内，会被打包、备份、转发。
> 唯一保存真实凭据的地方是服务器上的 `server/gl-license/config.json`（不入库、不随包分发）。

---

## 2. 服务端部署

### 2.1 架构（最低占用，三容器 + Docker 网络 `uverif-net`）

| 容器 | 镜像 | 端口 | 内存上限 | 实测占用 |
| --- | --- | --- | --- | --- |
| `uverif-web` | `nginx:alpine` | **0.0.0.0:8080** | 48 M | ~3.5 MiB |
| `uverif-php` | `uverif-php:7.4`（自建，72.4 MB） | 内部 9000 | 160 M | ~6.1 MiB |
| `uverif-db` | `mysql:5.7` | 内部 3306 | 256 M | ~49 MiB |

合计约 **56 MiB**。宿主 sg：Debian 9 / 2G 内存 / 40G 磁盘。

### 2.2 为什么不用 80/443

按需求不用 80/443（CDN 由你自己配）。源站监听 **8080**；华为云安全组需放行入方向 `8080/TCP`。

### 2.3 PHP 环境

- PHP 7.4.33（`php:7.4-fpm-alpine` 为基座）
- 扩展：`mysqli` / `pdo_mysql` / `curl` / `mbstring` / `opcache`（`json`、`openssl`、`session` 为内置）
- 应用实际不需要 `gd`、`zip`
- MySQL 5.7.44，低内存配置 `/opt/uverif/db/lowmem.cnf`（`innodb_buffer_pool_size=48M`、`performance_schema=OFF`）
- **PHP 时区 = `Asia/Singapore`**（`php/php.ini`），影响 `vipExpDate` 的渲染，见 7.6.3

### 2.4 关键文件

```
/opt/uverif/
├── www/                 # 站点代码（属主 uid 82 = www-data）
│   ├── config/          # config.php(DB) / app.php(站点) / admin.php(管理员) / msg.php(错误码)
│   ├── app/controllers/ # admin.php(后台) api.php(接口) index.php notify.php(支付回调)
│   ├── app/views/       # admin/ 后台视图；index/ 落地页+安装页
│   └── Ue/              # 框架 + tools/(Aes/ip/out/pay/...) + function/
├── nginx/default.conf
├── php/php.ini, php/zz-uverif.conf
├── db/lowmem.cnf
├── tools/uv-call.sh     # 协议调用器（联调/排障，见第 8 节）
├── tools/gen-trial.sh   # 批量生成试用账号（见 7.6）
├── trials/              # gen-trial.sh 输出的码表 CSV
├── .dbpass              # DB 密码（600）
├── .adminpass           # 后台密码（600）
└── README-deploy.md     # 本文档
```

### 2.5 部署时踩的坑（重建时必看）

1. **PHP 镜像必须用 `docker run` + `docker commit` 构建，且构建期加 `--security-opt seccomp=unconfined`**
   否则 `make` 无法执行配方 shell，报 `/bin/sh: Operation not permitted`。
   *运行时不需要 unconfined*（实测 PHP 的 `exec()`/`shell_exec()` 正常）。
2. **commit 时必须显式指定 CMD**，否则会把构建命令带进镜像：
   `--change 'ENTRYPOINT ["docker-php-entrypoint"]' --change 'CMD ["php-fpm"]'`
3. **php-fpm 池里不能写 `listen.allowed_clients = any`**（非法值 → 丢弃所有连接 → 502）。
4. **opcache 必须 `revalidate_freq = 0`** —— 安装程序/后台会改写 `config/*.php`，否则读到旧配置（表现为"账号密码不正确"）。
5. nginx 的 `fastcgi_pass` 用变量 + `resolver 127.0.0.11`，php 容器不在时 nginx 也能启动。
6. **MariaDB 10.6/10.11 在 sg 上起不来**（内核 4.9 + 老 libseccomp → `Can't initialize timers`），故用 `mysql:5.7`（也正好是本应用 `install.sql` 的原生版本）。

### 2.6 重建 PHP 镜像

```bash
docker rm -f uverif-php-build
docker run --name uverif-php-build --security-opt seccomp=unconfined php:7.4-fpm-alpine sh -c '
  apk add --no-cache --virtual .bd $PHPIZE_DEPS curl-dev oniguruma-dev
  docker-php-ext-install -j2 mysqli pdo_mysql opcache
  apk del .bd; rm -rf /var/cache/apk/* /tmp/* /usr/src/* /usr/local/etc/php-fpm.d/www.conf'
docker commit --change 'ENTRYPOINT ["docker-php-entrypoint"]' \
  --change 'CMD ["php-fpm"]' --change 'WORKDIR /var/www/html' --change 'EXPOSE 9000' \
  uverif-php-build uverif-php:7.4
docker rm -f uverif-php-build
```

---

## 3. 与官方协议的差异 + 已打补丁（★ 核心）

### 3.1 结论先说

**官方是支持 AES 的**（后台就有 AES 选项，要求 32 位密钥 + 16 位 IV）。
问题不在"支不支持 AES"，而在**这份 PHP 重写实现的 AES（以及另外 3 处）与官方协议不一致**。
你的客户端（GhostLock）按官方 C/Go/Python/uni-app 四份 SDK 实现，所以必须把服务端对齐到官方协议。

### 3.2 实测证据链（AES 那处）

| 步骤 | 现象 | 推断 |
| --- | --- | --- |
| 用客户端算法（随机 IV 前置）打原版服务端 | `{"code":109,"msg":"签名验证失败"}` | 解密**没报错**（否则是 113），说明解出了东西但内容不对 |
| 分析 | 明文**整体错位一个 CBC 块**，首块是垃圾 | 服务端用**配置里的固定 IV** 解「IV 前置」的密文：`P'₁=D(IV)⊕IV_cfg` 是垃圾，但 `P'₂=D(CT₁)⊕IV = P₁`，其余同理 |
| 改成「取前 16 字节作 IV」 | 签名通过 → 进入业务逻辑 | 证实原版 IV 处理与官方协议不符 |

原版：`openssl_decrypt(hex2bin($data), 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $this->iv)`（固定 IV）
官方协议：`data = hex(IV16 ‖ AES-128-CBC-PKCS7(payload))`（**随机 IV 前置**）

**附带发现**：原版要求 AES 密钥填 **32 字符**，但调用的是 `AES-128-CBC`（**只用前 16 字节**；实测 16 字节与 32 字节密钥密文完全相同），而官方客户端要求**正好 16 字节**。所以那个 32 位校验本身就是坑 —— 我们把密钥设成 `K16+K16`（前 16 位 = 客户端那把），两边才对得上。

### 3.3 四处差异与补丁清单

| # | 差异 | 原行为 | 补丁后 | 改动文件 |
| --- | --- | --- | --- | --- |
| 1 | **AES IV** | 用配置里的固定 IV | 取密文前 16 字节作 IV；失败回退固定 IV | `Ue/tools/Aes.php`（重写 encode/decode） |
| 2 | **API 路径** | 只认 `/api/{appid}/{index}/{api}` | 兼容官方 `/api/user/{appid}/{index}/{ver}/{api}` | `app/controllers/api.php` `index()` |
| 3 | **成功码** | 成功返回 `200` | 成功返回 `0`（官方协议；客户端 `if(code!=0) throw`） | `Ue/tools/out.php` `e()` |
| 4 | **缺 `__heartbeat`** | 接口不存在 → 客户端每 60s 心跳失败会收回本地授权 | 新增 `__heartbeat`（验 token → 返回有效期） | `app/controllers/api.php` |

### 3.4 其他已修项（非协议差异）

| 项 | 原状 | 处理 |
| --- | --- | --- |
| `U_DEBUG` 调试面板 | `index.php`/`admin.php` 里写死 `TRUE`，每页底部渲染 `ue-trace`（泄露引入文件绝对路径 + SQL 日志） | 改为 `FALSE`（`U_ERROR` 一并关） |
| `ip.php` 取客户端 IP | 取 `X-Forwarded-For` **首段**（可被客户端伪造），而 CDN 把真实 IP 追加在**链尾** | 改为优先 `REMOTE_ADDR`（nginx 已配 realip，解析的是链尾）；XFF 退路只取链尾；补 IPv6 |
| 后台入口 | 必须先访问 `admin.php` 才能用 `/admin` | `/admin` 直接可用（该守卫改为自动建会话） |
| `mi_type` 校验笔误 | `'rsa,rc4,ase'` —— **`ase` 是 `aes` 的笔误**，后台根本选不了 AES | 改为 `'rsa,rc4,aes'` |
| `WEB_URL` | 模板值 `http://www.user.com/` | 改为 `https://yz.765163599.xyz/`（支付回调靠它拼） |

### 3.5 回滚

所有改动前都做了备份：

```bash
ls -la /root/*.bak-*
# admin.php.bak-*  api.php.bak-*  Aes.php.bak-*  out.php.bak-*  ip.php.bak-*  app.php.bak-*
```

---

## 4. 后台操作流程（实测通过）

> 后台需带 `appid` cookie 才能操作应用内的资源（版本/卡密/用户/商品）。
> 网页端登录后自动带，用脚本调 API 时要手动加。

### 4.1 建应用

后台 → 应用（首页）→ 创建应用 → 填名称、版本号。
系统自动生成 `app_key = md5(getcode(10).uniqid())`，并自动建一条默认版本行。

### 4.2 配版本（加密方式）

后台 → 版本控制 → 编辑该版本：

| 字段 | 值 | 说明 |
| --- | --- | --- |
| 版本名称 | 默认版本 | |
| **版本索引** | `gl` | 2~16 位字母数字，客户端 `UVERIF_APP_INDEX` 用它 |
| 版本号 | `1.0.0` | 客户端 `UVERIF_APP_VER` |
| **加密方式** | **AES** | 选错成 RC4/RSA/无加密 → 客户端一律连不上 |
| 数据加密 | 开启 | `mi_state=on` |
| 数据签名 | 开启 | `mi_sign=on` |
| 时差校验 | 300 | 秒，允许客户端时钟偏差 |
| **AES 密钥** | **32 字符** | ⚠️ 必须填 32 字符（后台校验），但 **AES-128 只用前 16 字节**。所以填「客户端那把 16 字节密钥 + 再重复一遍」= 32 字符 |
| **AES IV** | 16 字符 | 补丁后服务端从密文前缀取 IV，这里填什么只用于回退 |

例：客户端密钥 `K`（16 字节）→ 后台 `mi_aes_key` 填 `K` 重复两遍（32 字符）。AES-128 只用前 16 字节。

### 4.3 建卡密

1. 后台 → **卡密分组** → 添加：`类型=vip`、`名称`、`面值=2592000`（秒，即 30 天）、`定价`
2. 后台 → **卡密列表** → 生成：选分组、`长度=16`、`数量=N`、**`导出状态=n`**、**`导出类型=txt`**（这两项是必填，漏了会报"导出状态有误"）

### 4.4 ⚠️ 卡密不会自动建号（重要）

**`__logon` 只查 `uss_user` 表**（按 phone/email/acctno + `md5(密码)`），**不会用卡密自动建号**。
`__kamiTopup`（卡密充值）是"**已登录用户**用卡密续期"，也不建号。

所以文档里说的"**卡密即账号，账号名 = 卡密本身，密码同值**"是**运营约定**，需要你在后台为每张卡建一条对应账号：

后台 → **用户管理** → 添加：`账号 = 卡密`、`密码 = 卡密`、`VIP 到期时间 = 期望值`

（实测：给卡 `A72F60C0D1AB01BE` 建了同值账号后，客户端 `logon` 返回 `code 0 登录成功` + JWT token + 有效期。）

**⚠️ 卡密长度约束**：`uss_user.acctno` 是 `varchar(18)`，而 `__logon` 的账号规则要求 **5~18 位字母数字**。
所以后台生成卡密时长度必须 **≤18**（现有卡密是 16 位，如 `A72F60C0D1AB01BE`，正合适）。
**不要**用 gl-license 侧的默认卡密格式 `XXXXX-XXXXX-XXXXX-XXXXX`（23 字符，见 7.6.2）—— 塞不进 `acctno`。

---

## 5. 客户端接入

### 5.1 `local.properties`（★ 2026-10-11 晚已改版）

**App 不再直连 U验证。** 客户端只跟自建授权服务 `gl-license` 说话，所以 APK 里只需要一个地址；
**U验证 的 5 项凭据不进 APK**，它们只写在 `server/gl-license/config.json`（服务端到服务端使用）。

`D:\XM\免解\ghostlock-product\local.properties`：

```properties
# 本机 SDK/构建路径（机器相关，勿外传）
sdk.dir=D:\\XM\\GJ\\android-sdk

# ── 自建授权服务地址（App 唯一的对端）──────────────────────────────────────
# 部署 server/gl-license/ 后，这里填它对外可访问的地址。留空 = 未配置 = 激活明确报错。
# U验证 的 5 项凭据**不进 APK**，它们写在 server/gl-license/config.json 里
# （见 docs/uverif-integration.md）。
LICENSE_BASE_URL=http://127.0.0.1:8787
```

`app/build.gradle.kts` 构建期注入 `buildConfigField("String","LICENSE_BASE_URL", ...)`；
取值顺序：`local.properties` → 同名环境变量 → 空（空即未配置）。

⚠️ **`LICENSE_BASE_URL` 目前仍是 `http://127.0.0.1:8787` 占位** —— `server/gl-license/` **尚未部署到任何机器**。
交付前必须：① 部署 `server/gl-license/`（它才是有 U验证 凭据的那一侧）；② 把 `LICENSE_BASE_URL` 改成它的对外地址；③ 重新 `assembleRelease`。

> **历史**：改版前 `local.properties` 里放的是 6 项 `UVERIF_*`（`UVERIF_BASE_URL` / `_APP_ID` / `_APP_INDEX` / `_APP_VER` / `_APP_KEY` / `_AES_KEY`）。
> 那套已作废，备份在 `local.properties.bak-20261011-uverifurl`。

```powershell
.\gradlew.bat assembleRelease -x :buildGhostlockNative --no-daemon
```

### 5.2 协议（补丁后已对齐）

```
POST {base}/api/user/{app_id}/{app_index}/{app_ver}/{api}
Content-Type: application/x-www-form-urlencoded

body: data=<hex(IV16 ‖ AES-128-CBC-PKCS7(payload))>&sign=<md5(payload + app_key)>
payload: key=value&...&time=<unix 秒>   （time 固定最后）

响应: {"code":0,"msg":"...","time":...,"data":"<hex>","sign":"..."}
  code == 0 为成功；data 用同一把 AES 密钥解密（IV 同样前置）后是 JSON
```

### 5.3 接口

| 接口 | 参数 | 用途 | 实测 |
| --- | --- | --- | --- |
| `logon` | `account` / `password` / `udid` | 卡密登录，返回 `token` + `tokenState` + `info` | ✅ code 0 |
| `heartbeat` | `token` | 保活（客户端每 60s） | ✅ code 0（**本补丁新增**） |
| `info` | `token` | 刷新有效期 | ✅ code 0 |
| `goods` | `token` | 商品列表 | 服务端已有 |
| `order` | `token` | 订单列表 | 服务端已有 |
| `pay` | `uid` / `gid` / `type`(ali\|wx) | 下单 | 服务端已有（见第 6 节） |

### 5.4 客户端侧的两层结构（理解"试用"必须先看清这个）

```
App（GhostLock）
  └─ LicenseClient.kt        ← 二进制 GlBlob 线路，只跟自建授权服务说话
        │  POST /api/activate   (card, device_fp, pubkey, app_ver)
        │  POST /api/heartbeat  (token)
        ▼
自建授权服务 gl-license（Python，工程里 server/gl-license/）
  └─ uverif.py               ← 服务端到服务端，调 U验证
        │  logon(account=card, password=card, udid=device_fp)
        ▼
U验证（yz.765163599.xyz）
```

**App 只认卡密，不认"账号密码"** —— 激活框里填的那串东西就是卡密。
`UVerifClient.kt`（客户端工程里那份）是给联调/自检用的直连 U验证 实现，生产链路走的是 `LicenseClient` + `uverif.py`。

### 5.5 U验证 凭据在哪

**App 侧没有。** 全部在服务端 `server/gl-license/config.json`：

```json
"uverif": {
  "base_url": "https://yz.765163599.xyz",
  "app_id": "1000",
  "app_index": "gl",
  "app_ver": "1.0.0",
    "app_key": "<见服务器上的 config.json，本文档不保存>",
    "aes_key": "<见服务器上的 config.json，本文档不保存>"
}
```

`uverif.py` 构造时校验 `aes_key` 正好 16 字节（`ValueError: uverif aes_key must be exactly 16 UTF-8 bytes`）；
不满足则上游客户端构造失败（`server.py` 里降级为 `uverif = None` → 激活返回 `1004 上游校验服务未配置`）。

---

## 6. 支付对接（现状 + 讨论）

### 6.1 现有支付链路

```
用户(网页) ──token──> __goods   取商品列表
          ──token──> __pay     uid+gid+type(ali/wx)
                         ├─ order_no = YmdHis+5位随机，写 uss_order
                         ├─ notify_url = WEB_URL + notify/{ali|wx}/{order_no}
                         ├─ return_url = WEB_URL + return/{ali|wx}/{order_no}
                         └─ t('pay')->create(...) → 网关下单，返回支付链接/二维码
   用户付款 ─────────────────────────────────────────────────┘
                         │
   网关异步回调 ──> /notify/{ali|wx}/{order_no}   (notify.php)
                         ├─ 查订单 + 幂等(state!=0 直接 success)
                         ├─ t('pay')->notify(type, config) 验签
                         └─ __up()：state=2 + trade_no，按 type 给用户
                                    加 vip / 加积分 / 升代理 → die('success')
```

**网关是插件制**：`Ue/tools/pay/<id>/config.php` 声明配置表单，`<id>Pay.php` 实现 `create()/notify()/verify()/sign()`。
后台 → **支付控制** 里按应用分别配 支付宝 / 微信 的 `state` + `type`(网关ID) + `config`(JSON)。

### 6.2 四个硬伤

| # | 问题 | 证据 |
| --- | --- | --- |
| 1 | **只带一个网关：`jie`（皆网支付）** —— 作者自家聚合，`host = http://www.jienet.com/pay/api`（**明文 HTTP**）。要接支付宝/微信/易支付，**必须自己写插件** | `Ue/tools/pay/` 下只有 `jie/` |
| 2 | **没有面向用户的网页前台** —— `app/views/index/` 只有落地页和安装页；控制器只有 `admin/api/index/notify`。用户**没地方注册、登录、看商品、下单** | 目录实况 |
| 3 | **`return_url` 是死的** —— 指向 `return` 控制器，而 `app/controllers/return.php` **不存在** → 同步跳回落到了首页 | 实测 `/return/ali/TEST` → 落地页 |
| 4 | **支付成功是给「账号」加时长，不发卡密** —— `__up()` 直接 `update uss_user set vip=...`。与"卡密即账号"模式对不上 | `notify.php::__up()` |

回调通道本身是通的：实测 `/notify/ali/TESTORDER` 穿透 CDN 回源返回 `fail`（正常）。

### 6.3 四个可选方案

**方案 A：只做发卡，不做在线支付**（零开发）
后台批量生成卡密 → 第三方发卡平台/群里卖 → 用户拿到卡 → 后台建同值账号 → 客户端激活。
成本最低，无自动发货。

**方案 B：自建最小用户前台 + 第三方聚合支付**（推荐）
1. 写 `Ue/tools/pay/<id>/` 插件对接易支付类（个人可签，支付宝/微信都能收）
2. 写最小前台（注册 / 登录 / 商品 / 下单 / 订单查询），直接调已有 `__reg`/`__logon`/`__goods`/`__pay`/`__order`
3. 改 `__up()`：支付成功后**除加 VIP 外自动生成一张卡密**并在订单里返回
   → 把"支付 → 发卡 → 客户端激活"完整接上

**方案 C：外部收款 + 后台手动发卡**（最省事）
收款走自有渠道，后台手工发卡。适合量小。

**方案 D：把购买做进客户端**
客户端加"购买"页调 `goods`/`pay`，拉起支付宝/微信。
缺点：要改客户端，Android 内拉 H5 支付兼容麻烦；回调仍得服务端处理。

### 6.4 待拍板

1. **手上有什么收款通道？** 支付宝当面付 / 微信 Native / 易支付类聚合 / 个人转账？
2. **要不要"支付后自动发卡"？** 要就必须改 `__up()`。
3. **用户前台要不要做？** 还是只在 App 里买？
4. **收款主体**：个人 or 企业？（决定能接哪些通道）
5. **回调域名**：现为 `WEB_URL=https://yz.765163599.xyz/`，是否需实测完整回调链路。

---

## 7. 「试用」这条线怎么用

### 7.1 一句话结论

**这套系统没有独立的"试用"功能，客户端也没有注册入口。**
所以"试用"只能靠**在 U验证 里预先建好一批短时长账号**（账号 = 密码 = 试用码），
把码发给用户，用户填进客户端激活框 → 到期自动失效。

现成一键脚本：`/opt/uverif/tools/gen-trial.sh`（见 7.6）。

### 7.2 先看清完整链路（为什么"试用码"本质就是"账号"）

```
客户端 App
  │  POST /api/activate    body = GlBlob(card, device_fp, pubkey, app_ver)
  ▼
自建授权服务 gl-license（工程里 server/gl-license/server.py）
  │  server.py:339   self.ctx.uverif.logon(card, card, device_fp_hex)
  │                  ↑ account = card，password = card，udid = device_fp
  ▼
U验证（yz.765163599.xyz）
  │  __logon 按 (acctno 或 phone 或 email) + md5(password) + appid 查 uss_user
  │  返回 info.vipExpTime / info.vipExpDate
  ▼
gl-license
  │  server.py:353  expire = extract_vip_expire(upstream)
  │  server.py:359  expire != 0 且 expire <= now  →  1003「卡密已过期」
  ▼
App 拿到 token + expire + blob + wrapped
```

**关键三点：**

1. **卡密 = U验证 账号 = U验证 密码。** `logon(card, card, ...)` 把卡密同时当账号和密码用。
   → 一张能用的"卡"，本质就是 `uss_user` 里一条 `acctno = 密码 = 卡密` 的记录。
2. **有效期来自 U验证 的 `uss_user.vip`**（渲染成 `vipExpDate`），**不是**卡密表 `uss_kami.val`。
   → `uss_kami` 的 `val` 对这条链路**不起作用**（`__kamiTopup` 只服务"已登录用户续期"）。
3. **U验证 的 `__logon` 会把 `device_fp` 绑进 `client_list`**（`logon_mc_num=1`）。
   但 gl-license **不检查** `tokenState`，且它那侧 `store.bind_card()` 是**无条件覆写** `device_fp`
   → 换机再激活即重绑，**当前链路并不强制单设备**。

### 7.3 三条"看起来像试用"的路，只有一条能走

| 路 | 字段 / 入口 | 能不能用来做试用 |
| --- | --- | --- |
| 应用模式「免费」 | `uss_app.app_mode = 'n'` | ❌ **死字段**。全站只在后台保存/显示出现，`api.php` 从未读取，设了**毫无效果** |
| 注册奖励 | `uss_app.reg_award='vip'` + `reg_award_val=86400` | ⚠️ **逻辑生效，但客户端走不到** —— 客户端只调 `logon`/`heartbeat`/`info`，不调 `__reg` |
| **预建账号** | `uss_user`（`acctno` / `password` / `vip`） | ✅ **唯一可用**（推荐，零开发） |

### 7.4 注册奖励（逻辑生效，但客户端用不上）

`api.php::__reg` 里的逻辑：

```php
if($this->app['reg_award_val'] > 0){          // 奖励事件
    if($this->app['reg_award'] == 'vip'){
        $regData['vip'] = time() + $this->app['reg_award_val'];   // 送 VIP 时长（秒）
    }else{
        $regData['fen'] += $this->app['reg_award_val'];           // 送积分
    }
}
```

**默认 `reg_award='vip'`、`reg_award_val=86400` → 新注册用户自动获得 24 小时 VIP**，这就是"免费试用 1 天"。

配置入口：后台 → **奖励控制**，可配四项（都支持 `会员(秒)` 或 `积分` 两种）：

| 项 | 字段 | 当前值 | 含义 |
| --- | --- | --- | --- |
| 注册奖励 | `reg_award` / `reg_award_val` | vip / 86400 | 注册即送 24h VIP（**这就是注册线的试用**） |
| 受邀请者奖励 | `invitee_award_val` | 43200 | 被邀请者送 12h |
| 邀请人奖励 | `inviter_award_val` | 86400 | 邀请人送 24h |
| 签到奖励 | `diary_award_val` | 100 | 每日签到送 100 积分 |

### 7.5 ⚠️ 当前配置下注册走不通

`reg_way = email` → 注册需要**邮箱验证码**（查 `uss_vcode` 表 + 发信），而 `smtp_state = off`（发信未开）。
所以现在注册会报"验证码为空/不正确"（业务码 118/119）。

要开通注册线，二选一：
- 后台 → **注册登录** → 把 `reg_way` 改成 **`wordnum`**（纯账号密码，无需验证码）
- 或后台 → **发信控制** 配好 SMTP（`smtp_state=on` + 服务器/账号/密码/端口）

另外注册有防刷：`reg_time_ip=24`（同 IP 24h 内不能重复注册）、`reg_time_mc=24`（同机器码 24h）。
（注：`reg_time_mc` 有 bug —— 查的是 `reg_mc` 列但写入的是 `reg_udid`，所以这条**永不命中**。）

### 7.6 推荐做法：批量建「试用账号」（一键脚本）★

脚本：`/opt/uverif/tools/gen-trial.sh`

```bash
# 用法
/opt/uverif/tools/gen-trial.sh <数量> [时长] [前缀]
#   时长: 30m | 24h | 7d | 86400（纯数字=秒）；默认 24h
#   前缀: 纯字母数字，默认 TRIAL

# 例：10 个 24 小时试用码
/opt/uverif/tools/gen-trial.sh 10
# 例：50 个 72 小时试用码，前缀 GLT
/opt/uverif/tools/gen-trial.sh 50 72h GLT
```

**它做的事**：为每一条生成 `acctno = 密码 = 试用码`、`vip = now + 时长`、`appid = 1000` 的 `uss_user` 行，
并把码表写到 `/opt/uverif/trials/trial-<时间戳>.csv`（列：`code,password,expire_unix,expire_local`）。

**发给用户的只有 `code`**（它同时就是密码）。用户在客户端激活框里填进去即可。
后台 → 用户管理 里也能直接看到/禁用这批账号（`ban` 字段设成未来时间戳即封禁）。

#### 7.6.1 实测输出（2026-10-11，已通过）

```text
$ /opt/uverif/tools/gen-trial.sh 2 24h TRL
count=2  duration=86400s  prefix=TRL  expire=2026-10-12 19:45:34
TRL1A193F9DB662
TRLBD494FE236FE
--- csv: /opt/uverif/trials/trial-20261011-194534.csv

$ /opt/uverif/tools/uv-call.sh logon account=TRL1A193F9DB662 password=TRL1A193F9DB662 udid=TEST-UDID-0001
--- payload : account=TRL1A193F9DB662&password=TRL1A193F9DB662&udid=TEST-UDID-0001&time=1791719134
--- resp    : {"code":0,"msg":"登录成功", ...}
--- data    : {"token":"eyJhbGciOiJIUzI1NiIs...","tokenState":"y",
               "info":{"uid":"3","acctno":"TRL1A193F9DB662",
                       "vipExpTime":"1791805534","vipExpDate":"2026-10-12 19:45:34","agent":"0"}}
```

`vipExpTime = 1791805534` = 生成时刻 `1791719134` + `86400` ✅ —— 试用码开箱即用。
（测试用的 2 条已从库里删除，`/opt/uverif/trials/` 已清空。）

#### 7.6.2 长度与字符约束（踩过的坑）

| 约束 | 值 | 来源 |
| --- | --- | --- |
| `acctno` 列宽 | **`varchar(18)`** | `uss_user` 表结构 |
| `logon` 账号规则 | **5~18 位字母数字** | `api.php::__logon`（`wordnum` 规则） |
| `password` 规则 | **6~18 位**，特殊字符只允许 `. - * _` | `Password` 校验规则 |
| ⚠️ **别用 gl-license 默认卡密格式** | `XXXXX-XXXXX-XXXXX-XXXXX` = **23 字符** | `store.py::generate_card_key()`（base32 → 4×5 分组）→ **塞不进 `acctno`** |

→ 试用码请用 **16 位大写字母数字**（和现有卡密 `A72F60C0D1AB01BE` 同风格），脚本已按此生成。
→ 这也意味着：**gl-license 自己 `gen_cards()` 生成的卡，不能直接当 U验证 账号用**，中间得转换/截断。

#### 7.6.3 到期语义（别踩的坑）

| `uss_user.vip` | `vipExpDate` 渲染 | gl-license 侧判定 |
| --- | --- | --- |
| `now + N` | 具体时间 | `expire <= now` → `1003「卡密已过期」` |
| **`0`** | `1970-01-01 07:30:00`（PHP 时区 `Asia/Singapore`） | 解析结果**依赖两端时区**：gl-license 也在 UTC+8 → 得 `0` → 视为"永不过期"；在 UTC → 得负值 → 判为已过期 |

**结论：别用 `vip=0` 做试用**（语义不稳）。要"长期有效"就填一个很大的时间戳（如 `9999999999`），
代码里 `vip = 9999999999` 恰好被当作"永久"处理（见 `__reg` 邀请奖励分支的 `if($inv_res['vip'] != 9999999999)`）。

#### 7.6.4 试用码的运营细节

- **一码一账号**：`acctno` 是唯一键，不要重复生成同码。
- **封禁**：后台 → 用户管理 → 把该账号 `ban` 设为未来时间戳，`logon` 立刻返回 `127`（账号被禁用）。
- **续期**：直接把该行 `vip` 改成新的到期时间戳即可（客户端 `heartbeat`/`info` 会刷新）。
- **批量导出**：`/opt/uverif/trials/*.csv` 直接就是发卡表。
- **限时活动**：`gen-trial.sh 100 1h EVT` 生成 1 小时活动码。

### 7.7 另外三种做法（备选）

1. **后台手工建账号**（量小，零脚本）
   后台 → 用户管理 → 添加：`账号 = 试用码`、`密码 = 同值`、`VIP 到期时间 = 期望值`。
   和 7.6 的脚本等价，只是手动。
2. **试用卡密 + 同值账号**
   卡密分组 `type=vip`、`val=试用时长` → 批量生成卡 → 再批量建同值账号。
   （注意：**卡密本身不会建号**，仍要建账号；且卡密的 `val` 对 gl-license 链路无效，真正生效的是 `uss_user.vip`）
3. **给客户端加注册功能**
   调 `__reg`（需先把 `reg_way` 改成 `wordnum` 并开 `reg_state`）→ 注册即得 `reg_award_val` 试用时长。
   要改客户端（新增注册页 + 调 `reg`），是唯一能让用户"自助领取试用"的路。
4. **`app_mode='n'`（免费）** —— **别用**，是死字段，没有效果。

### 7.8 注册线实测记录（2026-10-11，已通过）

```text
步骤1  后台把 reg_way 从 email 改成 wordnum（email 需验证码，而 smtp_state=off）
步骤2  调 __reg：account=TRIAL193600 / password=TRIAL193600 / udid=TRIAL-UDID-0001
步骤3  响应 {"code":0,"msg":"注册成功"}
步骤4  查库：acctno=TRIAL193600  vip=1791804960
       而注册时刻 now=1791718560，1791718560 + 86400 = 1791804960  ← 正好等于 reg_award_val
步骤5  用该账号 logon → {"code":0,"msg":"登录成功"}
       info.vipExpTime=1791804960  info.vipExpDate=2026-10-12 19:36:00
步骤6  还原 reg_way=email
```

**结论**：注册奖励确实生效，`reg_award_val` 就是"免费试用时长"。新账号注册后立刻可登录，且带上了试用有效期。
但这条路**客户端用不到**（客户端没有注册入口），所以对 GhostLock 而言，**7.6 才是可用的"试用"线**。

---

## 8. 调试工具

### 8.1 `/opt/uverif/tools/uv-call.sh` —— 协议调用器

脱离客户端直接打 U验证 接口，用于联调/排障（依赖 `openssl` / `xxd` / `md5sum` / `curl`，都在宿主上）。

```bash
# 登录（account = password = 卡密）
/opt/uverif/tools/uv-call.sh logon account=A72F60C0D1AB01BE password=A72F60C0D1AB01BE udid=TEST-UDID-0001

# 刷新有效期
/opt/uverif/tools/uv-call.sh info token=<token>

# 心跳
/opt/uverif/tools/uv-call.sh heartbeat token=<token>
```

输出会打印：明文 payload、签名、原始响应、以及**解密后的 data**（JSON）。
脚本内部按补丁后的协议构造 `data=hex(IV16‖AES-128-CBC-PKCS7(payload))` 与 `sign=md5(payload+app_key)`，
所以它同时也是"协议实现正确性"的活体参照。

实测（`uv-call.sh logon ...`）：

```json
{"token":"eyJhbGciOiJIUzI1NiIs...","tokenState":"y",
 "info":{"uid":"1","acctno":"A72F60C0D1AB01BE","vipExpTime":"1794309740",
         "vipExpDate":"2026-11-10 19:22:20","agent":"0"}}
```

### 8.2 `/opt/uverif/tools/gen-trial.sh` —— 批量试用账号

见 7.6。

---

## 9. 运维手册

```bash
# 状态 / 资源
docker ps --filter name=uverif
docker stats --no-stream uverif-db uverif-php uverif-web

# 日志（PHP 错误都打到 stderr）
docker logs --tail 50 uverif-php
docker logs --tail 50 uverif-web

# 数据库
docker exec -e MYSQL_PWD="$(cat /opt/uverif/.dbpass)" uverif-db mysql -uroot uverif -e 'show tables;'

# 查用户 / 试用码
docker exec -e MYSQL_PWD="$(cat /opt/uverif/.dbpass)" uverif-db mysql -uroot uverif -e \
  "select id,acctno,vip,ban from uss_user order by id desc limit 20;"

# 改完 php.ini / 配置后重启
docker restart uverif-php

# 关键表
#   uss_app        应用（app_key/app_mode/reg_award/支付配置）
#   uss_app_ver    版本（ver_key/ver_val/mi_type/mi_key=AES 配置）
#   uss_user       用户（acctno/password=md5/vip/client_list 设备绑定/ban 封禁）
#   uss_kami(_group) 卡密及分组
#   uss_goods      商品（type=vip/fen/agent, val, money）
#   uss_order      订单（state 0=未付 2=已付）
#   uss_vcode      验证码（注册/重置密码/绑定/换绑机器码）
#   uss_agent*     代理/分销
```

---

## 10. 风险与待办

| # | 项 | 说明 |
| --- | --- | --- |
| 1 | **`mi_aes_key` 必须填 32 字符** | 后台校验硬要求，但 AES-128 只用前 16 字节。别在后台把它改成别的 32 字符，否则客户端密钥对不上 |
| 2 | **补丁是直接改源码** | 升级/重装会丢。补丁清单见 3.3 / 3.4，备份在 `/root/*.bak-*` |
| 3 | **卡密 ≠ 账号** | 必须为每张卡建同值账号（见 4.4），否则客户端登录报"账号或密码有误"(126) |
| 4 | **卡密长度 ≤ 18** | `acctno varchar(18)`；gl-license 默认卡密格式 23 字符，不能直接用（见 7.6.2） |
| 5 | **`app_mode` 是死字段** | 别指望"免费模式"生效（见 7.3） |
| 6 | **注册需邮箱验证码** | 当前 `smtp_state=off`，注册走不通；要么改 `reg_way=wordnum`，要么配 SMTP（见 7.5） |
| 7 | **`vip=0` 语义不稳** | 是否"永不过期"取决于两端时区（见 7.6.3）；要永久就填 `9999999999` |
| 8 | **gl-license 侧不强制单设备** | `store.bind_card()` 无条件覆写 `device_fp`，且不检查 U验证 的 `tokenState` → 换机再激活即重绑 |
| 9 | **`return_url` 无控制器** | 同步跳回落到首页；异步回调正常 |
| 10 | **支付网关只有 `jie`** | 且是明文 HTTP 的第三方聚合；正式收款需自写插件 |
| 11 | **8080 直连源站可伪造 XFF** | nginx `set_real_ip_from 0.0.0.0/0`，直接打源站并伪造 `X-Forwarded-For` 能影响 `REMOTE_ADDR`（影响审计日志 IP）。彻底解决需把 `set_real_ip_from` 收窄到 CDN 回源段 |
| 12 | **站点页脚仍是作者署名** | `© 版权所有：Jienet.com 本服务由皆网云提供` |
| 13 | **`LICENSE_BASE_URL` 还是占位** | `local.properties` 里是 `http://127.0.0.1:8787`；`server/gl-license/` **尚未部署到任何机器**。交付前必须部署它并改成对外地址，否则 Release 激活直接报「未配置授权服务」（见 5.1） |
| 14 | **Release 签名未固定** | 换签名可能改 Widevine DRM ID → 已绑定卡密全部失效（客户端工程侧待办） |

---

## 11. 变更记录

| 日期 | 内容 |
| --- | --- |
| 2026-10-11 | 首版：部署 + 4 处协议差异补丁 + 后台流程 + 客户端接入 + 支付讨论 + 试用线初探 |
| 2026-10-11（第 2 版） | 补全 `local.properties` 的 `UVERIF_BASE_URL`；新增 **7.2 完整链路**、**7.6 批量试用账号脚本 gen-trial.sh（含实测）**、**7.6.2 长度约束**、**7.6.3 到期语义**、**第 8 节 调试工具 uv-call.sh**；风险表补 4 条 |
| 2026-10-11（第 3 版） | 对齐客户端改版：App 不再直连 U验证，`local.properties` 由 6 项 `UVERIF_*` 改为单个 `LICENSE_BASE_URL` → **重写 5.1**、**新增 5.5「U验证 凭据在哪」**；风险表补 `LICENSE_BASE_URL` 占位项 |
