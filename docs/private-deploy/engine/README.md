# 旧版引擎参考源码（私有化适配）

> 来源：`ghostlock-57-124-145-project/src`，即 R15 时期的 **C 引擎**（`libghostlock.so` 的源码）。
> 上游当前已是 C++ 重写 + HOCON profile；这份旧引擎之所以保留，是因为私有化部署的核心改动都在这里，
> 而且它有**上游 profile 里不存在的字段**。
>
> 许可证：Apache-2.0（`LICENSE` 取自上游仓库）。本目录只保留源码与偏移表，不含构建产物。

## 目录

```
src/core/            引擎主体（main / fops / util / kernelsnitch / target.h）
src/core/offsets_json.c/h   JSON 偏移加载器（私有化新增）
src/kernels/offsets.h       struct kernel_offsets + known_offsets[] 调度表
src/kernels/<release>/offsets.h  3 条设备验证条目
```

## 相对上游的私有化改动

1. **内建三版本偏移表**
   `src/kernels/offsets.h` 的 `known_offsets[]` 只保留 3 条**真机验证**条目：

   ```
   6.1.57-android14-11-maybe-dirty
   6.1.124-android14-11-maybe-dirty
   6.1.145-android14-11-maybe-dirty
   ```

   上游那 42 条未经真机验证的内建条目不再参与匹配。匹配规则是 `uname -r` **全串** `strcmp`。

2. **`offsets_json.c`：JSON 与内建表合并**
   加载 `offsets.json` 时，先以命中的内建条目为底，再让 JSON 覆盖它**实际出现**的键。
   这样旧 JSON 里缺 `off_tp_sys_exit_*` 时不会把内建值清零（早期版本曾因此让 VR 阶段必然失败）。

3. **上游缺少的字段：`off_tp_sys_exit_tp` / `off_tp_sys_exit_funcs`**
   这是 `vr.ko` 全局中和用的 `__tracepoint_sys_exit` 与 `funcs` 偏移（6.1 上 `funcs = tp + 0x40`）。
   上游仓库当前代码搜索 `tp_sys_exit` 为 **0 命中**，HOCON profile 里也没有对应键；
   本引擎把它作为 `struct kernel_offsets` 的一等字段，缺省为 0（= 跳过中和）。

4. **vr.ko 处理**
   全局：把 `__tracepoint_sys_exit.funcs` 清零，让 sys_exit 探针不再回调；
   逐任务：清 `thread_info.flags`（覆盖 tag A `+0x06` 与 `0x400` 位）和 tag B `+0x2c` 对齐字。
   两者都在 `src/core/main.c`，日志分别为 `vr.ko neutralize` 与 `VR.ko per-task tags cleared`。

5. **路由选择**
   `mcast_route_selected()` / `tcp_route_selected()` / 否则 pselect；
   `mcast seq=1..15 errno=99、seq=16 成功` 是该路线的正常现象，不要按“失败”处理。

## 字段映射到上游 HOCON

| 本引擎字段 | 上游 profile 键 | 说明 |
|---|---|---|
| `kernel_phys_load` | `kernel_phys_load` | MTK 实测 `0x80000000` |
| `pselect_waiter_shift` | `route … select_stack.waiter_shift` | 本引擎三条路线共用 |
| `compact_waiter` | `route.tcp_zerocopy.compact_waiter` | 6.1 = 1 |
| `mm_struct_sz` | `kernelsnitch.mm_struct_sz` | 1024 |
| `task_*` | `task_struct.*` | 15 个键一一对应 |
| `off_*` | `offset.*` | 绝对/镜像内偏移 |
| `off_tp_sys_exit_tp/funcs` | **无对应键** | 上游缺失，需新增字段或由引擎自行处理 |

## 构建

见 `../build.md`。本目录是**参考源码**，不参与商业工程的 Gradle/native 构建；
商业工程使用的是加密容器（GLT2）版本，两者不要混编。

## 注意

- 偏移是设备/镜像级数据：同一 `uname -r` 不代表同一镜像，换机型必须重新提取。
- `off_slide_*` 只用于日志打印，改错不影响功能，只会误导排障。
- 同一开机周期内不要连续运行第二次；失败后重启再试。
