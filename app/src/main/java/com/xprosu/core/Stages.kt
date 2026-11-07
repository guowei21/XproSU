package com.xprosu.core

/**
 * 12 个运行阶段，锚点取自 0.13.5 的日志解析表。
 * core 只输出文本，UI 侧做子串匹配即可，不需要改 native。
 */
data class StageSpec(val title: String, val anchors: List<String>)

val STAGES: List<StageSpec> = listOf(
    StageSpec("启动", listOf("[core] start")),
    StageSpec("环境检查", listOf("[anchors]", "[info] build=", "[syms]")),
    StageSpec("校准内存", listOf("[ids] trace", "[base] made")),
    StageSpec("泄漏 cred", listOf("[leak] child exec")),
    StageSpec("定位 cred", listOf("[cred] attempt=")),
    StageSpec("设置 SELinux", listOf("stage selinux", "set SELinux permissive")),
    StageSpec("零写 vr.ko", listOf("vr: nulling", "stage vr_sys_exit_funcs")),
    StageSpec("伪造 cred", listOf("stage fake_cred")),
    StageSpec("提权 uid", listOf("stage fake_uid")),
    StageSpec("提权 euid", listOf("stage fake_euid")),
    StageSpec("执行 payload", listOf("exec payload", "[fullshell]", "plant verified")),
    StageSpec("完成", listOf("handoff OK", "ROOT_SHELL_OK")),
)

enum class StagePhase { PENDING, RUNNING, DONE }

data class StageStatus(val title: String, val phase: StagePhase)

/**
 * 线性推进：命中第 N 阶段的锚点就把 0..N-1 标完成、N 标运行中。
 * 完成锚点单独处理，避免 "执行 payload" 里出现 handoff OK 时提前结束。
 */
class StageTracker {
    private var current = -1
    private var completed = -1

    fun reset() {
        current = -1
        completed = -1
    }

    fun snapshot(): List<StageStatus> = STAGES.mapIndexed { i, spec ->
        val phase = when {
            i <= completed -> StagePhase.DONE
            i == current -> StagePhase.RUNNING
            else -> StagePhase.PENDING
        }
        StageStatus(spec.title, phase)
    }

    fun feed(line: String) {
        if (line.isEmpty()) return
        if (line.contains("ROOT_SHELL_OK") || line.contains("handoff OK")) {
            completed = STAGES.lastIndex
            current = -1
            return
        }
        val idx = STAGES.indexOfFirst { spec -> spec.anchors.any { line.contains(it) } }
        if (idx < 0) return
        if (idx > current) {
            completed = maxOf(completed, idx - 1)
            current = idx
        }
    }
}
