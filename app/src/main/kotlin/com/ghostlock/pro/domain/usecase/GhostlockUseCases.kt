package com.ghostlock.pro.domain.usecase

import com.ghostlock.pro.domain.model.CpuPair
import com.ghostlock.pro.domain.repository.GhostlockRepository

class LoadKernelSnapshotUseCase(private val repository: GhostlockRepository) {
    suspend operator fun invoke() = repository.snapshot()
}

class RunExploitUseCase(private val repository: GhostlockRepository) {
    suspend operator fun invoke(
        pair: CpuPair,
        onLog: (String) -> Unit,
    ) = repository.runExploit(pair, onLog)
}
