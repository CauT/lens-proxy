// Adapted from REA process identity reader, MIT License, copyright (c) 2026 morluto.
// Only start-identity observation is included; no environment or token reads.
import Darwin
import Foundation

struct ProcessIdentityObservation: Encodable {
  let pid: Int32
  let state: String
  let identity: String?
  let reason: String?
}

private struct ProcessMetadata {
  let identity: String
  let pointerSize: Int
}

struct ProcessSnapshot {
  fileprivate let metadata: [Int32: ProcessMetadata]
  let failure: String?
}

typealias ProcessTableSysctlCall = (
  _ mib: inout [Int32],
  _ output: UnsafeMutableRawPointer?,
  _ size: inout Int
) -> Int32

private func readProcessSnapshot() -> ProcessSnapshot {
  readProcessSnapshot { mib, output, size in
    sysctl(&mib, u_int(mib.count), output, &size, nil, 0)
  }
}

func readProcessSnapshot(
  sysctlCall: ProcessTableSysctlCall
) -> ProcessSnapshot {
  for _ in 0..<3 {
    var mib = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
    var size = 0
    guard sysctlCall(&mib, nil, &size) == 0 else {
      let failure = errno
      return ProcessSnapshot(metadata: [:], failure: "process_table_failed_\(failure)")
    }
    guard size >= MemoryLayout<kinfo_proc>.size,
          size % MemoryLayout<kinfo_proc>.stride == 0 else {
      return ProcessSnapshot(metadata: [:], failure: "process_table_failed_\(errno)")
    }
    var processes = [kinfo_proc](
      repeating: kinfo_proc(),
      count: size / MemoryLayout<kinfo_proc>.stride
    )
    let result = processes.withUnsafeMutableBufferPointer { buffer in
      let output = buffer.baseAddress.map { UnsafeMutableRawPointer($0) }
      return sysctlCall(&mib, output, &size)
    }
    guard result == 0 else {
      let failure = errno
      if failure == ENOMEM { continue }
      return ProcessSnapshot(metadata: [:], failure: "process_table_failed_\(failure)")
    }
    guard size % MemoryLayout<kinfo_proc>.stride == 0 else {
      return ProcessSnapshot(metadata: [:], failure: "process_table_failed_\(errno)")
    }
    let processCount = size / MemoryLayout<kinfo_proc>.stride
    let metadata = Dictionary(
      processes.prefix(processCount).map { process in
        let start = process.kp_proc.p_starttime
        return (
          process.kp_proc.p_pid,
          ProcessMetadata(
            identity: "\(start.tv_sec):\(start.tv_usec)",
            pointerSize: process.kp_proc.p_flag & P_LP64 != 0 ? 8 : 4
          )
        )
      },
      uniquingKeysWith: { first, _ in first }
    )
    return ProcessSnapshot(metadata: metadata, failure: nil)
  }
  return ProcessSnapshot(metadata: [:], failure: "process_table_failed_\(ENOMEM)")
}

func readProcessIdentities(pids: [Int32]) -> [ProcessIdentityObservation] {
  let snapshot = readProcessSnapshot()
  return pids.map { pid in
    guard let metadata = snapshot.metadata[pid] else {
      return unavailableIdentity(
        pid: pid,
        reason: snapshot.failure ?? "process_not_in_snapshot"
      )
    }
    return ProcessIdentityObservation(pid: pid, state: "readable", identity: metadata.identity, reason: nil)
  }
}

private func unavailableIdentity(pid: Int32, reason: String) -> ProcessIdentityObservation {
  ProcessIdentityObservation(pid: pid, state: "unavailable", identity: nil, reason: reason)
}
