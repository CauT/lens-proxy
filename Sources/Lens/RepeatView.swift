import SwiftUI

struct RepeatTarget: Identifiable { let id = UUID(); let source: TrafficFlow }

struct LensRepeatView: View {
    @ObservedObject var store: LensStore
    let source: TrafficFlow
    @Environment(\.dismiss) private var dismiss
    @State private var count = 3
    @State private var concurrency = 1
    @State private var intervalMs = 0
    @State private var sending = false
    @State private var issue: String?
    @State private var queued = false

    private var currentSource: TrafficFlow? { store.flows(in: source.sessionId ?? store.currentSessionID).first { $0.id == source.id } }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Repeat requests").font(.title2.weight(.semibold))
            if let current = currentSource {
                Text("\(current.method)  \(current.url)").font(.system(.callout, design: .monospaced)).textSelection(.enabled).lineLimit(3)
            } else { Text("The source request is no longer retained.").foregroundStyle(.secondary) }
            Text("Source flow \(source.id)").font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 12) {
                GridRow { Text("Requests"); TextField("Count", value: $count, format: .number).frame(width: 100); Stepper("", value: $count, in: 1...1000).labelsHidden() }
                GridRow { Text("Concurrency"); TextField("Workers", value: $concurrency, format: .number).frame(width: 100); Stepper("", value: $concurrency, in: 1...16).labelsHidden() }
                GridRow { Text("Interval (ms)"); TextField("Interval", value: $intervalMs, format: .number).frame(width: 100); Stepper("", value: $intervalMs, in: 0...60000, step: 100).labelsHidden() }
            }
            Text("Queueing snapshots the current source request for every attempt. Each request passes through your rules and capture settings. At most 4 outgoing requests run at once across all jobs.")
                .font(.caption).foregroundStyle(.secondary)
            if let issue { Text(issue).font(.caption).foregroundStyle(.red) }
            if queued { Text("Repeat job queued. Inspect the job and captured results for completion or failure.").font(.caption).foregroundStyle(.secondary) }
            HStack {
                Button("Close") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button(sending ? "Queueing…" : "Queue \(count) requests") {
                    sending = true; issue = nil; queued = false
                    store.repeatFlow(id: source.id, sessionID: source.sessionId, count: count, concurrency: concurrency, intervalMs: intervalMs) { error in
                        sending = false; issue = error; queued = error == nil
                    }
                }
                    .buttonStyle(.borderedProminent)
                    .disabled(sending || currentSource == nil || !store.isRunning || !(1...1000).contains(count) || !(1...16).contains(concurrency) || !(0...60000).contains(intervalMs))
            }
            Divider()
            Text("Jobs").font(.headline)
            ScrollView {
                VStack(spacing: 12) {
                    ForEach(store.repeatJobs.reversed()) { job in
                        VStack(alignment: .leading, spacing: 7) {
                            HStack {
                                Text(job.state.capitalized).font(.callout.weight(.medium))
                                Spacer()
                                Text("\(job.finishedCount) / \(job.total)").font(.caption.monospacedDigit())
                                if !job.finished { Button("Cancel") { store.cancelRepeat(job) }.buttonStyle(.borderless) }
                            }
                            Text("Job \(job.id) · source \(job.sourceId ?? "Not recorded")").font(.caption).textSelection(.enabled)
                            ProgressView(value: Double(job.finishedCount), total: Double(max(1, job.total)))
                            Text("\(job.completed) completed · \(job.failed) failed · \(job.cancelled) cancelled").font(.caption).foregroundStyle(.secondary)
                        }.padding(12).background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
                    }
                    if store.repeatJobs.isEmpty { Text("No repeat jobs yet.").foregroundStyle(.secondary).frame(maxWidth: .infinity).padding(20) }
                }
            }.frame(height: 180)
        }.padding(24).frame(width: 620)
    }
}
