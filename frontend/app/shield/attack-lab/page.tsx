'use client'
import { useState } from 'react'
import { ShieldLayout } from '@/components/app-shell'
import { ATTACKS, runAttack, resetGateway, passed, type Attack, type AttackResult } from '@/lib/attacks'
import { Play, RotateCcw, ShieldAlert, ShieldCheck, ShieldX, LoaderCircle } from 'lucide-react'

type Progress = { id: string; done: number; total: number } | null

function Lab() {
  const [results, setResults] = useState<Record<string, AttackResult>>({})
  const [running, setRunning] = useState<string | null>(null)
  const [progress, setProgress] = useState<Progress>(null)
  const [all, setAll] = useState(false)
  const [note, setNote] = useState('')

  async function fire(a: Attack) {
    setRunning(a.id)
    setProgress(null)
    const r = await runAttack(a, (done, total) => setProgress({ id: a.id, done, total }))
    setResults((x) => ({ ...x, [a.id]: r }))
    setRunning(null)
    setProgress(null)
  }

  async function runAll() {
    setAll(true)
    setNote('')
    setResults({})
    for (const a of ATTACKS) {
      await resetGateway() // fresh counters, so one attack cannot affect the next
      await fire(a)
      await new Promise((r) => setTimeout(r, 150))
    }
    await resetGateway()
    setAll(false)
  }

  async function reset() {
    const ok = await resetGateway()
    setNote(ok ? 'Gateway state cleared: IP blocks, strikes and rate limits reset.' : 'Reset failed. Is the backend running in development mode?')
  }

  const done = ATTACKS.filter((a) => results[a.id])
  const passes = done.filter((a) => passed(a, results[a.id])).length
  const busy = running !== null || all

  function outcome(a: Attack) {
    const r = results[a.id]
    return r.blocked ? 'BLOCK' : 'ALLOW'
  }

  function copyMarkdown() {
    const rows = done.map((a) => {
      const r = results[a.id]
      return `| ${a.name} | ${a.expected} | ${outcome(a)} | ${r.code ?? '-'} | ${r.riskScore ?? '-'} | ${passed(a, r) ? 'PASS' : 'FAIL'} |`
    })
    const md = ['| Attack | Expected | Actual | Code | Risk | Result |', '|---|---|---|---|---|---|', ...rows, '', `Score: ${passes}/${done.length}`].join('\n')
    navigator.clipboard.writeText(md)
    setNote('Results copied as a Markdown table.')
  }

  return (
    <>
      <div className="mb-8">
        <div className="flex items-center gap-3">
          <h1 className="text-[27px] font-semibold tracking-tight sm:text-[32px]">Attack Lab</h1>
          <span className="rounded-md border border-rose-500/20 bg-rose-500/10 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-rose-300">Live</span>
        </div>
        <p className="mt-2 text-sm text-[#8090a0]">Fire real attacks at your own API and watch Aegis respond.</p>
      </div>

      <div role="note" className="mb-6 flex gap-3 rounded-xl border border-amber-500/25 bg-amber-500/[.06] p-4">
        <ShieldAlert size={17} className="mt-0.5 shrink-0 text-amber-300" />
        <div>
          <p className="text-sm font-medium text-amber-200">These are real requests against your own backend.</p>
          <p className="mt-1 text-xs leading-relaxed text-[#91a0af]">After 5 blocked requests your IP is blocked for a few minutes. Use Reset gateway state to continue. Run all resets automatically between attacks.</p>
        </div>
      </div>

      <div className="mb-5 flex flex-wrap items-center gap-3">
        <button disabled={busy} onClick={runAll} className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-4 py-2.5 text-xs font-semibold text-[#07100d] disabled:opacity-50">
          {all ? <LoaderCircle size={14} className="animate-spin" /> : <Play size={14} />}Run all attacks
        </button>
        <button disabled={busy} onClick={reset} className="inline-flex items-center gap-2 rounded-lg border border-[#293644] px-4 py-2.5 text-xs font-medium text-[#b1bdc8] hover:bg-[#141d26] disabled:opacity-50">
          <RotateCcw size={14} />Reset gateway state
        </button>
        {done.length > 0 && (
          <button onClick={copyMarkdown} className="rounded-lg border border-[#293644] px-4 py-2.5 text-xs font-medium text-[#b1bdc8] hover:bg-[#141d26]">Copy results</button>
        )}
        {note && <span className="text-xs text-emerald-300">{note}</span>}
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {ATTACKS.map((a) => {
          const r = results[a.id]
          const p = progress && progress.id === a.id ? progress : null
          return (
            <article key={a.id} className="rounded-xl border border-[#1e2a38] bg-[#111821] p-4 sm:p-5">
              <div className="flex items-center justify-between gap-3">
                <span className="rounded-md border border-[#34414d] bg-[#19232d] px-2 py-1 text-[10px] text-[#b8c5cf]">{a.category}</span>
                <span className={`rounded-md px-2 py-1 text-[10px] font-semibold ${a.expected === 'ALLOW' ? 'bg-emerald-500/10 text-emerald-300' : 'bg-rose-500/10 text-rose-300'}`}>Expected: {a.expected}</span>
              </div>
              <h2 className="mt-4 text-sm font-semibold">{a.name}</h2>
              <p className="mt-1 min-h-10 text-xs leading-relaxed text-[#82909f]">{a.description}</p>

              {p && (
                <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-[#1c2833]">
                  <div className="h-full bg-emerald-400 transition-all" style={{ width: `${(p.done / p.total) * 100}%` }} />
                </div>
              )}

              <div className="mt-4 flex items-center justify-between border-t border-[#1e2a38] pt-3">
                <span className="text-[10px] text-[#748292]">
                  {r ? (
                    <span className={`flex items-center gap-1.5 ${passed(a, r) ? 'text-emerald-300' : 'text-rose-300'}`}>
                      {passed(a, r) ? <ShieldCheck size={13} /> : <ShieldX size={13} />}
                      {outcome(a)} · HTTP {r.status || 'no response'} · {r.latencyMs} ms
                    </span>
                  ) : (
                    'Ready'
                  )}
                </span>
                <button onClick={() => fire(a)} disabled={busy} className="flex items-center gap-1.5 rounded-md border border-[#34414d] px-3 py-1.5 text-[11px] font-medium text-[#d0d8df] hover:border-emerald-500/40 hover:text-emerald-300 disabled:opacity-50">
                  {running === a.id ? 'Running…' : <><Play size={12} />Fire</>}
                </button>
              </div>

              {r && (
                <div className="mt-3 rounded-lg bg-[#0c1319] p-3 text-[11px] text-[#9caab7]">
                  {r.status === 0 ? (
                    <p className="text-rose-300">No response. Check the backend is running and CLIENT_URL matches this page.</p>
                  ) : (
                    <>
                      {r.total > 1 && <p className="mb-1 text-[#c3ced8]">Responses: {Object.entries(r.counts).map(([s, n]) => `HTTP ${s} ×${n}`).join(', ')}</p>}
                      {r.code && <p>Code: <span className="text-[#d0d8df]">{r.code}</span>{r.riskScore !== undefined && <> · Risk {r.riskScore}/100</>}</p>}
                      {r.reasons.map((x) => <p key={x} className="mt-1 break-words text-[#748292]">{x}</p>)}
                      {!r.blocked && <p>Request was allowed through.</p>}
                    </>
                  )}
                </div>
              )}
            </article>
          )
        })}
      </div>

      {done.length > 0 && (
        <section className="mt-6 overflow-hidden rounded-xl border border-[#1e2a38] bg-[#111821]">
          <div className="flex items-center justify-between border-b border-[#1e2a38] p-4">
            <h2 className="text-sm font-semibold">Results</h2>
            <span className="text-xs text-emerald-300">{passes}/{done.length} as expected</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] text-left text-xs">
              <thead>
                <tr className="text-[10px] uppercase text-[#748292]">
                  <th className="px-4 py-3">Attack</th><th className="px-4 py-3">Expected</th><th className="px-4 py-3">Actual</th><th className="px-4 py-3">Risk</th><th className="px-4 py-3">Result</th>
                </tr>
              </thead>
              <tbody>
                {done.map((a) => {
                  const r = results[a.id]
                  const ok = passed(a, r)
                  return (
                    <tr key={a.id} className="border-t border-[#1e2a38]">
                      <td className="px-4 py-3">{a.name}</td>
                      <td className="px-4 py-3">{a.expected}</td>
                      <td className="px-4 py-3">{outcome(a)}</td>
                      <td className="px-4 py-3">{r.riskScore ?? '-'}</td>
                      <td className="px-4 py-3"><span className={ok ? 'text-emerald-300' : 'text-rose-300'}>{ok ? 'PASS' : 'FAIL'}</span></td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </>
  )
}

export default function AttackLabPage() {
  return (
    <ShieldLayout>
      <Lab />
    </ShieldLayout>
  )
}