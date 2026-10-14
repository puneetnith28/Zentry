import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useScan } from '@/hooks/useScans'
import { getRecentScans, type RecentScanEntry } from '@/utils/recentScans'
import { calculateRiskScore, riskScoreLabel } from '@/utils/scanResults'
import { formatDateTime, truncateId } from '@/utils/format'

function HistoryRow({ entry }: { entry: RecentScanEntry }) {
  const { data } = useScan(entry.scanId)
  const status = data?.status ?? 'PENDING'

  const risk = useMemo(() => {
    if (!data?.result?.summary) return { label: 'PENDING', score: 0 }
    const score = calculateRiskScore(data.result.summary)
    return { label: riskScoreLabel(score), score }
  }, [data])

  return (
    <tr className="border-b-2 border-black hover:bg-[#bce7fd]/30 font-mono text-xs">
      <td className="p-3 border-r-2 border-black font-bold">
        {truncateId(entry.scanId)}
      </td>
      <td className="p-3 border-r-2 border-black font-bold text-black underline">
        <Link to={`/scans/${entry.scanId}`}>{data?.target_url ?? entry.targetUrl}</Link>
      </td>
      <td className="p-3 border-r-2 border-black">
        <span
          className={`border border-black px-2 py-0.5 font-black uppercase text-black brutal-shadow-sm ${
            status === 'COMPLETED' ? 'bg-[#8cf0ba]' : status === 'FAILED' ? 'bg-[#ff9de2]' : 'bg-[#fff37a]'
          }`}
        >
          {status}
        </span>
      </td>
      <td className="p-3 border-r-2 border-black font-bold">
        <span className="border border-black bg-white px-2 py-0.5 brutal-shadow-sm">
          {risk.label} ({risk.score}/100)
        </span>
      </td>
      <td className="p-3 border-r-2 border-black text-slate-600">
        {formatDateTime(entry.createdAt)}
      </td>
      <td className="p-3 text-right">
        <Link
          to={`/scans/${entry.scanId}`}
          className="border border-black bg-[#fff37a] px-3 py-1 font-bold text-black brutal-shadow-sm hover:bg-[#ffea40]"
        >
          VIEW RECEIPT ↗
        </Link>
      </td>
    </tr>
  )
}

export function ScanHistoryPage() {
  const [filter, setFilter] = useState<'ALL' | 'COMPLETED' | 'FAILED'>('ALL')
  const recentScans = getRecentScans()

  const filtered = useMemo(() => {
    if (filter === 'ALL') return recentScans
    return recentScans
  }, [filter, recentScans])

  return (
    <div className="min-h-screen bg-[#fffdf5] px-4 py-12 sm:px-8">
      <div className="mx-auto max-w-6xl space-y-8">
        {/* Header */}
        <div className="flex flex-wrap items-baseline justify-between gap-4 border-b-2 border-black pb-6">
          <div>
            <span className="border-2 border-black bg-[#ff9de2] px-3 py-1 font-mono text-xs font-black uppercase text-black brutal-shadow-sm">
              HISTORICAL AUDIT ARCHIVE
            </span>
            <h1 className="mt-3 font-mono text-4xl font-black text-black sm:text-5xl">
              RECORDED SESSIONS.
            </h1>
            <p className="mt-2 font-sans text-sm font-medium text-slate-700">
              Deterministic verification runs stored immutably with full raw diagnostic snapshots.
            </p>
          </div>

          <Link
            to="/scans/new"
            className="inline-flex items-center gap-2 border-2 border-black bg-[#fff37a] px-5 py-3 font-mono text-xs font-black uppercase tracking-wider text-black brutal-shadow hover:bg-[#ffea40] active:translate-x-1 active:translate-y-1"
          >
            <span>+ NEW VERIFICATION</span>
            <span className="text-base font-black">↗</span>
          </Link>
        </div>

        {/* Filters */}
        <div className="flex gap-2 font-mono text-xs font-bold">
          {(['ALL', 'COMPLETED', 'FAILED'] as const).map((mode) => (
            <button
              type="button"
              key={mode}
              onClick={() => setFilter(mode)}
              className={`border-2 border-black px-4 py-2 uppercase brutal-shadow-sm transition ${
                filter === mode ? 'bg-black text-white' : 'bg-white text-black hover:bg-slate-100'
              }`}
            >
              {mode} SESSIONS
            </button>
          ))}
        </div>

        {/* Audit Table */}
        <div className="border-2 border-black bg-white brutal-shadow-lg overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b-2 border-black bg-[#fffdf5] font-mono text-xs font-black uppercase text-black">
                <th className="p-3 border-r-2 border-black">SCAN ID</th>
                <th className="p-3 border-r-2 border-black">TARGET URL</th>
                <th className="p-3 border-r-2 border-black">STATUS</th>
                <th className="p-3 border-r-2 border-black">RISK VERDICT</th>
                <th className="p-3 border-r-2 border-black">TIMESTAMP</th>
                <th className="p-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center font-mono text-sm text-slate-600">
                    NO RECORDED VERIFICATION SESSIONS FOUND.
                  </td>
                </tr>
              ) : (
                filtered.map((entry) => <HistoryRow key={entry.scanId} entry={entry} />)
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
