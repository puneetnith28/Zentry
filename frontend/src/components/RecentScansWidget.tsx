import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useScan } from '@/hooks/useScans'
import type { ScanStatus } from '@/types/scan'
import { formatRelativeTime, truncateId } from '@/utils/format'
import { getRecentScans, type RecentScanEntry } from '@/utils/recentScans'
import { calculateRiskScore, riskScoreLabel } from '@/utils/scanResults'

function RecentRow({ entry }: { entry: RecentScanEntry }) {
  const { data } = useScan(entry.scanId)
  const status: ScanStatus = data?.status ?? 'PENDING'

  const riskLabel = useMemo(() => {
    if (!data?.result?.summary) return 'PENDING AUDIT'
    const score = calculateRiskScore(data.result.summary)
    return riskScoreLabel(score)
  }, [data])

  return (
    <div className="flex flex-wrap items-center justify-between gap-4 border-b-2 border-[#10201d] py-3 px-4 transition hover:bg-[#e97b77]/20">
      <div className="min-w-0">
        <Link
          to={`/scans/${entry.scanId}`}
          className="font-mono text-sm font-black text-[#10201d] underline underline-offset-2 hover:bg-[#e97b77]"
        >
          {data?.target_url ?? entry.targetUrl}
        </Link>
        <div className="mt-1 flex items-center gap-2 font-mono text-[10px] text-slate-700">
          <span className="font-bold">ID: {truncateId(entry.scanId)}</span>
          <span>•</span>
          <span>{formatRelativeTime(entry.createdAt)}</span>
        </div>
      </div>

      <div className="flex items-center gap-2 font-mono text-xs">
        <span className="border border-[#10201d] bg-white px-2 py-0.5 font-bold text-[#10201d] brutal-shadow-sm">
          {riskLabel}
        </span>
        <span
          className={`border border-[#10201d] px-2 py-0.5 font-black uppercase text-[#10201d] brutal-shadow-sm ${
            status === 'COMPLETED' ? 'bg-[#80c4b7]' : status === 'FAILED' ? 'bg-[#e97b77]' : 'bg-[#edd17d]'
          }`}
        >
          {status}
        </span>
        <Link
          to={`/scans/${entry.scanId}`}
          className="ml-2 font-mono text-sm font-bold text-[#10201d] hover:translate-x-1 transition-transform"
        >
          →
        </Link>
      </div>
    </div>
  )
}

export function RecentScansWidget({ className = '' }: { className?: string }) {
  const recentScans = getRecentScans()

  if (recentScans.length === 0) {
    return (
      <div className={`border-2 border-[#10201d] bg-[#f7f3ee] p-8 text-center brutal-shadow ${className}`}>
        <span className="border border-[#10201d] bg-[#e97b77] px-3 py-1 font-mono text-xs font-black uppercase text-[#10201d] brutal-shadow-sm">
          NO RECORDED SESSIONS
        </span>
        <h4 className="mt-4 font-mono text-lg font-black text-[#10201d]">NO ACTIVE RUNS FOUND</h4>
        <p className="mt-1 font-sans text-xs text-slate-700">
          Target assessments and verification records will appear here automatically upon initialization.
        </p>
      </div>
    )
  }

  return (
    <div className={`border-2 border-[#10201d] bg-[#f7f3ee] brutal-shadow-lg overflow-hidden ${className}`}>
      <div className="flex items-center justify-between border-b-2 border-[#10201d] bg-white px-5 py-3">
        <div>
          <span className="border border-[#10201d] bg-[#e97b77] px-2 py-0.5 font-mono text-[10px] font-black uppercase text-[#10201d] brutal-shadow-sm">
            VERIFIED AUDIT LOG
          </span>
          <h4 className="mt-1 font-mono text-base font-black text-[#10201d]">
            RECORDED SECURITY SESSIONS ({recentScans.length})
          </h4>
        </div>
        <Link
          to="/history"
          className="border-2 border-[#10201d] bg-[#e97b77] px-3 py-1 font-mono text-xs font-black uppercase text-[#10201d] brutal-shadow-sm hover:bg-[#df6d69]"
        >
          VIEW ALL LOGS ↗
        </Link>
      </div>

      <div className="divide-y-0">
        {recentScans.slice(0, 5).map((scan) => (
          <RecentRow key={scan.scanId} entry={scan} />
        ))}
      </div>
    </div>
  )
}
