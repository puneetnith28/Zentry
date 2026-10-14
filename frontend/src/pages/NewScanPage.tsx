import { Link } from 'react-router-dom'
import { ScanForm } from '@/components/ScanForm'

export function NewScanPage() {
  return (
    <div className="min-h-screen bg-[#fffdf5] px-4 py-12 sm:px-8">
      <div className="mx-auto max-w-4xl space-y-8">
        <div className="flex flex-wrap items-baseline justify-between gap-4 border-b-2 border-black pb-6">
          <div>
            <span className="border-2 border-black bg-[#ff9de2] px-3 py-1 font-mono text-xs font-black uppercase text-black brutal-shadow-sm">
              NEW VERIFICATION RUN
            </span>
            <h1 className="mt-3 font-mono text-4xl font-black text-black sm:text-5xl">
              AUDIT TARGET.
            </h1>
            <p className="mt-2 font-sans text-sm font-medium text-slate-700">
              Configure defensive inspection engines and verify your attack surface in non-destructive passes.
            </p>
          </div>

          <Link
            to="/history"
            className="border-2 border-black bg-white px-4 py-2 font-mono text-xs font-black uppercase text-black brutal-shadow-sm hover:bg-slate-100"
          >
            ← BACK TO ARCHIVE
          </Link>
        </div>

        <ScanForm />
      </div>
    </div>
  )
}
