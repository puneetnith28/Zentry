import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useCreateScan } from '@/hooks/useScans'
import { getErrorMessage } from '@/types/api'
import type { ScanOptions } from '@/types/scan'
import { validateScanTarget } from '@/utils/validateScanTarget'

const DEFAULT_OPTIONS: Pick<ScanOptions, 'ssl_scan' | 'headers_scan' | 'port_scan' | 'tech_scan' | 'subdomain_scan'> = {
  ssl_scan: true,
  headers_scan: true,
  port_scan: true,
  tech_scan: true,
  subdomain_scan: true,
}

const SCAN_MODULES = [
  {
    id: 'headers_scan' as const,
    label: 'HTTP Security Headers',
    code: 'SEC-01',
    description: 'HSTS max-age, CSP policies, framing options, and cookie protection.',
  },
  {
    id: 'ssl_scan' as const,
    label: 'SSL/TLS Cryptography',
    code: 'SEC-02',
    description: 'Certificate chains, expiry alerts, cipher suites, and hostname match.',
  },
  {
    id: 'port_scan' as const,
    label: 'TCP Port Audit',
    code: 'SEC-03',
    description: 'Non-disruptive connect probes on standard web and database ports.',
  },
  {
    id: 'tech_scan' as const,
    label: 'Tech Stack Fingerprinting',
    code: 'SEC-04',
    description: 'Passive signature matching across web servers, CMS, and frameworks.',
  },
  {
    id: 'subdomain_scan' as const,
    label: 'Passive OSINT Subdomains',
    code: 'SEC-05',
    description: 'Certificate Transparency logs interrogation with zero DNS brute force.',
  },
]

export function ScanForm({ className = '' }: { className?: string }) {
  const navigate = useNavigate()
  const createScan = useCreateScan()

  const [target, setTarget] = useState('https://')
  const [options, setOptions] = useState(DEFAULT_OPTIONS)
  const [fieldError, setFieldError] = useState<string | null>(null)
  const [apiError, setApiError] = useState<string | null>(null)

  const toggleOption = (key: keyof typeof DEFAULT_OPTIONS) => {
    setOptions((prev) => ({ ...prev, [key]: !prev[key] }))
    setFieldError(null)
    setApiError(null)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setFieldError(null)
    setApiError(null)

    const validation = validateScanTarget(target, options)
    if (!validation.valid) {
      setFieldError(validation.error ?? 'Invalid target format')
      return
    }

    try {
      const result = await createScan.mutateAsync({
        target: target.trim(),
        options: {
          ...options,
          port_list: null,
        },
      })
      navigate(`/scans/${result.scan_id}`)
    } catch (err) {
      setApiError(getErrorMessage(err, 'Failed to initialize verification run'))
    }
  }

  const displayError = fieldError ?? apiError

  return (
    <form
      onSubmit={handleSubmit}
      className={`border-2 border-[#10201d] bg-[#f7f3ee] p-6 sm:p-8 brutal-shadow-lg ${className}`}
      noValidate
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b-2 border-[#10201d] pb-4 mb-6">
        <div>
          <span className="border border-[#10201d] bg-[#e97b77] px-2.5 py-0.5 font-mono text-[11px] font-black uppercase text-[#10201d] brutal-shadow-sm">
            EVALUATION PARAMETERS
          </span>
          <h3 className="mt-2 font-mono text-2xl font-black text-[#10201d]">
            LAUNCH DEFENSIVE SCAN
          </h3>
        </div>
        <span className="font-mono text-xs font-bold text-slate-700">
          AUTHORIZED TARGETS ONLY
        </span>
      </div>

      <div className="space-y-6">
        {/* Target Input */}
        <div>
          <label htmlFor="target-input" className="block font-mono text-xs font-black uppercase text-[#10201d] mb-1.5">
            TARGET HOSTNAME OR URL
          </label>
          <div className="relative">
            <input
              id="target-input"
              type="url"
              value={target}
              onChange={(e) => {
                setTarget(e.target.value)
                setFieldError(null)
                setApiError(null)
              }}
              placeholder="https://example.com"
              required
              className="w-full border-2 border-[#10201d] bg-white px-4 py-3 font-mono text-sm font-bold text-[#10201d] placeholder:text-slate-400 focus:outline-none brutal-shadow-sm"
            />
          </div>
          <p className="mt-1.5 font-sans text-xs text-slate-600">
            Internal IP addresses and private loopbacks (SSRF) are strictly blocked by the safe outbound proxy.
          </p>
        </div>

        {/* Modules Grid */}
        <div>
          <label className="block font-mono text-xs font-black uppercase text-[#10201d] mb-2">
            SELECT ACTIVE MODULE ENGINES (5 DETERMINISTIC PASSES)
          </label>
          <div className="grid gap-2.5 sm:grid-cols-2">
            {SCAN_MODULES.map((mod) => {
              const active = options[mod.id]
              return (
                <button
                  type="button"
                  key={mod.id}
                  onClick={() => toggleOption(mod.id)}
                  className={`flex flex-col text-left border-2 border-[#10201d] p-3 transition-transform cursor-pointer ${
                    active ? 'bg-[#e97b77] brutal-shadow-sm translate-x-[-1px] translate-y-[-1px]' : 'bg-white opacity-70'
                  }`}
                >
                  <div className="flex items-center justify-between w-full">
                    <span className="font-mono text-[10px] font-bold text-[#10201d] border border-[#10201d] bg-white px-1.5 py-0.2">
                      {mod.code}
                    </span>
                    <span className="font-mono text-xs font-black text-[#10201d]">
                      {active ? '[ENABLED]' : '[SKIPPED]'}
                    </span>
                  </div>
                  <div className="mt-1.5 font-mono text-xs font-bold text-[#10201d]">
                    {mod.label}
                  </div>
                  <div className="mt-1 font-sans text-[11px] text-slate-800 leading-tight">
                    {mod.description}
                  </div>
                </button>
              )
            })}
          </div>
        </div>

        {displayError && (
          <div className="border-2 border-[#10201d] bg-[#e97b77] p-3 font-mono text-xs font-bold text-[#10201d] brutal-shadow-sm">
            ERROR: {displayError}
          </div>
        )}

        {/* Submit Button */}
        <div className="pt-2">
          <button
            type="submit"
            disabled={createScan.isPending}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 border-2 border-[#10201d] bg-[#e97b77] px-8 py-4 font-mono text-sm font-black uppercase tracking-wider text-[#10201d] brutal-shadow transition-transform hover:bg-[#df6d69] active:translate-x-1 active:translate-y-1 disabled:opacity-60 cursor-pointer"
          >
            <span>{createScan.isPending ? 'EXECUTING VERIFICATION…' : 'INITIALIZE SECURITY SCAN'}</span>
            <span className="text-base font-black">↗</span>
          </button>
        </div>
      </div>
    </form>
  )
}
