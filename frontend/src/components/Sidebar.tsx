import { NavLink } from 'react-router-dom'
import { cn } from '@/utils/cn'

const navItems = [
  {
    to: '/',
    label: 'Command Matrix',
    subtext: 'Overview & Telemetry',
    icon: (
      <svg className="size-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" />
      </svg>
    ),
  },
  {
    to: '/history',
    label: 'Audit History',
    subtext: 'Recorded Sessions',
    icon: (
      <svg className="size-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
  },
  {
    to: '/scans/new',
    label: 'Proactive Audit',
    subtext: 'Launch Inspection',
    icon: (
      <svg className="size-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
      </svg>
    ),
  },
]

export function Sidebar() {
  return (
    <aside className="hidden w-64 shrink-0 flex-col border-r border-emerald-500/15 bg-[#030705]/90 backdrop-blur-xl lg:flex">
      {/* Brand Header */}
      <div className="flex h-16 items-center gap-3 border-b border-emerald-500/15 px-6">
        <div className="flex size-9 items-center justify-center rounded-lg bg-emerald-500/10 ring-1 ring-emerald-500/30 shadow-[0_0_12px_rgba(16,185,129,0.3)]">
          <svg className="size-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
          </svg>
        </div>
        <div>
          <p className="font-mono text-sm font-bold tracking-tight text-white">ZENTRY</p>
          <p className="font-mono text-[9px] uppercase tracking-widest text-emerald-400/90">DEFENSIVE SUITE</p>
        </div>
      </div>

      {/* Nav List */}
      <nav className="flex-1 space-y-1.5 p-4" aria-label="Main navigation">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            className={({ isActive }) =>
              cn(
                'group relative flex items-center gap-3 rounded-xl px-3 py-3 font-mono text-xs transition-all duration-200',
                isActive
                  ? 'bg-emerald-500/10 text-emerald-300 ring-1 ring-emerald-500/30 shadow-[0_0_20px_-5px_rgba(16,185,129,0.25)]'
                  : 'text-slate-400 hover:bg-slate-900/60 hover:text-slate-200',
              )
            }
          >
            {({ isActive }) => (
              <>
                {isActive && (
                  <span
                    className="absolute left-0 top-1/2 h-6 w-[3px] -translate-y-1/2 rounded-r-full bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]"
                    aria-hidden
                  />
                )}
                <span className={cn('transition-colors', isActive ? 'text-emerald-400' : 'group-hover:text-emerald-300')}>
                  {item.icon}
                </span>
                <div>
                  <div className="font-semibold text-slate-100">{item.label}</div>
                  <div className="text-[10px] text-slate-500">{item.subtext}</div>
                </div>
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Footer Info */}
      <div className="space-y-3 border-t border-emerald-500/15 p-4 font-mono">
        <div className="flex items-center justify-between text-[11px] text-slate-400">
          <span>Security Engine</span>
          <span className="text-emerald-400">v1.0.0</span>
        </div>
        <p className="text-[10px] leading-relaxed text-slate-500">
          Verlet mesh + GSAP ScrollTrigger + 3D isometric audit telemetry.
        </p>
      </div>
    </aside>
  )
}
