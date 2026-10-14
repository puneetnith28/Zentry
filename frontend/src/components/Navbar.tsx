import { useState } from 'react'
import { Link, NavLink, useLocation } from 'react-router-dom'
import { cn } from '@/utils/cn'

const navItems = [
  {
    to: '/',
    label: 'SECURITY MATRIX',
  },
  {
    to: '/history',
    label: 'AUDIT LOGS',
  },
  {
    to: '/scans/new',
    label: 'VERIFICATION RUN',
  },
]

export function Navbar() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const location = useLocation()

  return (
    <header className="sticky top-0 z-50 w-full border-b-2 border-[#10201d] bg-[#f7f3ee] px-4 sm:px-6 lg:px-8">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between gap-4">
        {/* Left: Square icon badge with salmon accent + brand text */}
        <div className="flex items-center gap-6">
          <Link
            to="/"
            onClick={() => setMobileMenuOpen(false)}
            className="flex items-center gap-3 group"
          >
            <div className="flex size-9 items-center justify-center border-2 border-[#10201d] bg-[#e97b77] text-[#10201d] font-mono font-black text-lg brutal-shadow-sm transition-transform group-hover:translate-x-0.5 group-hover:translate-y-0.5">
              Z
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xl font-black tracking-tight text-[#10201d]">
                ZENTRY
              </span>
              <span className="text-xl font-black text-[#10201d]">|</span>
            </div>
          </Link>

          {/* Desktop Navigation Links */}
          <nav className="hidden md:flex items-center gap-6" aria-label="Main navigation">
            {navItems.map((item) => {
              const isActive = location.pathname === item.to
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === '/'}
                  className={cn(
                    'font-mono text-xs font-bold tracking-wider transition-colors hover:text-[#10201d]',
                    isActive
                      ? 'text-[#10201d] underline underline-offset-4 decoration-2 decoration-[#e97b77]'
                      : 'text-slate-600',
                  )}
                >
                  {item.label}
                </NavLink>
              )
            })}
          </nav>
        </div>

        {/* Right Action Buttons with coral & rust shadows */}
        <div className="flex items-center gap-3">
          <a
            href="#how-it-works"
            className="hidden sm:inline-flex items-center gap-1.5 border-2 border-[#10201d] bg-white px-4 py-2 font-mono text-xs font-black uppercase tracking-wider text-[#10201d] brutal-shadow-sm transition hover:bg-slate-50 active:translate-x-0.5 active:translate-y-0.5"
          >
            <svg className="size-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            HOW IT WORKS
          </a>

          <Link
            to="/scans/new"
            onClick={() => setMobileMenuOpen(false)}
            className="inline-flex items-center gap-1.5 border-2 border-[#10201d] bg-[#e97b77] px-4 py-2 font-mono text-xs font-black uppercase tracking-wider text-[#10201d] brutal-shadow-sm transition hover:bg-[#df6d69] active:translate-x-0.5 active:translate-y-0.5"
          >
            <span>AUDIT TARGET</span>
            <span className="text-sm font-black">↗</span>
          </Link>

          {/* Mobile Hamburger Toggle */}
          <button
            type="button"
            onClick={() => setMobileMenuOpen((prev) => !prev)}
            aria-label="Toggle navigation menu"
            aria-expanded={mobileMenuOpen}
            className="md:hidden flex size-9 items-center justify-center border-2 border-[#10201d] bg-white text-[#10201d] brutal-shadow-sm"
          >
            {mobileMenuOpen ? (
              <svg className="size-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            ) : (
              <svg className="size-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            )}
          </button>
        </div>
      </div>

      {/* Mobile Dropdown */}
      {mobileMenuOpen && (
        <div className="border-t-2 border-[#10201d] bg-[#f7f3ee] px-4 py-4 md:hidden">
          <nav className="flex flex-col gap-3 font-mono text-sm font-black">
            {navItems.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                onClick={() => setMobileMenuOpen(false)}
                className="border-2 border-[#10201d] bg-white px-4 py-3 brutal-shadow-sm"
              >
                {item.label}
              </Link>
            ))}
          </nav>
        </div>
      )}
    </header>
  )
}
