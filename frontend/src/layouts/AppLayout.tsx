import { useEffect } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { Navbar } from '@/components/Navbar'

export function AppLayout() {
  const { pathname } = useLocation()

  // Scroll to top on route change
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'instant' })
  }, [pathname])

  return (
    <div className="flex min-h-screen flex-col bg-[#2e4742] text-[#10201d]">
      <Navbar />
      <main
        className="flex-1"
        role="main"
        aria-label="Page content"
      >
        <Outlet />
      </main>
    </div>
  )
}
