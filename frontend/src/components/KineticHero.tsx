import React, { useEffect, useRef } from 'react'

interface KineticHeroProps {
  title?: string
  subtitle?: string
  onPrimaryAction?: () => void
  onSecondaryAction?: () => void
  stats?: {
    totalScans?: number
    activeScans?: number
    avgDuration?: string
  }
}

interface Point {
  x: number
  y: number
  oldX: number
  oldY: number
  pinned: boolean
}

interface Constraint {
  p1: Point
  p2: Point
  length: number
}

export const KineticHero: React.FC<KineticHeroProps> = ({
  title = 'ZENTRY',
  subtitle = 'Automated, high-performance defensive security posture scanner evaluating web applications, cryptographic integrity, and exposed attack surfaces.',
  onPrimaryAction,
  onSecondaryAction,
  stats,
}) => {
  const containerRef = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let animationFrameId: number

    // Measure exact window / hero dimensions
    const getDims = () => {
      const w = containerRef.current?.clientWidth || window.innerWidth
      const h = containerRef.current?.clientHeight || window.innerHeight
      return { w, h }
    }

    let { w: width, h: height } = getDims()
    canvas.width = width
    canvas.height = height

    // Simulation grid dimensions — density adapted for wide screen coverage
    const cols = Math.max(32, Math.floor(width / 42))
    const rows = Math.max(18, Math.floor(height / 38))
    const spacingX = width / (cols - 1)
    const spacingY = height / (rows - 1)

    const points: Point[] = []
    const constraints: Constraint[] = []

    // Initialize Verlet mesh across the entire full-bleed canvas
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const x = c * spacingX
        const y = r * spacingY
        const pinned = r === 0 || r === rows - 1 || c === 0 || c === cols - 1
        points.push({
          x,
          y,
          oldX: x,
          oldY: y,
          pinned,
        })
      }
    }

    // Horizontal & vertical spring constraints
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const i = r * cols + c
        if (c < cols - 1) {
          constraints.push({
            p1: points[i],
            p2: points[i + 1],
            length: spacingX,
          })
        }
        if (r < rows - 1) {
          constraints.push({
            p1: points[i],
            p2: points[i + cols],
            length: spacingY,
          })
        }
      }
    }

    // Pointer interaction
    const pointer = {
      x: -1000,
      y: -1000,
      oldX: -1000,
      oldY: -1000,
      isDown: false,
      radius: 140,
    }

    const handlePointerMove = (e: MouseEvent | TouchEvent) => {
      const rect = canvas.getBoundingClientRect()
      const clientX = 'touches' in e ? e.touches[0].clientX : e.clientX
      const clientY = 'touches' in e ? e.touches[0].clientY : e.clientY
      pointer.x = clientX - rect.left
      pointer.y = clientY - rect.top
    }

    const handlePointerDown = () => {
      pointer.isDown = true
    }

    const handlePointerUp = () => {
      pointer.isDown = false
    }

    const handlePointerLeave = () => {
      pointer.x = -1000
      pointer.y = -1000
      pointer.isDown = false
    }

    window.addEventListener('mousemove', handlePointerMove)
    window.addEventListener('mousedown', handlePointerDown)
    window.addEventListener('mouseup', handlePointerUp)
    canvas.addEventListener('mouseleave', handlePointerLeave)

    const handleResize = () => {
      const d = getDims()
      width = canvas.width = d.w
      height = canvas.height = d.h
    }
    window.addEventListener('resize', handleResize)

    // Main physics and render loop
    let time = 0
    const render = () => {
      time += 0.02
      ctx.clearRect(0, 0, width, height)

      // Pointer velocity
      const pvx = pointer.x - pointer.oldX
      const pvy = pointer.y - pointer.oldY
      pointer.oldX = pointer.x
      pointer.oldY = pointer.y

      // Verlet Integration & Ambient Harmonic Wave
      for (let i = 0; i < points.length; i++) {
        const p = points[i]
        if (p.pinned) continue

        // Ambient gentle fluid pulse
        const waveX = Math.sin(time + p.y * 0.008) * 0.4
        const waveY = Math.cos(time + p.x * 0.008) * 0.4

        const vx = (p.x - p.oldX) * 0.96 + waveX * 0.05
        const vy = (p.y - p.oldY) * 0.96 + waveY * 0.05

        p.oldX = p.x
        p.oldY = p.y
        p.x += vx
        p.y += vy

        // Pointer force repulsion and dragging
        const dx = p.x - pointer.x
        const dy = p.y - pointer.y
        const dist = Math.sqrt(dx * dx + dy * dy)
        if (dist < pointer.radius && dist > 0) {
          const force = (1 - dist / pointer.radius) * (pointer.isDown ? 3.8 : 2.0)
          p.x += (dx / dist) * force * 16 + pvx * 0.3
          p.y += (dy / dist) * force * 16 + pvy * 0.3
        }
      }

      // Satisfy spring relaxation constraints
      const iterations = 4
      for (let iter = 0; iter < iterations; iter++) {
        for (let j = 0; j < constraints.length; j++) {
          const { p1, p2, length } = constraints[j]
          const dx = p2.x - p1.x
          const dy = p2.y - p1.y
          const dist = Math.sqrt(dx * dx + dy * dy)
          if (dist === 0) continue
          const diff = (dist - length) / dist
          const mul = 0.45

          if (!p1.pinned) {
            p1.x += dx * 0.5 * diff * mul
            p1.y += dy * 0.5 * diff * mul
          }
          if (!p2.pinned) {
            p2.x -= dx * 0.5 * diff * mul
            p2.y -= dy * 0.5 * diff * mul
          }
        }
      }

      // Draw horizontal & vertical wireframe lines with emerald glow
      ctx.beginPath()
      ctx.lineWidth = 1
      ctx.strokeStyle = 'rgba(74, 222, 128, 0.32)' // emerald-400 matrix glow

      // Draw horizontal lines
      for (let r = 0; r < rows; r++) {
        const start = r * cols
        ctx.moveTo(points[start].x, points[start].y)
        for (let c = 1; c < cols; c++) {
          const idx = r * cols + c
          ctx.lineTo(points[idx].x, points[idx].y)
        }
      }

      // Draw vertical lines
      for (let c = 0; c < cols; c++) {
        ctx.moveTo(points[c].x, points[c].y)
        for (let r = 1; r < rows; r++) {
          const idx = r * cols + c
          ctx.lineTo(points[idx].x, points[idx].y)
        }
      }
      ctx.stroke()

      // Render glowing nodes at vertices near pointer or pulsing
      for (let i = 0; i < points.length; i++) {
        const p = points[i]
        const dx = p.x - pointer.x
        const dy = p.y - pointer.y
        const dist = Math.sqrt(dx * dx + dy * dy)
        if (dist < 120) {
          const glowAlpha = (1 - dist / 120) * 0.85
          ctx.beginPath()
          ctx.arc(p.x, p.y, 2.5, 0, Math.PI * 2)
          ctx.fillStyle = `rgba(34, 211, 238, ${glowAlpha})`
          ctx.fill()
        }
      }

      animationFrameId = requestAnimationFrame(render)
    }

    render()

    return () => {
      cancelAnimationFrame(animationFrameId)
      window.removeEventListener('mousemove', handlePointerMove)
      window.removeEventListener('mousedown', handlePointerDown)
      window.removeEventListener('mouseup', handlePointerUp)
      canvas.removeEventListener('mouseleave', handlePointerLeave)
      window.removeEventListener('resize', handleResize)
    }
  }, [])

  return (
    <div
      ref={containerRef}
      className="relative flex min-h-[calc(100vh-4.5rem)] w-full items-center justify-center overflow-hidden bg-[#030705] px-4 py-16 sm:px-6 lg:px-8"
    >
      {/* 3D Kinetic Canvas Background covering the entire window */}
      <canvas
        ref={canvasRef}
        className="pointer-events-auto absolute inset-0 size-full cursor-crosshair opacity-85 transition-opacity hover:opacity-100"
      />

      {/* Subtle radial center vignette to ensure text contrast while keeping grid visible to all 4 edges */}
      <div
        className="pointer-events-none absolute inset-0 bg-radial from-transparent via-[#030705]/40 to-[#030705]/80"
        aria-hidden="true"
      />

      {/* Foreground Hero Content floating seamlessly over the full canvas */}
      <div className="relative z-10 mx-auto flex max-w-4xl flex-col items-center text-center">
        {/* Futuristic Status Badge */}
        <div className="inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-950/70 px-4 py-1.5 text-xs font-mono uppercase tracking-[0.25em] text-emerald-400 backdrop-blur-md shadow-[0_0_20px_-3px_rgba(16,185,129,0.3)]">
          <span className="relative flex size-2">
            <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex size-2 rounded-full bg-emerald-400" />
          </span>
          Verlet Physics Surface Active
        </div>

        {/* Big Bold Hero Typography */}
        <h1 className="mt-8 font-mono text-6xl font-black tracking-tighter text-white sm:text-7xl md:text-8xl lg:text-9xl drop-shadow-[0_0_35px_rgba(16,185,129,0.3)]">
          {title}
        </h1>

        {/* Subtitle with monospace cyber styling */}
        <p className="mt-6 max-w-2xl font-mono text-xs leading-relaxed text-emerald-400/90 sm:text-sm md:text-base">
          {subtitle}
        </p>

        {/* Quick Action Buttons */}
        <div className="mt-10 flex flex-wrap items-center justify-center gap-4">
          {onPrimaryAction && (
            <button
              type="button"
              onClick={onPrimaryAction}
              className="group relative inline-flex items-center gap-2 overflow-hidden rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-6 py-3.5 font-mono text-sm font-bold uppercase tracking-wider text-black shadow-lg shadow-emerald-500/25 transition-all duration-200 hover:scale-105 hover:shadow-emerald-500/40"
            >
              <span className="relative z-10 flex items-center gap-2">
                Launch Security Scan
                <svg className="size-4 transition-transform group-hover:translate-x-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                </svg>
              </span>
            </button>
          )}

          {onSecondaryAction && (
            <button
              type="button"
              onClick={onSecondaryAction}
              className="inline-flex items-center gap-2 rounded-xl border border-emerald-500/30 bg-black/60 px-6 py-3.5 font-mono text-sm font-semibold text-emerald-300 backdrop-blur-md transition-all duration-200 hover:border-emerald-400/60 hover:bg-emerald-950/60 hover:text-white"
            >
              Explore Telemetry
            </button>
          )}
        </div>

        {/* Live telemetry counters */}
        {stats && (
          <div className="mt-12 grid grid-cols-3 gap-6 border-t border-emerald-500/15 pt-8 font-mono text-left sm:gap-12">
            <div>
              <div className="text-[11px] uppercase tracking-wider text-slate-500">Total Scans</div>
              <div className="text-2xl font-bold text-emerald-400 sm:text-3xl">{stats.totalScans ?? 0}</div>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wider text-slate-500">Active Probes</div>
              <div className="text-2xl font-bold text-cyan-400 sm:text-3xl">{stats.activeScans ?? 0}</div>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wider text-slate-500">Avg Duration</div>
              <div className="text-2xl font-bold text-white sm:text-3xl">{stats.avgDuration ?? '2.4s'}</div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
