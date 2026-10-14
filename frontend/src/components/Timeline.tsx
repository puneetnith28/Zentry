import {
  type CSSProperties,
  useLayoutEffect,
  useRef,
  useSyncExternalStore,
} from "react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";

if (typeof window !== "undefined") {
  gsap.registerPlugin(ScrollTrigger);
}

function useGSAP(
  callback: () => void | (() => void),
  options?: {
    dependencies?: unknown[];
    scope?: { current: Element | null } | Element | null;
  }
) {
  const deps = options?.dependencies ?? [];
  const scope = options?.scope;
  const ctxRef = useRef<gsap.Context | null>(null);
  const cleanupRef = useRef<(() => void) | undefined>(undefined);

  useLayoutEffect(() => {
    const el =
      scope && typeof scope === "object" && "current" in scope
        ? scope.current
        : (scope as Element | null);
    ctxRef.current = gsap.context(() => {}, el ?? undefined);
    return () => {
      cleanupRef.current?.();
      cleanupRef.current = undefined;
      ctxRef.current?.revert();
      ctxRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useLayoutEffect(() => {
    if (!ctxRef.current) return;
    cleanupRef.current?.();
    const ret = ctxRef.current.add(callback);
    cleanupRef.current = typeof ret === "function" ? ret : undefined;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}

export type InspectionModuleItem = {
  id: string;
  code: string;
  title: string;
  category: string;
  description: string;
  status: string;
  isTop?: boolean;
};

export const defaultInspectionModules: InspectionModuleItem[] = [
  // Top row modules
  {
    id: "sec-mod-01",
    code: "SEC-MOD-01",
    title: "HTTP & Framing Headers",
    category: "Defense Layer",
    description: "Deep audit of Strict-Transport-Security, CSP policies, framing permissions, and server exposure leaks.",
    status: "Subsystem Ready",
    isTop: true,
  },
  {
    id: "sec-mod-03",
    code: "SEC-MOD-03",
    title: "Non-Disruptive Port Audit",
    category: "Network Recon",
    description: "Strictly bounded TCP connect probes with anti-evasion checks and safe socket lifecycle handling.",
    status: "Subsystem Ready",
    isTop: true,
  },
  {
    id: "sec-mod-05",
    code: "SEC-MOD-05",
    title: "Passive OSINT Subdomains",
    category: "Perimeter Mapping",
    description: "Reconnaissance mapping via Subfinder OSINT providers, wildcard detection, and domain posture checks.",
    status: "Subsystem Ready",
    isTop: true,
  },
  // Bottom row modules
  {
    id: "sec-mod-02",
    code: "SEC-MOD-02",
    title: "SSL/TLS Cryptography",
    category: "Cryptographic Core",
    description: "Cipher suite analysis, certificate trust chains, hostname SAN verification, and expiration monitors.",
    status: "Subsystem Ready",
    isTop: false,
  },
  {
    id: "sec-mod-04",
    code: "SEC-MOD-04",
    title: "Tech Stack Fingerprint",
    category: "Signature Analysis",
    description: "Passive signature matching across web servers, frontend frameworks, CDNs, and vulnerable dependencies.",
    status: "Subsystem Ready",
    isTop: false,
  },
  {
    id: "sec-mod-06",
    code: "SEC-MOD-06",
    title: "Deterministic PDF Reports",
    category: "Executive Intelligence",
    description: "Executive summaries, finding remediation guidance, and 0-100 severity risk score exports.",
    status: "Subsystem Ready",
    isTop: false,
  },
];

export type TimelineProps = {
  title?: string;
  periodLabel?: string;
  textColor?: string;
  mutedTextColor?: string;
  activeColor?: string;
  backgroundColor?: string;
  imageUrl?: string;
  imageAlt?: string;
  items?: InspectionModuleItem[];
  duration?: number;
  scrollDuration?: number;
};

const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

function subscribeToReducedMotion(callback: () => void) {
  if (typeof window === "undefined") return () => {};
  const mediaQueryList = window.matchMedia(REDUCED_MOTION_QUERY);
  mediaQueryList.addEventListener("change", callback);
  return () => mediaQueryList.removeEventListener("change", callback);
}

function getReducedMotionSnapshot() {
  if (typeof window === "undefined") return false;
  return window.matchMedia?.(REDUCED_MOTION_QUERY)?.matches ?? false;
}

function getServerReducedMotionSnapshot() {
  return false;
}

function usePrefersReducedMotion() {
  return useSyncExternalStore(
    subscribeToReducedMotion,
    getReducedMotionSnapshot,
    getServerReducedMotionSnapshot,
  );
}

export function Timeline({
  title = "Inspection Modules",
  periodLabel = "6 Verified Engines",
  textColor = "var(--color-foreground, #f8fafc)",
  mutedTextColor = "var(--color-muted-foreground, #94a3b8)",
  activeColor = "#10b981",
  backgroundColor = "transparent",
  imageUrl = "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=1200&q=80",
  imageAlt = "Cyber security command center operations",
}: TimelineProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const trackRef = useRef<HTMLDivElement>(null);
  const reducedMotion = usePrefersReducedMotion();

  const topModules = defaultInspectionModules.filter((m) => m.isTop);
  const bottomModules = defaultInspectionModules.filter((m) => !m.isTop);
  const allModules = [...topModules, ...bottomModules];

  const sectionStyle: CSSProperties = {
    color: textColor,
    backgroundColor,
  };
  const activeStyle: CSSProperties = {
    backgroundColor: activeColor,
  };
  const mutedTextStyle: CSSProperties = {
    color: mutedTextColor,
  };

  useGSAP(() => {
    const container = containerRef.current;
    const track = trackRef.current;
    if (!container || !track) return;

    if (reducedMotion) {
      allModules.forEach((item) => {
        gsap.set(`.jl-${item.id}`, { scaleY: 1 });
        gsap.set(`.jd-${item.id}`, { scale: 1 });
        gsap.set(`.card-${item.id}`, { opacity: 1, y: 0 });
      });
      return;
    }

    // Set initial states
    allModules.forEach((item) => {
      gsap.set(`.jl-${item.id}`, {
        scaleY: 0,
        transformOrigin: item.isTop ? "bottom bottom" : "top top",
      });
      gsap.set(`.jd-${item.id}`, { scale: 0 });
      gsap.set(`.card-${item.id}`, { opacity: 0.6, y: item.isTop ? 20 : -20 });
    });

    // Compute exact pixel distance the track needs to translate so that the last cards (Modules 05 & 06)
    // dock comfortably within view without any extra empty space.
    const getScrollAmount = () => {
      const trackWidth = track.scrollWidth;
      const windowWidth = window.innerWidth;
      // Scroll exactly so the last cards fit neatly on screen, minus standard right padding
      return -(trackWidth - windowWidth + 40);
    };

    // Main horizontal scroll timeline pinned to vertical scrolling
    const tl = gsap.timeline({
      scrollTrigger: {
        trigger: container,
        pin: true,
        pinSpacing: true,
        anticipatePin: 1,
        start: "top top",
        end: () => `+=${Math.max(600, Math.abs(getScrollAmount()))}`,
        scrub: 1,
        invalidateOnRefresh: true,
      },
    });

    // 1. Precise horizontal slide — exact travel distance with zero extra empty void
    tl.to(track, {
      x: getScrollAmount,
      ease: "none",
    });

    // 2. Center journey line expansion along with scroll (completes right as the last cards settle)
    tl.to(
      ".journey-line",
      {
        width: "100%",
        ease: "none",
      },
      0
    );

    // 3. Staggered reveal of each node & connector line during the horizontal travel
    allModules.forEach((item, index) => {
      const positionFraction = (index + 0.5) / allModules.length;
      tl.to(
        `.jl-${item.id}`,
        {
          scaleY: 1,
          duration: 0.12,
          ease: "power2.out",
        },
        positionFraction * 0.75
      )
      .to(
        `.jd-${item.id}`,
        {
          scale: 1,
          duration: 0.12,
          ease: "back.out(2)",
        },
        "<"
      )
      .to(
        `.card-${item.id}`,
        {
          opacity: 1,
          y: 0,
          duration: 0.18,
          ease: "power2.out",
        },
        "<"
      );
    });

    const handleResize = () => {
      ScrollTrigger.refresh();
    };

    window.addEventListener("resize", handleResize);

    return () => {
      window.removeEventListener("resize", handleResize);
    };
  }, { dependencies: [reducedMotion], scope: containerRef });

  return (
    <div
      ref={containerRef}
      id="journey"
      className="relative h-screen w-full overflow-hidden bg-[#030705]"
      style={sectionStyle}
    >
      {/* Integrated Section Header inside the pinned container */}
      <div className="absolute left-6 sm:left-12 top-6 z-20 pointer-events-none">
        <div className="inline-flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-widest text-emerald-400">
          <span className="size-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
          Interactive Horizontal Scroll Experience
        </div>
        <h2 className="mt-1 font-mono text-2xl font-extrabold tracking-tight text-white sm:text-3xl">
          Security Inspection Engines
        </h2>
      </div>

      <div className="flex h-full w-full items-center overflow-hidden pt-12">
        <div
          ref={trackRef}
          className="flex h-[80vh] items-center gap-8 px-8 sm:px-12 will-change-transform"
        >
          {/* Cyber Preview Poster Card */}
          <div className="relative h-[68vh] w-[340px] shrink-0 overflow-hidden rounded-3xl border border-emerald-500/30 bg-black/70 shadow-[0_0_40px_-10px_rgba(16,185,129,0.25)] backdrop-blur-2xl">
            <img
              src={imageUrl}
              alt={imageAlt}
              draggable={false}
              className="size-full object-cover opacity-75 mix-blend-luminosity filter contrast-125"
            />
            <div className="absolute inset-0 bg-gradient-to-t from-black via-black/40 to-transparent" />
            <div className="absolute bottom-8 left-8 right-8">
              <span className="font-mono text-xs uppercase tracking-widest text-emerald-400">
                Audited Engines
              </span>
              <h3 className="mt-1 font-mono text-2xl font-black text-white sm:text-3xl">
                Inspection Modules
              </h3>
              <p className="mt-2 font-mono text-xs text-slate-400">
                Non-disruptive defensive security analyzers verified for production environments.
              </p>
            </div>
          </div>

          {/* Horizontal Storyline Content: Auto-sized to content without excess trailing space */}
          <div className="relative h-[68vh] w-max shrink-0">
            {/* The Central Animated Glowing Guide Line */}
            <div className="absolute left-0 top-[50%] flex h-fit w-full -translate-y-1/2 items-center">
              <div
                className="size-3 rounded-full shadow-[0_0_12px_rgba(16,185,129,0.8)]"
                style={activeStyle}
              ></div>
              <div
                className="journey-line h-[2px] w-[0%] rounded-full shadow-[0_0_15px_rgba(16,185,129,0.6)]"
                style={activeStyle}
              ></div>
              <div
                className="size-3 rounded-full shadow-[0_0_12px_rgba(16,185,129,0.8)]"
                style={activeStyle}
              ></div>
            </div>

            {/* Top Row: Modules 01, 03, 05 */}
            <div className="flex h-1/2 items-center justify-start gap-8">
              <div className="h-full w-[180px] shrink-0 pt-4">
                <h2 className="font-mono text-3xl font-extrabold leading-[1] text-white">
                  {title}
                </h2>
              </div>

              <div className="flex h-full items-center gap-16 pr-8">
                {topModules.map((item) => (
                  <div
                    key={`top-${item.id}`}
                    className="relative flex h-full w-[310px] shrink-0 flex-col justify-end px-3 pb-6"
                  >
                    {/* Vertical Connector Line & Node */}
                    <div className="absolute bottom-0 left-0 top-0 size-full">
                      <div
                        className={`jd-${item.id} relative aspect-square size-3 -translate-x-1/2 rounded-full shadow-[0_0_12px_rgba(16,185,129,0.9)]`}
                        style={activeStyle}
                      ></div>
                      <div
                        className={`jl-${item.id} h-[92%] w-[2px] origin-bottom rounded-full shadow-[0_0_8px_rgba(16,185,129,0.5)]`}
                        style={activeStyle}
                      ></div>
                    </div>

                    {/* Card Content */}
                    <div className={`card-${item.id} rounded-2xl border border-slate-800/80 bg-[#080e14]/90 p-5 shadow-xl backdrop-blur-md transition-all duration-300 hover:border-emerald-500/40 hover:shadow-[0_0_24px_rgba(16,185,129,0.2)]`}>
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[10px] tracking-wider text-emerald-400">
                          {item.code}
                        </span>
                        <span className="font-mono text-[10px] text-slate-500">
                          {item.category}
                        </span>
                      </div>
                      <h4 className="mt-2 font-mono text-base font-bold leading-tight text-white sm:text-lg">
                        {item.title}
                      </h4>
                      <p
                        className="mt-1.5 font-sans text-xs leading-relaxed text-slate-300"
                        style={mutedTextStyle}
                      >
                        {item.description}
                      </p>
                      <div className="mt-3 flex items-center gap-1.5 font-mono text-[10px] text-emerald-400">
                        <span className="size-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.8)]" />
                        <span>{item.status}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Bottom Row: Modules 02, 04, 06 */}
            <div className="flex h-1/2 items-center justify-start gap-8">
              <div className="h-full w-[180px] shrink-0 pt-6">
                <p
                  className="font-mono text-sm tracking-wider text-emerald-400"
                  style={mutedTextStyle}
                >
                  {periodLabel}
                </p>
              </div>

              <div className="flex h-full items-center gap-16 pr-8">
                {bottomModules.map((item) => (
                  <div
                    key={`bottom-${item.id}`}
                    className="relative flex h-full w-[310px] shrink-0 flex-col justify-start px-3 pt-6"
                  >
                    {/* Vertical Connector Line & Node */}
                    <div className="absolute bottom-0 left-0 top-0 size-full">
                      <div
                        className={`jl-${item.id} h-[92%] w-[2px] origin-top rounded-full shadow-[0_0_8px_rgba(34,211,238,0.5)]`}
                        style={{ backgroundColor: "#22d3ee" }}
                      ></div>
                      <div
                        className={`jd-${item.id} relative aspect-square size-3 -translate-x-1/2 rounded-full shadow-[0_0_12px_rgba(34,211,238,0.9)]`}
                        style={{ backgroundColor: "#22d3ee" }}
                      ></div>
                    </div>

                    {/* Card Content */}
                    <div className={`card-${item.id} rounded-2xl border border-slate-800/80 bg-[#080e14]/90 p-5 shadow-xl backdrop-blur-md transition-all duration-300 hover:border-cyan-500/40 hover:shadow-[0_0_24px_rgba(34,211,238,0.2)]`}>
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[10px] tracking-wider text-cyan-400">
                          {item.code}
                        </span>
                        <span className="font-mono text-[10px] text-slate-500">
                          {item.category}
                        </span>
                      </div>
                      <h4 className="mt-2 font-mono text-base font-bold leading-tight text-white sm:text-lg">
                        {item.title}
                      </h4>
                      <p
                        className="mt-1.5 font-sans text-xs leading-relaxed text-slate-300"
                        style={mutedTextStyle}
                      >
                        {item.description}
                      </p>
                      <div className="mt-3 flex items-center gap-1.5 font-mono text-[10px] text-cyan-400">
                        <span className="size-1.5 rounded-full bg-cyan-400 shadow-[0_0_6px_rgba(34,211,238,0.8)]" />
                        <span>{item.status}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
export default Timeline;
