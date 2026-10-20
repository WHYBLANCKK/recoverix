"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ArrowRight, Database, FileSearch, Layers } from "lucide-react";
import { RecoverixLogo } from "@/components/ui/RecoverixLogo";

export function TopNav() {
  const pathname = usePathname();
  const isLanding = pathname === "/" || pathname === "";

  const isSetupActive = pathname?.startsWith("/setup");
  const isCasesActive = pathname?.startsWith("/cases");
  const isDashboardActive = pathname?.startsWith("/dashboard");

  return (
    <header className="border-b border-slate-200/80 bg-white/90 backdrop-blur-md sticky top-0 z-50 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center gap-4">
          <Link href="/" className="flex items-center gap-2 group" aria-label="Recoverix Home">
            <RecoverixLogo size={32} variant="navy" subtitle="DIGITAL EVIDENCE RECOVERY PLATFORM" priority />
          </Link>

          {!isLanding && (
            <div className="hidden lg:flex items-center gap-2 pl-4 border-l border-slate-200 font-mono text-[11px]">
              <span className="bg-slate-100 text-slate-700 border border-slate-200 px-2.5 py-0.5 rounded font-semibold">
                DETERMINISTIC V/R/M
              </span>
            </div>
          )}
        </div>

        {/* Center / Navigation Links */}
        <nav className="hidden md:flex items-center gap-2 sm:gap-3 text-xs font-mono">
          {isLanding ? (
            <>
              <a href="#platform" className="px-3 py-1.5 rounded-lg text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors">
                Platform
              </a>
              <a href="#how-it-works" className="px-3 py-1.5 rounded-lg text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors">
                How It Works
              </a>
              <a href="#evidence" className="px-3 py-1.5 rounded-lg text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors">
                Evidence Matrix
              </a>
              <Link
                href="/cases"
                className="px-3 py-1.5 rounded-lg text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors"
              >
                Cases & Audit
              </Link>
            </>
          ) : (
            <>
              <Link
                href="/setup"
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-all ${
                  isSetupActive
                    ? "bg-emerald-50 border-emerald-300 text-emerald-800 shadow-xs"
                    : "border-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-100"
                }`}
              >
                <FileSearch className="w-3.5 h-3.5" />
                <span>NEW RECOVERY</span>
              </Link>

              <Link
                href="/cases"
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-all ${
                  isCasesActive
                    ? "bg-emerald-50 border-emerald-300 text-emerald-800 shadow-xs"
                    : "border-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-100"
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>CASES & AUDIT</span>
              </Link>

              <Link
                href="/dashboard"
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-all ${
                  isDashboardActive
                    ? "bg-emerald-50 border-emerald-300 text-emerald-800 shadow-xs"
                    : "border-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-100"
                }`}
              >
                <Database className="w-3.5 h-3.5" />
                <span>OVERVIEW</span>
              </Link>
            </>
          )}
        </nav>

        {/* Right side: Engine Status + CTA */}
        <div className="flex items-center gap-3 font-mono text-xs">
          <div className="flex items-center gap-2 bg-emerald-50/70 border border-emerald-200 px-3 py-1.5 rounded-lg shadow-2xs">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="font-semibold tracking-wider text-emerald-800 text-[11px]">
              ENGINE ONLINE
            </span>
          </div>

          <Link
            href="/setup"
            className="bg-emerald-500 hover:bg-emerald-600 text-white font-bold px-4 py-2 rounded-lg transition-all flex items-center gap-1.5 shadow-xs hover:shadow-sm"
          >
            <span>EXECUTE RECOVERY</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>
    </header>
  );
}
