"use client";

import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { RecoverixLogo } from "@/components/ui/RecoverixLogo";

export function TopNav() {
  const handleRecoverClick = () => {
    if (typeof window !== "undefined" && (window.location.pathname === "/" || window.location.pathname === "")) {
      const dropzone = document.getElementById("upload");
      if (dropzone) {
        dropzone.scrollIntoView({ behavior: "smooth" });
        const fileInput = document.getElementById("home-dropzone-file-input") as HTMLInputElement;
        if (fileInput) {
          fileInput.focus();
        }
      }
    }
  };

  return (
    <header className="border-b border-slate-200/80 bg-white/90 backdrop-blur-md sticky top-0 z-50 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center gap-4">
          <Link href="/" className="flex items-center gap-2 group" aria-label="Recoverix Home">
            <RecoverixLogo size={32} variant="navy" subtitle="DIGITAL EVIDENCE RECOVERY PLATFORM" priority />
          </Link>
        </div>

        {/* Prominent Recovery CTA */}
        <div className="flex items-center">
          <Link
            href="/#upload"
            onClick={handleRecoverClick}
            className="bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-mono font-bold px-4 py-2 rounded-lg transition-all flex items-center gap-2 shadow-xs hover:shadow-sm text-xs"
          >
            <span>Recover a File</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>
    </header>
  );
}
