"use client";

import React from "react";
import Image from "next/image";

export interface RecoverixLogoProps {
  className?: string;
  size?: number;
  showText?: boolean;
  subtitle?: string;
  variant?: "navy" | "white";
  markOnly?: boolean;
  priority?: boolean;
}

export function RecoverixLogo({
  className = "",
  size = 32,
  showText = true,
  subtitle = "DIGITAL EVIDENCE RECOVERY PLATFORM",
  variant = "navy",
  markOnly = false,
  priority = false,
}: RecoverixLogoProps) {
  const isNavy = variant === "navy";
  // The official brand mark has an aspect ratio of 656 / 565 ≈ 1.161
  const markHeight = size;
  const markWidth = Math.round(size * (656 / 565));

  const markElement = (
    <div
      className={`relative inline-flex items-center justify-center shrink-0 ${
        !isNavy ? "bg-white/95 rounded-lg p-1 shadow-2xs border border-white/20" : ""
      }`}
      style={{
        width: !isNavy ? markWidth + 8 : markWidth,
        height: !isNavy ? markHeight + 8 : markHeight,
      }}
    >
      <Image
        src="/brand/recoverix-logo-transparent.png"
        alt={showText && !markOnly ? "" : "Recoverix Logo"}
        width={markWidth}
        height={markHeight}
        priority={priority}
        className="object-contain shrink-0"
        aria-hidden={showText && !markOnly ? true : undefined}
      />
    </div>
  );

  if (markOnly) {
    return <div className={`inline-flex items-center ${className}`}>{markElement}</div>;
  }

  return (
    <div className={`inline-flex items-center gap-2.5 ${className}`}>
      {markElement}
      {showText && (
        <div className="flex flex-col">
          <div className="flex items-center gap-1.5 leading-none">
            <span
              className={`font-mono font-extrabold tracking-wider text-base ${
                isNavy ? "text-slate-900" : "text-white"
              }`}
            >
              RECOVERIX
            </span>
          </div>
          {subtitle && (
            <span
              className={`font-mono text-[9px] uppercase tracking-wider mt-1 hidden sm:block ${
                isNavy ? "text-slate-500" : "text-slate-400"
              }`}
            >
              {subtitle}
            </span>
          )}
        </div>
      )}
    </div>
  );
}
