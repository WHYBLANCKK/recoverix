"use client";

import { useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { X } from "lucide-react";
import { RecoveryEntryExperience } from "./RecoveryEntryExperience";

interface RecoveryEntryModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function RecoveryEntryModal({ isOpen, onClose }: RecoveryEntryModalProps) {
  const router = useRouter();

  // Handle ESC key to close modal
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
      }
    },
    [onClose]
  );

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = "hidden";
      window.addEventListener("keydown", handleKeyDown);
    } else {
      document.body.style.overflow = "";
    }
    return () => {
      document.body.style.overflow = "";
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [isOpen, handleKeyDown]);

  const handleSelectUpload = () => {
    onClose();
    if (typeof window !== "undefined") {
      if (window.location.pathname === "/" || window.location.pathname === "") {
        const uploadEl = document.getElementById("upload");
        if (uploadEl) {
          uploadEl.scrollIntoView({ behavior: "smooth" });
          const fileInput = document.getElementById("home-dropzone-file-input") as HTMLInputElement;
          if (fileInput) {
            fileInput.focus();
          }
        }
      } else {
        router.push("/#upload");
      }
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="recovery-entry-modal-title"
    >
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal Dialog Card */}
      <div className="relative bg-white rounded-2xl shadow-2xl border border-slate-200/90 w-full max-w-4xl max-h-[92vh] flex flex-col z-10 overflow-hidden my-auto animate-in fade-in-0 zoom-in-95 duration-150">
        {/* Sticky Modal Top Bar with Close Button */}
        <div className="flex items-center justify-between px-6 py-3.5 border-b border-slate-100 bg-slate-50/70 shrink-0">
          <span
            id="recovery-entry-modal-title"
            className="text-xs font-mono font-bold text-slate-700 uppercase tracking-wider"
          >
            Recoverix · Recovery Intake & Live Demo
          </span>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close recovery dialog"
            className="w-7 h-7 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-500 hover:text-slate-800 flex items-center justify-center transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="overflow-y-auto flex-1">
          <RecoveryEntryExperience onSelectUpload={handleSelectUpload} isModal={true} />
        </div>
      </div>
    </div>
  );
}
