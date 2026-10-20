"use client";

import { useRouter } from "next/navigation";
import { RecoveryEntryExperience } from "@/components/recovery/RecoveryEntryExperience";

export default function RecoverPage() {
  const router = useRouter();

  const handleSelectUpload = () => {
    router.push("/#upload");
  };

  return (
    <main className="min-h-screen bg-[#F8FAFC] py-8 sm:py-12">
      <div className="max-w-5xl mx-auto px-4 sm:px-6">
        <div className="bg-white border border-slate-200/90 rounded-2xl shadow-xs overflow-hidden">
          <RecoveryEntryExperience onSelectUpload={handleSelectUpload} isModal={false} />
        </div>
      </div>
    </main>
  );
}
