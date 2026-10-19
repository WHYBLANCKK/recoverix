import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { TopNav } from "@/components/layout/TopNav";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Recoverix | Forensic Evidence Recovery Workspace",
  description: "Deterministic digital evidence recovery and grounded forensic interpretation",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jetbrainsMono.variable} h-full antialiased`}
    >
      <body className="font-sans antialiased bg-[#F8FAFC] text-slate-900 min-h-full flex flex-col selection:bg-emerald-500/20 selection:text-emerald-950">
        <TopNav />
        {children}
      </body>
    </html>
  );
}
