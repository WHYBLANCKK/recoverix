import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async rewrites() {
    const rawBackendUrl =
      process.env.NEXT_PUBLIC_API_URL ||
      (process.env.NODE_ENV === "production"
        ? "https://recoverix-backend-staging.onrender.com"
        : "http://127.0.0.1:8000");
    const backendUrl = rawBackendUrl.replace(/\/+$/, "");
    return [
      {
        source: '/backend-api/:path*',
        destination: `${backendUrl}/:path*`
      }
    ];
  }
};

export default nextConfig;
