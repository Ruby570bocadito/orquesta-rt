import type { NextConfig } from "next";

/**
 * Cabeceras de seguridad del despliegue (endurecimiento de producción):
 * la consola maneja operaciones con consecuencias legales — se minimiza la
 * superficie del navegador (clickjacking, MIME sniffing, referers).
 */
const CABECERAS_SEGURIDAD = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=()",
  },
  { key: "X-DNS-Prefetch-Control", value: "off" },
];

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: CABECERAS_SEGURIDAD }];
  },
  typescript: {
    // Código cerrado: el build DEBE fallar con errores de tipos (v13).
    ignoreBuildErrors: false,
  },
  reactStrictMode: false,
};

export default nextConfig;
