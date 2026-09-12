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
  {
    // z3 (auditoría seguridad): CSP de refuerzo. No restringe script/style
    // (Next.js/React necesitan inline y eval en dev) pero cierra vector de
    // objetos embebidos, base-uri y anidamiento — complementa X-Frame-Options.
    key: "Content-Security-Policy",
    value:
      "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
  },
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
  // z1 (v28): el indicador de desarrollo de Next contamina capturas y
  // demostraciones de la consola; el despliegue real es producción standalone.
  devIndicators: false,
};

export default nextConfig;
