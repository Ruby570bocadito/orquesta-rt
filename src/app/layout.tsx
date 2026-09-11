import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "OrquestaRT — Red Team Orquestado por IA",
  description:
    "Consola del operador de la plataforma de red team orquestada por IA: ciclo ofensivo F0-F7 con guardrails ROE, control humano y economía del token. Código cerrado, despliegue on-prem.",
  keywords: ["red team", "IA", "ciberseguridad ofensiva", "LangGraph", "MCP", "operator-in-command"],
  icons: {
    icon: "https://z-cdn.chatglm.cn/z-ai/static/logo.svg",
  },
  openGraph: {
    title: "OrquestaRT — Red Team Orquestado por IA",
    description: "Ciclo ofensivo completo con control humano en cada transición crítica",
    siteName: "OrquestaRT",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-ink text-zinc-100`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
