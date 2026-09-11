"use client";

/**
 * OrquestaRT — Plataforma de Red Team orquestado por IA.
 *
 * Esta ruta ES el producto: la consola del operador conectada en vivo al
 * orquestador Python (backend real con boundary de guardrails, memoria del
 * caso cifrada y cadena de custodia). No hay página promocional ni modo
 * demostración: cada dato que ves procede del backend.
 */

import { useEffect } from "react";
import { Consola } from "@/components/consola/consola";

export default function Pagina() {
  useEffect(() => {
    document.title = "OrquestaRT — Consola de operador";
  }, []);
  return <Consola />;
}
