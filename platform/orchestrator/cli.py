"""CLI del operador (typer) — consola de texto para el día a día.

Comandos:
  crear      crea un engagement con su ROE
  estado     resumen del caso (fase, bloqueos, coste)
  avanzar    ejecuta la fase activa del ciclo
  aprobar    decide una aprobación pendiente
  informe    consolida el informe markdown
  demo       siembra un engagement de demostración completo (lab)
  servidor   arranca la API FastAPI

Ejemplos:
  python -m orchestrator.cli crear --nombre "ACME Corp" --cliente ACME \
      --dominio acme.local --cidr 10.20.0.0/16
  python -m orchestrator.cli avanzar caso_abc123
  python -m orchestrator.cli demo
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .memory import MemoriaCaso
from .models import Actor, Engagement, Fase, ROEPolitica, VentanaHoraria
from .router import RouterModelos
from .graph import OrquestadorEngagement
from .skills import BibliotecaSkills
from datetime import datetime, timezone

app = typer.Typer(help="Plataforma de red team orquestada por IA", no_args_is_help=True)
console = Console()

RAIZ_CASOS = Path("casos")
RAIZ_SKILLS = Path("skills")


def _memoria(engagement_id: str) -> MemoriaCaso:
    ruta = RAIZ_CASOS / f"{engagement_id}.db"
    if not ruta.exists():
        console.print(f"[red]Engagement {engagement_id} no existe[/red]")
        raise typer.Exit(1)
    return MemoriaCaso(ruta)


def _orquestador(engagement_id: str) -> OrquestadorEngagement:
    memoria = _memoria(engagement_id)
    fila = memoria.obtener_engagement(engagement_id)
    roe = ROEPolitica.model_validate_json(fila["roe_json"])
    router = RouterModelos(memoria=memoria, engagement_id=engagement_id)
    router.configurar_presupuestos(json.loads(fila["presupuesto_tokens_json"]))
    return OrquestadorEngagement(engagement_id, memoria, router, roe,
                                 BibliotecaSkills(RAIZ_SKILLS))


@app.command()
def crear(
    nombre: str = typer.Option(..., help="Nombre del engagement"),
    cliente: str = typer.Option(..., help="Cliente del engagement"),
    dominio: list[str] = typer.Option([], help="Dominios en alcance (repetible)"),
    cidr: list[str] = typer.Option([], help="CIDRs en alcance (repetible)"),
    excluido: list[str] = typer.Option([], help="Dominios/CIDRs excluidos (repetible)"),
    techo_ruido: int = typer.Option(50, help="Techo de ruido 0-100"),
) -> None:
    """Crea un engagement con ROE máquina-legible."""
    import uuid
    eid = f"caso_{uuid.uuid4().hex[:10]}"
    roe = ROEPolitica(
        engagement_id=eid, cliente=cliente,
        alcance_dominios=list(dominio), alcance_cidrs=list(cidr),
        alcance_excluido=list(excluido), techo_ruido=techo_ruido,
    )
    eng = Engagement(
        id=eid, nombre=nombre, cliente=cliente, roe=roe,
        creado_en=datetime.now(timezone.utc), actualizado_en=datetime.now(timezone.utc),
    )
    memoria = MemoriaCaso(RAIZ_CASOS / f"{eid}.db")
    memoria.crear_engagement(eng)
    memoria.registrar_auditoria(eid, Actor.HUMANO, "engagement.crear",
                                detalle=f"Caso creado: {nombre}", herramienta="cli")
    memoria.cerrar()
    console.print(f"[green]Engagement creado:[/green] {eid}")


@app.command()
def estado(engagement_id: str) -> None:
    """Resumen del caso: fase, bloqueos, economía y cadena de custodia."""
    memoria = _memoria(engagement_id)
    fila = memoria.obtener_engagement(engagement_id)
    pendientes = memoria.listar_aprobaciones(engagement_id, solo_pendientes=True)
    cadena = memoria.verificar_cadena(engagement_id)
    tabla = Table(title=f"{fila['nombre']} · {engagement_id}")
    tabla.add_column("Campo", style="cyan")
    tabla.add_column("Valor")
    tabla.add_row("Cliente", fila["cliente"])
    tabla.add_row("Fase actual", f"{fila['fase_actual']} ({fila['estado_fase']})")
    tabla.add_row("Aprobaciones pendientes", str(len(pendientes)))
    tabla.add_row("Tokens acumulados", f"{fila['tokens_acumulados']:,}")
    tabla.add_row("Coste acumulado", f"{fila['coste_acumulado_usd']:.4f} USD")
    tabla.add_row("Cadena de custodia",
                  "[green]VÁLIDA[/green]" if cadena["valida"] else "[red]INVÁLIDA[/red]")
    console.print(tabla)
    if pendientes:
        console.print("[yellow]Aprobaciones esperando al operador:[/yellow]")
        for a in pendientes:
            console.print(f"  • {a['id']} — {a['titulo']} (riesgo {a['riesgo']})")


@app.command()
def avanzar(
    engagement_id: str,
    notas: str = typer.Option("", help="Notas del cliente para F0"),
    vector: str = typer.Option("", help="Vector elegido para F3"),
    perfil: str = typer.Option("", help="Perfil objetivo para F6"),
) -> None:
    """Ejecuta la fase activa si no hay aprobaciones pendientes."""
    orch = _orquestador(engagement_id)
    resultado = orch.avanzar({
        "notas_cliente": notas, "vector_elegido": vector, "perfil_objetivo": perfil,
    })
    orch.router.cerrar()
    console.print_json(json.dumps(resultado, ensure_ascii=False, default=str))


@app.command()
def aprobar(aprobacion_id: str, aprovar_ok: bool = typer.Argument(True),
            comentario: str = typer.Option("", help="Motivo de la decisión")) -> None:
    """Decide una aprobación pendiente (operator-in-command)."""
    if RAIZ_CASOS.exists():
        for db in sorted(RAIZ_CASOS.glob("*.db")):
            memoria = MemoriaCaso(db)
            pend = memoria.listar_aprobaciones(db.stem, solo_pendientes=True)
            if any(a["id"] == aprobacion_id for a in pend):
                memoria.decidir_aprobacion(aprobacion_id, aprovar_ok, "cli", comentario)
                memoria.registrar_auditoria(
                    db.stem, Actor.HUMANO, "aprobacion.decision",
                    detalle=f"Aprobada={aprovar_ok}: {aprobacion_id}", herramienta="cli")
                memoria.cerrar()
                console.print(f"[green]Decisión registrada:[/green] {aprobacion_id}")
                return
            memoria.cerrar()
    console.print("[red]Aprobación no encontrada o ya decidida[/red]")


@app.command()
def informe(engagement_id: str) -> None:
    """Consolida el informe markdown del engagement."""
    memoria = _memoria(engagement_id)
    from .reporting import construir_informe
    ruta = construir_informe(engagement_id, memoria, carpeta_salida=RAIZ_CASOS)
    console.print(f"[green]Informe generado:[/green] {ruta}")


@app.command()
def servidor(
    host: str = typer.Option("0.0.0.0"),
    puerto: int = typer.Option(8000),
) -> None:
    """Arranca la API del orquestador."""
    import uvicorn
    uvicorn.run("orchestrator.api:app", host=host, port=puerto, reload=False)


@app.command()
def demo() -> None:
    """Siembra un engagement de demostración completo sobre el lab simulado."""
    from .demo_seed import sembrar_demo
    eid = sembrar_demo(RAIZ_CASOS)
    console.print(f"[green]Engagement de demostración sembrado:[/green] {eid}")


@app.command("respaldo-completo")
def respaldo_completo(salida: Path = typer.Argument(
        Path("backups"), help="Carpeta destino del ZIP")) -> None:
    """Copia de seguridad consistente de TODAS las BDs (VACUUM INTO + SHA-256).

    Pensado para cron, p. ej. diario a las 03:00:
      0 3 * * * cd /opt/orquesta/platform && ../.venv/bin/python3 -m \
          orchestrator.cli respaldo-completo backups/
    """
    import os
    from .respaldo import construir_respaldo_completo, restaurar_aviso
    from . import auth as _auth

    raiz_casos = Path(os.environ.get("RAIZ_CASOS", RAIZ_CASOS))
    zip_bytes, manifiesto = construir_respaldo_completo(raiz_casos, _auth.RUTA_DB)
    salida.mkdir(parents=True, exist_ok=True)
    marca = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    destino = salida / f"orquesta_respaldo_{marca}.zip"
    destino.write_bytes(zip_bytes)
    console.print(f"[green]Respaldo generado:[/green] {destino}")
    console.print(f"Bases incluidas: {manifiesto['total_bases']} — "
                  f"{len(zip_bytes):,} bytes")
    for f in manifiesto["ficheros"]:
        console.print(f"  - {f['nombre']}: {f['sha256'][:16]}… "
                      f"({f['bytes']:,} bytes)")
    console.print(f"[dim]{restaurar_aviso()}[/dim]")


@app.command("auditoria-sistema")
def auditoria_sistema(limite: int = typer.Option(
        50, help="Número de eventos a mostrar (1-1000)")) -> None:
    """Muestra la auditoría de nivel despliegue (respaldos, cuentas)."""
    from . import auth as _auth
    eventos = _auth.listar_auditoria_sistema(limite)
    if not eventos:
        console.print("[dim]Sin eventos de sistema registrados todavía.[/dim]")
        return
    tabla = Table(title="Auditoría de sistema")
    tabla.add_column("Fecha (UTC)")
    tabla.add_column("Actor")
    tabla.add_column("Acción")
    tabla.add_column("Detalle", overflow="fold")
    for ev in eventos:
        tabla.add_row(ev["creado_en"][:19], ev["actor"], ev["accion"],
                      ev["detalle"] or "")
    console.print(tabla)


if __name__ == "__main__":
    app()
