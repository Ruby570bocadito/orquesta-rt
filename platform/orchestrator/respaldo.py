"""Copia de seguridad consistente del sistema (continuidad operativa).

Usa `VACUUM INTO` de SQLite: genera un snapshot compacto y
transaccionalmente consistente de cada base de datos aunque esté en modo
WAL con escritores activos (método recomendado en producción junto al
Online Backup API de sqlite.org/backup.html). El resultado es un ZIP con
todas las BDs del sistema y un manifiesto con hashes SHA-256.

El mismo módulo sirve al endpoint admin (descarga desde la consola) y al
comando CLI `respaldo-completo` (automatización con cron).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory


def _snapshot_vacuum(origen: Path, destino: Path) -> None:
    """VACUUM INTO: copia consistente y compactada (incluye el WAL)."""
    conn = sqlite3.connect(str(origen), timeout=15)
    try:
        conn.isolation_level = None  # VACUUM no puede ir dentro de una transacción
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("VACUUM INTO ?", (str(destino),))
    finally:
        conn.close()


def _sha256(ruta: Path) -> str:
    h = hashlib.sha256()
    with ruta.open("rb") as fh:
        for bloque in iter(lambda: fh.read(65536), b""):
            h.update(bloque)
    return h.hexdigest()


def construir_respaldo_completo(raiz_casos: Path,
                                ruta_usuarios: Path) -> tuple[bytes, dict]:
    """Genera el respaldo ZIP del sistema completo.

    Devuelve (zip_bytes, manifiesto). El manifiesto también viaja dentro
    del ZIP como `manifest.json` para que el fichero sea autoverificable
    en el momento de la restauración.
    """
    generados = datetime.now(timezone.utc).isoformat()
    entradas: list[tuple[Path, str, str]] = []  # (fichero, nombre_zip, sha256)

    with TemporaryDirectory(prefix="orquesta-respaldo-") as tmp:
        tmp_dir = Path(tmp)
        pendientes: list[tuple[Path, str]] = []
        if ruta_usuarios.exists():
            pendientes.append((ruta_usuarios, "usuarios.db"))
        if raiz_casos.exists():
            for bd in sorted(raiz_casos.glob("caso_*.db")):
                pendientes.append((bd, bd.name))

        for origen, nombre in pendientes:
            destino = tmp_dir / nombre
            _snapshot_vacuum(origen, destino)
            entradas.append((destino, nombre, _sha256(destino)))

        manifiesto = {
            "generado": generados,
            "herramienta": "OrquestaRT",
            "metodo": "VACUUM INTO (snapshot consistente en caliente)",
            "total_bases": len(entradas),
            "ficheros": [
                {"nombre": nombre, "bytes": f.stat().st_size, "sha256": sha}
                for f, nombre, sha in entradas
            ],
        }
        ruta_manifiesto = tmp_dir / "manifest.json"
        ruta_manifiesto.write_text(
            json.dumps(manifiesto, ensure_ascii=False, indent=2), encoding="utf-8")

        import io
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for f, nombre, _ in entradas:
                zf.write(f, arcname=nombre)
            zf.write(ruta_manifiesto, arcname="manifest.json")
        zip_bytes = buffer.getvalue()

    return zip_bytes, manifiesto


def restaurar_aviso() -> str:
    """Instrucciones de restauración honestas (se entregan con el backup)."""
    return (
        "Restauración: detén la plataforma, sustituye cada .db por su copia del "
        "ZIP (borra -wal/-shm residuales del mismo nombre), verifica el SHA-256 "
        "contra manifest.json y arranca de nuevo con ./start.sh."
    )
