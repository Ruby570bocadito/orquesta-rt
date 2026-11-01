# OrquestaRT en Windows

Los scripts `./install.sh` y `./start.sh` son de Linux/macOS. En Windows tienes
tres rutas; la **nativa con PowerShell** es la más directa.

## Opción A — Nativa (PowerShell), recomendada

Requisitos: **Python 3.12** (desde [python.org](https://www.python.org/downloads/),
marca «Add to PATH») y **bun** (o Node 18+ con npm).

```powershell
.\install.ps1   # crea .venv, instala backend + consola, verifica imports
.\start.ps1     # levanta consola (:3000); el backend (:8000) se auto-arranca
.\stop.ps1      # detiene consola y backend
```

Abre **http://localhost:3000** — la primera pantalla crea la cuenta admin.

Si PowerShell bloquea los scripts (política de ejecución):

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

### Nota sobre rutas largas (impacket)

`impacket` trae ficheros muy anidados. Si lo clonas en una ruta profunda,
`pip` puede fallar con `OSError [Errno 22]` al superar el límite de 260
caracteres de Windows. Soluciones:

- Clona el repo en una ruta **corta**: `C:\orquesta-rt`.
- O habilita rutas largas (admin, una vez, y reinicia):
  ```powershell
  Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" LongPathsEnabled 1
  ```

La consola y todo el ciclo funcionan sin impacket; solo las técnicas de
Active Directory (Kerberos/SMB) lo necesitan en tiempo de ejecución.

## Opción B — WSL2 (Ubuntu)

Si prefieres los scripts bash originales, úsalos dentro de WSL2:

```bash
wsl ./install.sh && wsl ./start.sh
```

Requiere la característica **Plataforma de máquina virtual** activada y un
reinicio. Si `wsl` falla con `HCS_E_SERVICE_NOT_AVAILABLE`, actívala (admin):

```powershell
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

y reinicia. Luego, dentro de WSL, trata el repo como en Linux.

## Opción C — Docker Desktop

Multiplataforma, sin tocar Python local:

```powershell
docker compose up -d        # orquestador + consola
```
