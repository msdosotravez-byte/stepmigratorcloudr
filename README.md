# ⇅ StepMigratorDrive

Aplicación de escritorio para migrar archivos de forma bidireccional entre almacenamiento local y **Google Drive** (`Local ➔ Drive` y `Drive ➔ Disco Duro`), con protección criptográfica de cuenta, transferencias multihilo de alta velocidad y continuidad sin interrupciones.

---

## Índice

- [Descripción](#descripción)
- [Características](#características)
- [Arquitectura](#arquitectura)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Configuración de Google Drive](#configuración-de-google-drive)
- [Uso](#uso)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Módulos](#módulos)
  - [migrador.py](#migradorpy--motor-de-backend)
  - [app_gui.py](#app_guipy--interfaz-gráfica)
- [Correcciones aplicadas](#correcciones-aplicadas)

---

## Descripción

**StepMigratorDrive** es una herramienta de escritorio multiplataforma (macOS / Windows / Linux) diseñada para mover grandes volúmenes de datos en dos direcciones:

- **Subida (`Local ➔ Drive`)**: escanea con `os.scandir`, verifica cuota disponible en Drive, segmenta en lotes ≤ 1.5 GB conservando la jerarquía de carpetas y sube en paralelo.
- **Descarga (`Drive ➔ Disco Duro`)**: escanea Drive en modo **estrictamente solo lectura**, verifica el espacio libre en disco duro, exporta documentos nativos de Google Workspace y descarga atómicamente mediante archivos `.part`.

---

## Características

| Característica | Detalle |
|---|---|
| **Bóveda cifrada OAuth2** | Cifrado autenticado (`PBKDF2-HMAC-SHA256` 480k iteraciones + `Fernet`) guardado en `token.enc` con permisos `0600` |
| **Migración segura de token** | Migra `token.json` legado a `token.enc` y sobrescribe el archivo plano antes de eliminarlo |
| **Sesión efímera (RAM)** | Opción para operar sin guardar ningún token en disco |
| **Revocación y cierre seguro** | Botón para revocar el token OAuth2 en los servidores de Google y destruir credenciales locales |
| **Verificación de cuota y MD5** | Comprueba espacio libre antes de transferir y valida sumas MD5 para integridad y deduplicación |
| **Proceso inverso completo** | Descarga recursiva desde Drive al disco duro, con exportación automática de Google Docs/Sheets/Slides |
| **Alta velocidad multihilo** | `ThreadPoolExecutor` con hasta 8 hilos y cliente Drive `thread-local` independiente por hilo |
| **Chunks adaptativos** | Subida directa en 1 petición para archivos `≤ 4 MB`; chunks de `16 MB` para archivos grandes |
| **Cero interrupciones** | Reintentos exponenciales con *jitter* por operación y por chunk (`401`, `403` rate-limit, `429`, `5xx`, cortes de red) + refresco automático de token |
| **Anti-suspensión** | Bloqueo `SystemWakeLock` (`caffeinate` en macOS / `SetThreadExecutionState` en Windows) durante transferencias activas |
| **Telemetría y ETA en vivo** | Barra de progreso determinada (0–100 %), velocidad en `MB/s` y contador estimado de tiempo restante (`⏳ Restante`) |
| **Protección de origen y pre-formateo** | Auditoría 100 % MD5 con manifiesto JSON (`manifiesto_respaldo_drive.json`), informe final con fallos y exportación a PDF |
| **Higiene exFAT y preservación `mtime`** | Filtra basura de volumen (`._*`, `.Spotlight-V100`, `.Trashes`, `$RECYCLE.BIN`), normaliza Unicode NFC y preserva fechas originales al subir y restaurar |
| **Control anti-saturación USB/exFAT** | Semáforo de E/S para archivos `> 64 MB` evitando *thrashing* o desconexiones en discos externos |

---

## Arquitectura

```
StepMigratorDrive
│
├── app_gui.py          ← Interfaz gráfica (CustomTkinter)
│   ├── SecurityAuthDialog       → PIN de bóveda / sesión efímera
│   ├── DriveFolderPickerDialog  → Navegador visual de carpetas en Drive
│   ├── LogoutSecurityDialog     → Desconexión o revocación OAuth2
│   └── StepMigratorApp          → Cola thread-safe + selector bidireccional + telemetría
│
└── migrador.py         ← Motor de backend (sin dependencias de GUI)
    ├── AccountSecurityManager   → token.enc, permisos 0600, borrado seguro, revocación
    ├── SystemWakeLock           → Prevención de suspensión del sistema operativo
    ├── ThreadSafeDrivePool      → Instancia Drive Resource por hilo + refresh sincronizado
    ├── execute_with_retry()     → Backoff exponencial con jitter para HTTP/red
    ├── scan_source()            → Escáner local en una sola pasada (os.scandir)
    ├── scan_drive_source()      → Escáner de Drive (solo lectura + exportación Workspace)
    ├── build_segments()         → Segmentación ≤ 1.5 GB preservando rel_dir
    ├── DriveUploader            → Subida paralela directa / chunked 16 MB + MD5
    ├── DriveDownloader          → Descarga atómica (.part → os.replace) + MD5
    ├── StepMigrator             → Orquestador Local ➔ Drive
    └── StepDownloader           → Orquestador Drive ➔ Disco Duro
```

---

## Requisitos

- **Python** 3.10 o superior
- **Google Cloud Console**: proyecto con la API de Drive habilitada y credenciales OAuth2 de tipo *Aplicación de escritorio*

### Dependencias Python

```
customtkinter>=6.0.0
send2trash>=2.0.0
cryptography>=42.0.0
requests>=2.31.0
google-api-python-client>=2.0.0
google-auth>=2.0.0
google-auth-oauthlib>=1.0.0
google-auth-httplib2>=0.4.0
```

---

## Instalación

```bash
cd stepmigratordrive
python3 -m venv venv
source venv/bin/activate       # macOS/Linux
# venv\Scripts\activate        # Windows

pip install -r requirements.txt
python app_gui.py
```

---

## Configuración de Google Drive

1. Ve a [Google Cloud Console](https://console.cloud.google.com/) → **APIs y servicios** → **Credenciales**.
2. Habilita la **API de Google Drive**.
3. Crea credenciales → **ID de cliente OAuth 2.0** → tipo **Aplicación de escritorio**.
4. Descarga el archivo JSON y guárdalo como `credentials.json` en la raíz del proyecto.

---

## Uso

### Lanzamiento directo (macOS)
Haz doble clic en **`StepMigratorDrive.app`** dentro de la carpeta del proyecto (puedes arrastrarlo al Dock o crear un alias si lo deseas) para abrir la aplicación sin usar terminal.

### Flujo paso a paso

1. **Conectar Drive**: pulsa **Conectar Drive**, introduce una contraseña maestra para cifrar tu sesión en `token.enc` (o activa **Sesión efímera** para mantenerla solo en RAM) y autoriza en el navegador la primera vez.
2. **Elegir dirección**: selecciona `⬆ Local ➔ Drive` o `⬇ Drive ➔ Disco Duro`.
3. **Configurar velocidad e integridad**: elige el número de hilos (`1`, `4`, `6` u `8`) y deja activadas las casillas de verificación MD5 y limpieza `exFAT`.
4. **Seleccionar carpetas**: elige la carpeta local (`Examinar…`) y opcionalmente una carpeta específica de Google Drive (`Elegir en Drive…`, o deja `Mi Unidad (Raíz)`).
5. **Iniciar y revisar informe**: observa el progreso real en porcentaje, `MB/s` y tiempo restante estimado (`⏳ Restante`) en el pie de página. Al terminar, se mostrará el **Informe Final** con los fallos (si los hubiera) y el botón **`📄 Exportar a PDF…`** (también accesible desde **`📊 Último informe / PDF`**).

---

## Estructura del proyecto

```
stepmigratordrive/
├── StepMigratorDrive.app/  # Lanzador macOS con icono propio (doble clic en Finder)
├── app_gui.py              # Interfaz gráfica (CustomTkinter)
├── migrador.py             # Motor de backend seguro, bidireccional y multihilo
├── requirements.txt        # Dependencias Python
├── .gitignore              # Protege credenciales, tokens, manifiestos y venv
├── README.md               # Documentación del proyecto
├── credentials.json        # Credenciales OAuth2 de Google (ignorado en git)
├── token.enc               # Bóveda cifrada del token OAuth2 (ignorado en git)
└── venv/                   # Entorno virtual Python (ignorado en git)
```

> ⚠️ **Seguridad en GitHub:** El archivo `.gitignore` excluye automáticamente `credentials.json`, `token.enc`, `token.json`, `manifiesto_respaldo_drive.json`, `*.pdf` y `venv/` para que nunca expongas tus credenciales ni datos privados al hacer `git push`.

---

## Módulos

### `migrador.py` — Motor de backend

#### Constantes principales

| Constante | Valor | Descripción |
|---|---|---|
| `SCOPES` | `["https://www.googleapis.com/auth/drive"]` | Permisos OAuth2 |
| `ENC_TOKEN_FILE` | `"token.enc"` | Bóveda cifrada de sesión |
| `LIMIT_BYTES` | `1_536 * 1_024 * 1_024` | Límite de 1.5 GB por segmento |
| `CHUNK_SIZE` | `16 * 1_024 * 1_024` | Tamaño de chunk (16 MB) para subidas/descargas |
| `DIRECT_UPLOAD_THRESHOLD` | `4 * 1_024 * 1_024` | Límite para subida directa en una petición (4 MB) |
| `LARGE_IO_THRESHOLD` | `64 * 1_024 * 1_024` | Límite de E/S pesada (máx. 2 flujos simultáneos para proteger bus exFAT/USB) |
| `DEFAULT_MAX_WORKERS` | `6` | Hilos paralelos por defecto |
| `MAX_RETRIES` | `6` | Reintentos automáticos con backoff exponencial |
| `MANIFEST_FILE` | `"manifiesto_respaldo_drive.json"` | Manifiesto JSON de respaldo certificado tras subida 100 % |

#### Funciones y clases principales

- `authenticate(credentials_path, token_path, log, passphrase, persist_token, enc_token_path) → Resource`
- `get_account_info(service) → dict` — Obtiene email, usuario y cuota de almacenamiento.
- `revoke_and_logout(service_or_creds, token_path, enc_token_path, log) → bool` — Revoca el token en Google y destruye los archivos locales.
- `list_drive_folders(service, parent_id) → List[dict]` — Lista subcarpetas en Drive.
- `scan_source(...)` / `scan_drive_source(...)` — Escaneo local (`os.scandir`) o en Drive.
- `build_segments(...)` — Segmentación ≤ 1.5 GB conservando `rel_dir`.
- `StepMigrator(..., max_workers, progress_callback, verify_checksum, skip_existing, check_quota)` — Orquestador `Local ➔ Drive`.
- `StepDownloader(..., max_workers, progress_callback, verify_checksum, skip_existing)` — Orquestador `Drive ➔ Disco Duro`.
- `export_transfer_report_pdf(report, output_path)` — Exporta a PDF A4 el resumen de la transferencia y el detalle de fallos.

### `app_gui.py` — Interfaz gráfica

- Cola `queue.Queue` drenada periódicamente con `after(40, ...)` para garantizar que las actualizaciones de múltiples hilos nunca llamen directamente a widgets Tk fuera del hilo principal.
- Diálogos dedicados para bóveda cifrada (`SecurityAuthDialog`), selector de carpetas en Drive (`DriveFolderPickerDialog`), cierre/revocación de sesión (`LogoutSecurityDialog`) e informe final con exportación a PDF (`TransferReportDialog`).

---

## Correcciones aplicadas

Además de las correcciones originales de estabilidad de GUI (`try/except` en worker, separador en fila propia, reset de barra de progreso, `WM_DELETE_WINDOW` seguro y bloqueo de doble ejecución), se resolvieron las siguientes mejoras estructurales:

1. **Preservación de jerarquía en carpetas > 1.5 GB (`rel_dir`)**: Cuando `build_segments()` explota una carpeta grande, sus hijos conservan la ruta relativa `rel_dir` para recrear las subcarpetas exactas en el destino.
2. **Escaneo en una sola pasada**: `scan_source()` puebla el árbol `children` con `os.scandir` en una sola pasada, eliminando recálculos repetidos durante la subida.
3. **Escape de comillas en queries de Drive**: `_escape_drive_query()` evita fallos al buscar o crear carpetas cuyos nombres contienen apóstrofos (`'`).
4. **Protección contra borrado ante errores**: El diálogo para enviar el origen local a la papelera ya no aparece si hubo errores o advertencias durante la subida.
5. **Thread-safety en Tkinter con concurrencia**: Toda comunicación desde los hilos del pool pasa por una cola `queue.Queue` consumida exclusivamente en el hilo principal.
