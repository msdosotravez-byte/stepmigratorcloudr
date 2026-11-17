"""
migrador.py — Motor de backend de StepMigratorDrive
=====================================================
Responsabilidades:
  1. Capa de seguridad de cuenta Google Drive:
       · Bóveda cifrada de token OAuth2 (PBKDF2-HMAC-SHA256 + Fernet → token.enc).
       · Migración y borrado seguro de token.json en texto plano.
       · Endurecimiento de permisos de archivo (0o600).
       · Modo sesión efímera (solo RAM, sin persistencia en disco).
       · Verificación de identidad/cuota y revocación OAuth2 en servidores Google.
  2. Escaneo bidireccional:
       · Local → Drive: os.scandir estricto en una sola pasada (árbol completo).
       · Drive → Local: paginación v3 con detección de Google Docs/Sheets/Slides.
  3. Segmentación por lotes ≤ 1.5 GB preservando jerarquía relativa (rel_dir).
  4. Motor de transferencia de alta velocidad y cero interrupciones:
       · Pool multihilo thread-safe (ThreadLocal Drive Resource por hilo).
       · Subida adaptativa (directa ≤ 4 MB / reanudable por chunks de 16 MB).
       · Descarga atómica (.part + os.replace) con chunks de 16 MB.
       · Reintento exponencial con jitter por operación y por chunk individual.
       · Deduplicación y verificación de integridad por suma MD5.
       · Bloqueo anti-suspensión del sistema operativo (SystemWakeLock).

Integración con app_gui.py:
  · authenticate() / get_account_info() / revoke_and_logout()
  · list_drive_folders()
  · StepMigrator   (Local → Drive)
  · StepDownloader (Drive → Disco Duro)
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import http.client
import json
import os
import platform
import random
import shutil
import ssl
import subprocess
import textwrap
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import httplib2
import requests
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import Resource, build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

# ──────────────────────────────────────────────────────────────────────────────
#  Constantes públicas
# ──────────────────────────────────────────────────────────────────────────────

SCOPES: List[str] = ["https://www.googleapis.com/auth/drive"]
CREDENTIALS_FILE: str = "credentials.json"
TOKEN_FILE: str = "token.json"
ENC_TOKEN_FILE: str = "token.enc"

LIMIT_BYTES: int = 1_536 * 1_024 * 1_024            # 1.5 GB estricto por segmento
CHUNK_SIZE: int = 16 * 1_024 * 1_024                # 16 MB por chunk (alta velocidad)
DIRECT_UPLOAD_THRESHOLD: int = 4 * 1_024 * 1_024    # ≤ 4 MB subida directa en 1 petición
DOWNLOAD_BUFFER_SIZE: int = 4 * 1_024 * 1_024       # Buffer de escritura local de 4 MB
LARGE_IO_THRESHOLD: int = 64 * 1_024 * 1_024        # > 64 MB limita concurrencia para no saturar bus exFAT/USB
DEFAULT_MAX_WORKERS: int = 6                        # Concurrencia por defecto
MAX_RETRIES: int = 6                                # Reintentos con backoff exponencial
MANIFEST_FILE: str = "manifiesto_respaldo_drive.json"

EXFAT_SYSTEM_DIRS: frozenset[str] = frozenset(
    {
        ".Spotlight-V100",
        ".Trashes",
        ".fseventsd",
        ".TemporaryItems",
        ".DocumentRevisions-V100",
        "$RECYCLE.BIN",
        "System Volume Information",
        "RECYCLER",
        ".Trash-1000",
    }
)
EXFAT_JUNK_FILES: frozenset[str] = frozenset(
    {
        ".DS_Store",
        "Thumbs.db",
        "desktop.ini",
        ".apdisk",
        ".VolumeIcon.icns",
    }
)
_EXFAT_SYSTEM_DIRS_LOWER: frozenset[str] = frozenset(d.lower() for d in EXFAT_SYSTEM_DIRS)
_EXFAT_JUNK_FILES_LOWER: frozenset[str] = frozenset(f.lower() for f in EXFAT_JUNK_FILES)

_MIME_FOLDER: str = "application/vnd.google-apps.folder"
_MIME_SHORTCUT: str = "application/vnd.google-apps.shortcut"
_PBKDF2_ITERATIONS: int = 480_000

GOOGLE_EXPORT_MAP: Dict[str, Tuple[str, str]] = {
    "application/vnd.google-apps.document": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".docx",
    ),
    "application/vnd.google-apps.spreadsheet": (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".xlsx",
    ),
    "application/vnd.google-apps.presentation": (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".pptx",
    ),
    "application/vnd.google-apps.drawing": (
        "application/pdf",
        ".pdf",
    ),
    "application/vnd.google-apps.script": (
        "application/vnd.google-apps.script+json",
        ".json",
    ),
}

_RETRYABLE_STATUS_CODES = {401, 408, 429, 500, 502, 503, 504}
_RETRYABLE_403_REASONS = {
    "rateLimitExceeded",
    "userRateLimitExceeded",
    "sharingRateLimitExceeded",
    "backendError",
}

#: Callback de logging: (mensaje, nivel)
LogCallback = Callable[[str, str], None]
#: Callback de progreso: (bytes_transferidos, bytes_totales, velocidad_bps)
ProgressCallback = Callable[[int, int, float], None]


class TokenDecryptionError(Exception):
    """Se lanza cuando la contraseña maestra no puede descifrar el token."""


# ══════════════════════════════════════════════════════════════════════════════
#  1.  CAPA DE SEGURIDAD DE CUENTA Y AUTENTICACIÓN
# ══════════════════════════════════════════════════════════════════════════════

class AccountSecurityManager:
    """
    Gestiona la protección criptográfica del token OAuth2, permisos de archivo,
    borrado seguro, verificación de cuenta/cuota y revocación en Google.
    """

    @staticmethod
    def harden_file_permissions(path: str) -> None:
        """Restringe los permisos de ``path`` a lectura/escritura solo del propietario (0o600)."""
        if not path or not os.path.exists(path):
            return
        try:
            os.chmod(path, 0o600)
        except (OSError, NotImplementedError):
            pass

    @staticmethod
    def secure_wipe_file(path: str) -> None:
        """
        Sobrescribe el contenido de ``path`` con datos aleatorios y ceros antes
        de eliminarlo del sistema de archivos.
        """
        if not path or not os.path.isfile(path):
            return
        try:
            size = os.path.getsize(path)
            if size > 0:
                with open(path, "r+b") as fh:
                    fh.seek(0)
                    fh.write(os.urandom(size))
                    fh.flush()
                    os.fsync(fh.fileno())
                    fh.seek(0)
                    fh.write(b"\x00" * size)
                    fh.flush()
                    os.fsync(fh.fileno())
        except OSError:
            pass
        try:
            os.remove(path)
        except OSError:
            pass

    @staticmethod
    def _derive_fernet_key(passphrase: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_PBKDF2_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))

    @classmethod
    def encrypt_token_json(cls, token_json: str, passphrase: str) -> dict:
        """Cifra el JSON del token OAuth2 usando PBKDF2-HMAC-SHA256 + Fernet."""
        if not passphrase:
            raise ValueError("La contraseña maestra no puede estar vacía.")
        salt = os.urandom(16)
        key = cls._derive_fernet_key(passphrase, salt)
        ciphertext = Fernet(key).encrypt(token_json.encode("utf-8"))
        return {
            "version": 1,
            "encrypted": True,
            "salt": base64.b64encode(salt).decode("ascii"),
            "ciphertext": ciphertext.decode("ascii"),
        }

    @classmethod
    def decrypt_token_payload(cls, payload: dict, passphrase: str) -> str:
        """Descifra el payload almacenado en ``token.enc`` y devuelve el JSON original."""
        if not passphrase:
            raise TokenDecryptionError(
                "Se requiere la contraseña maestra para desbloquear la sesión cifrada."
            )
        try:
            if not isinstance(payload, dict) or not payload.get("encrypted"):
                raise TokenDecryptionError("Formato de bóveda de token inválido.")
            salt = base64.b64decode(payload["salt"])
            ciphertext = payload["ciphertext"].encode("ascii")
            key = cls._derive_fernet_key(passphrase, salt)
            plaintext = Fernet(key).decrypt(ciphertext)
            return plaintext.decode("utf-8")
        except TokenDecryptionError:
            raise
        except (InvalidToken, KeyError, TypeError, ValueError) as exc:
            raise TokenDecryptionError(
                "Contraseña maestra incorrecta o token cifrado corrupto."
            ) from exc

    @staticmethod
    def has_saved_token(
        token_path: str = TOKEN_FILE,
        enc_token_path: str = ENC_TOKEN_FILE,
    ) -> Tuple[bool, bool]:
        """
        Comprueba si existe un token guardado en disco.

        Returns
        -------
        Tuple[bool, bool]
            ``(existe_token, esta_cifrado)``
        """
        if os.path.exists(enc_token_path):
            return True, True
        if os.path.exists(token_path):
            return True, False
        return False, False


def harden_file_permissions(path: str) -> None:
    """Alias público de :meth:`AccountSecurityManager.harden_file_permissions`."""
    AccountSecurityManager.harden_file_permissions(path)


def secure_wipe_file(path: str) -> None:
    """Alias público de :meth:`AccountSecurityManager.secure_wipe_file`."""
    AccountSecurityManager.secure_wipe_file(path)


def encrypt_token_json(token_json: str, passphrase: str) -> dict:
    """Alias público de :meth:`AccountSecurityManager.encrypt_token_json`."""
    return AccountSecurityManager.encrypt_token_json(token_json, passphrase)


def decrypt_token_payload(payload: dict, passphrase: str) -> str:
    """Alias público de :meth:`AccountSecurityManager.decrypt_token_payload`."""
    return AccountSecurityManager.decrypt_token_payload(payload, passphrase)


def has_saved_token(
    token_path: str = TOKEN_FILE,
    enc_token_path: str = ENC_TOKEN_FILE,
) -> Tuple[bool, bool]:
    """Alias público de :meth:`AccountSecurityManager.has_saved_token`."""
    return AccountSecurityManager.has_saved_token(token_path, enc_token_path)


def _persist_credentials(
    creds: Credentials,
    token_path: str,
    enc_token_path: str,
    passphrase: Optional[str],
    persist_token: bool,
    log: Callable[[str, str], None],
) -> None:
    """Guarda las credenciales cifradas (o en texto plano si no hay PIN) o limpia si es efímero."""
    if not persist_token:
        secure_wipe_file(token_path)
        secure_wipe_file(enc_token_path)
        log("Sesión efímera activa (credenciales mantenidas solo en RAM).", "OK")
        return

    token_json = creds.to_json()
    try:
        if passphrase:
            payload = encrypt_token_json(token_json, passphrase)
            with open(enc_token_path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            harden_file_permissions(enc_token_path)
            if os.path.exists(token_path):
                secure_wipe_file(token_path)
                log(f"Token plano '{token_path}' migrado y eliminado de forma segura.", "OK")
            log(f"Token cifrado guardado en '{enc_token_path}' (permisos 0600).", "OK")
        else:
            with open(token_path, "w", encoding="utf-8") as fh:
                fh.write(token_json)
            harden_file_permissions(token_path)
            log(
                f"Token guardado en '{token_path}' (permisos 0600, sin cifrado por PIN).",
                "WARN",
            )
    except OSError as exc:
        log(f"No se pudo persistir el token en disco: {exc}", "WARN")


def authenticate(
    credentials_path: str = CREDENTIALS_FILE,
    token_path: str = TOKEN_FILE,
    log: Optional[LogCallback] = None,
    passphrase: Optional[str] = None,
    persist_token: bool = True,
    enc_token_path: str = ENC_TOKEN_FILE,
) -> Resource:
    """
    Ejecuta el flujo OAuth2 con Google Drive protegiendo las credenciales locales.

    Soporta:
      · Bóveda cifrada ``token.enc`` mediante contraseña maestra (PBKDF2 + Fernet).
      · Migración automática de ``token.json`` sin cifrar hacia ``token.enc``.
      · Modo sesión efímera (``persist_token=False``) sin almacenamiento en disco.
      · Refresco silencioso o re-autorización interactiva si el token expiró o fue revocado.

    Raises
    ------
    FileNotFoundError
        Si ``credentials_path`` no existe en disco.
    TokenDecryptionError
        Si ``enc_token_path`` existe pero la ``passphrase`` falta o es incorrecta.
    """

    def _log(msg: str, lvl: str = "INFO") -> None:
        if log:
            log(msg, lvl)

    if not os.path.exists(credentials_path):
        raise FileNotFoundError(
            f"No se encontró '{credentials_path}'. "
            "Descárgalo desde Google Cloud Console > Credenciales > OAuth 2.0."
        )

    harden_file_permissions(credentials_path)
    creds: Optional[Credentials] = None
    loaded_from_plain = False
    needs_persist = False

    # ── 1. Cargar token cifrado si existe ──────────────────────────────────
    if os.path.exists(enc_token_path):
        harden_file_permissions(enc_token_path)
        with open(enc_token_path, "r", encoding="utf-8") as fh:
            try:
                payload = json.load(fh)
            except json.JSONDecodeError as exc:
                raise TokenDecryptionError(
                    f"El archivo '{enc_token_path}' está dañado y no es JSON válido."
                ) from exc

        decrypted_json = decrypt_token_payload(payload, passphrase or "")
        try:
            info = json.loads(decrypted_json)
            creds = Credentials.from_authorized_user_info(info, SCOPES)
            _log(f"Sesión descifrada correctamente desde '{enc_token_path}'.", "OK")
        except Exception as exc:
            _log(f"Token descifrado corrupto, se solicitará nueva autorización: {exc}", "WARN")
            creds = None

    # ── 2. O cargar token plano legado si existe ──────────────────────────
    elif os.path.exists(token_path):
        harden_file_permissions(token_path)
        try:
            creds = Credentials.from_authorized_user_file(token_path, SCOPES)
            loaded_from_plain = True
            _log(f"Token existente cargado desde '{token_path}'.", "INFO")
            if passphrase or not persist_token:
                needs_persist = True
        except Exception as exc:
            _log(f"Token corrupto, se descartará: {exc}", "WARN")
            creds = None

    # ── 3. Refrescar o iniciar flujo OAuth2 interactivo ───────────────────
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            _log("Refrescando token OAuth expirado…", "INFO")
            try:
                creds.refresh(Request())
                _log("Token refrescado correctamente.", "OK")
                needs_persist = True
            except RefreshError as exc:
                _log(
                    f"No se pudo refrescar el token ({exc}); iniciando nuevo login…",
                    "WARN",
                )
                creds = None

        if not creds or not creds.valid:
            _log("Iniciando flujo OAuth2 (se abrirá el navegador)…", "INFO")
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            creds = flow.run_local_server(port=0, open_browser=True)
            _log("Autorización completada.", "OK")
            needs_persist = True

    # ── 4. Persistir o limpiar según configuración de seguridad ───────────
    if needs_persist or not persist_token:
        _persist_credentials(
            creds=creds,
            token_path=token_path,
            enc_token_path=enc_token_path,
            passphrase=passphrase,
            persist_token=persist_token,
            log=_log,
        )
    elif loaded_from_plain and not passphrase:
        _log(
            "Aviso de seguridad: el token está en texto plano; configura un PIN para cifrarlo.",
            "WARN",
        )

    service: Resource = build("drive", "v3", credentials=creds, cache_discovery=False)
    # Adjuntar metadatos de seguridad para el pool multihilo y revocación
    setattr(service, "_step_credentials", creds)
    setattr(service, "_step_encrypted", bool(passphrase) and persist_token)
    setattr(service, "_step_ephemeral", not persist_token)
    _log("Servicio Google Drive v3 listo.", "OK")
    return service


def get_account_info(service: Resource) -> Dict[str, Any]:
    """
    Consulta los datos de identidad y cuota de almacenamiento de la cuenta Drive.

    Returns
    -------
    dict
        ``{"email", "display_name", "usage", "usage_in_drive", "limit", "free"}``
    """
    about = execute_with_retry(
        lambda: service.about()
        .get(fields="user(displayName,emailAddress),storageQuota(limit,usage,usageInDrive)")
        .execute(),
        description="consulta de cuenta y cuota de Drive",
    )
    user = about.get("user", {}) or {}
    quota = about.get("storageQuota", {}) or {}

    def _to_int(val: Any) -> Optional[int]:
        if val is None:
            return None
        try:
            return int(val)
        except (TypeError, ValueError):
            return None

    limit = _to_int(quota.get("limit"))
    usage = _to_int(quota.get("usage"))
    usage_in_drive = _to_int(quota.get("usageInDrive"))
    free = max(0, limit - (usage or 0)) if limit is not None else None

    return {
        "email": user.get("emailAddress", "Cuenta desconocida"),
        "display_name": user.get("displayName", ""),
        "usage": usage,
        "usage_in_drive": usage_in_drive,
        "limit": limit,
        "free": free,
    }


def revoke_and_logout(
    service_or_creds: Any,
    token_path: str = TOKEN_FILE,
    enc_token_path: str = ENC_TOKEN_FILE,
    log: Optional[LogCallback] = None,
) -> bool:
    """
    Revoca el token OAuth2 en los servidores de Google y destruye de forma segura
    ``token.enc`` y ``token.json`` del disco local.
    """

    def _log(msg: str, lvl: str = "INFO") -> None:
        if log:
            log(msg, lvl)

    creds: Optional[Credentials] = None
    if isinstance(service_or_creds, Credentials):
        creds = service_or_creds
    elif service_or_creds is not None:
        creds = getattr(service_or_creds, "_step_credentials", None)
        if creds is None:
            creds = getattr(getattr(service_or_creds, "_http", None), "credentials", None)

    revoked_remote = True
    token_to_revoke = None
    if creds is not None:
        token_to_revoke = getattr(creds, "refresh_token", None) or getattr(creds, "token", None)

    if token_to_revoke:
        try:
            resp = requests.post(
                "https://oauth2.googleapis.com/revoke",
                params={"token": token_to_revoke},
                headers={"content-type": "application/x-www-form-urlencoded"},
                timeout=10,
            )
            if resp.status_code == 200:
                _log("Token OAuth2 revocado en los servidores de Google.", "OK")
            else:
                revoked_remote = False
                _log(
                    f"Google devolvió HTTP {resp.status_code} al revocar token; "
                    "se limpiarán las credenciales locales igualmente.",
                    "WARN",
                )
        except requests.RequestException as exc:
            revoked_remote = False
            _log(f"No se pudo contactar con Google para revocar ({exc}); limpiando local.", "WARN")

    secure_wipe_file(enc_token_path)
    secure_wipe_file(token_path)
    _log("Archivos de sesión locales destruidos de forma segura.", "OK")
    return revoked_remote


# ══════════════════════════════════════════════════════════════════════════════
#  2.  RESILIENCIA, CONCURRENCIA Y ANTI-SUSPENSIÓN
# ══════════════════════════════════════════════════════════════════════════════

class SystemWakeLock:
    """
    Mantiene el sistema activo durante transferencias largas para evitar
    interrupciones por suspensión del equipo o ahorro de energía de red/disco.
    """

    def __init__(self, log: Optional[LogCallback] = None) -> None:
        self._log = log
        self._proc: Optional[subprocess.Popen] = None
        self._win_active = False

    def __enter__(self) -> "SystemWakeLock":
        sys_name = platform.system()
        if sys_name == "Darwin":
            try:
                self._proc = subprocess.Popen(
                    ["caffeinate", "-di", "-w", str(os.getpid())],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if self._log:
                    self._log("Protección anti-suspensión activa (caffeinate).", "INFO")
            except OSError:
                self._proc = None
        elif sys_name == "Windows":
            try:
                # ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED
                ctypes.windll.kernel32.SetThreadExecutionState(0x80000000 | 0x00000001 | 0x00000040)
                self._win_active = True
                if self._log:
                    self._log("Protección anti-suspensión activa (Windows ExecutionState).", "INFO")
            except Exception:
                self._win_active = False
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None
        if self._win_active:
            try:
                ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)
            except Exception:
                pass
            self._win_active = False


class ThreadSafeDrivePool:
    """
    Proporciona una instancia de ``Resource`` por hilo (``threading.local``)
    respaldada por credenciales compartidas con refresco sincronizado por lock.
    """

    def __init__(
        self,
        service: Optional[Resource] = None,
        credentials: Optional[Credentials] = None,
        service_factory: Optional[Callable[[], Resource]] = None,
    ) -> None:
        self._primary_service = service
        self._factory = service_factory
        self._local = threading.local()
        self._refresh_lock = threading.Lock()
        self._last_refresh_ts: float = 0.0

        if credentials is not None:
            self._creds: Optional[Credentials] = credentials
        elif service is not None:
            raw_creds = getattr(service, "_step_credentials", None)
            self._creds = raw_creds if isinstance(raw_creds, Credentials) else None
        else:
            self._creds = None

    def get_service(self) -> Resource:
        """Devuelve un cliente Drive seguro para el hilo actual."""
        svc = getattr(self._local, "service", None)
        if svc is not None:
            return svc

        if self._factory is not None:
            svc = self._factory()
            self._local.service = svc
            return svc

        if self._creds is not None:
            svc = build("drive", "v3", credentials=self._creds, cache_discovery=False)
            self._local.service = svc
            return svc

        if self._primary_service is not None:
            return self._primary_service

        raise RuntimeError("No hay servicio ni credenciales disponibles para Drive.")

    def refresh_if_needed(self, log: Optional[LogCallback] = None) -> None:
        """Refresca el token OAuth2 una sola vez bajo lock cuando vence o da 401."""
        if self._creds is None:
            return
        with self._refresh_lock:
            now = time.monotonic()
            # Evitar refrescos redundantes si otro hilo acaba de refrescar hace < 5s
            if now - self._last_refresh_ts < 5.0 and self._creds.valid:
                return
            if self._creds.refresh_token:
                if log:
                    log("Renovando token OAuth2 automáticamente durante la transferencia…", "INFO")
                self._creds.refresh(Request())
                self._last_refresh_ts = time.monotonic()
                if log:
                    log("Token OAuth2 renovado sin interrumpir la transferencia.", "OK")


def _extract_http_error_reason(exc: HttpError) -> str:
    """Extrae el motivo (reason) de un ``HttpError`` de Google API."""
    content = getattr(exc, "content", b"")
    if isinstance(content, bytes):
        text = content.decode("utf-8", errors="ignore")
    else:
        text = str(content)
    try:
        data = json.loads(text)
        errors = data.get("error", {}).get("errors", [])
        if errors and isinstance(errors, list):
            return str(errors[0].get("reason", ""))
    except Exception:
        pass
    return text


def _is_retryable_http_error(exc: HttpError) -> bool:
    status = getattr(getattr(exc, "resp", None), "status", None)
    if status in _RETRYABLE_STATUS_CODES:
        return True
    if status == 403:
        reason = _extract_http_error_reason(exc)
        if reason in _RETRYABLE_403_REASONS:
            return True
        lowered = reason.lower()
        if "ratelimit" in lowered or "rate limit" in lowered or "quota" in lowered and "storage" not in lowered:
            return True
    return False


def execute_with_retry(
    func: Callable[[], Any],
    log: Optional[LogCallback] = None,
    description: str = "operación Drive",
    max_retries: int = MAX_RETRIES,
    creds_pool: Optional[ThreadSafeDrivePool] = None,
) -> Any:
    """
    Ejecuta ``func`` reintentando automáticamente ante errores HTTP transitorios
    (401, 403 rate limit, 408, 429, 5xx) y microcortes de red con backoff
    exponencial y jitter.
    """
    attempt = 0
    while True:
        try:
            return func()
        except (FileNotFoundError, PermissionError, IsADirectoryError, NotADirectoryError):
            raise
        except HttpError as exc:
            status = getattr(getattr(exc, "resp", None), "status", None)
            if not _is_retryable_http_error(exc) or attempt >= max_retries:
                raise
            if status == 401 and creds_pool is not None:
                try:
                    creds_pool.refresh_if_needed(log=log)
                except Exception:
                    pass
            delay = min(30.0, (2 ** attempt) * 0.8 + random.uniform(0.1, 0.9))
            attempt += 1
            if log:
                log(
                    f"  ↻ Reintento {attempt}/{max_retries} en {description} "
                    f"(HTTP {status}, espera {delay:.1f}s)…",
                    "WARN",
                )
            time.sleep(delay)
        except (
            TimeoutError,
            ConnectionError,
            BrokenPipeError,
            ssl.SSLError,
            http.client.HTTPException,
            httplib2.HttpLib2Error,
            OSError,
        ) as exc:
            if attempt >= max_retries:
                raise
            delay = min(30.0, (2 ** attempt) * 0.8 + random.uniform(0.1, 0.9))
            attempt += 1
            if log:
                log(
                    f"  ↻ Microcorte de red en {description} ({exc}); "
                    f"reintento {attempt}/{max_retries} en {delay:.1f}s…",
                    "WARN",
                )
            time.sleep(delay)


class _TransferProgressTracker:
    """Rastreador thread-safe de progreso global en bytes y velocidad instantánea."""

    def __init__(
        self,
        total_bytes: int,
        callback: Optional[ProgressCallback] = None,
    ) -> None:
        self._total = max(0, total_bytes)
        self._callback = callback
        self._lock = threading.Lock()
        self._completed_bytes: int = 0
        self._active_bytes: Dict[str, int] = {}
        self._start_ts = time.monotonic()
        self._last_emit_ts: float = 0.0

    def update_file(self, key: str, current_bytes: int) -> None:
        if not self._callback:
            return
        with self._lock:
            self._active_bytes[key] = max(0, current_bytes)
            now = time.monotonic()
            if now - self._last_emit_ts < 0.12:
                return
            self._last_emit_ts = now
            self._emit_locked(now)

    def complete_file(self, key: str, final_bytes: int) -> None:
        if not self._callback:
            return
        with self._lock:
            self._active_bytes.pop(key, None)
            self._completed_bytes += max(0, final_bytes)
            now = time.monotonic()
            self._last_emit_ts = now
            self._emit_locked(now)

    def finish(self) -> None:
        if not self._callback:
            return
        with self._lock:
            self._active_bytes.clear()
            now = time.monotonic()
            elapsed = max(0.001, now - self._start_ts)
            transferred = max(self._completed_bytes, self._total)
            self._callback(transferred, self._total, transferred / elapsed)

    def _emit_locked(self, now: float) -> None:
        transferred = self._completed_bytes + sum(self._active_bytes.values())
        if self._total > 0:
            transferred = min(transferred, self._total)
        elapsed = max(0.001, now - self._start_ts)
        speed_bps = transferred / elapsed
        self._callback(transferred, self._total, speed_bps)  # type: ignore[misc]


def _compute_md5(file_path: str) -> Optional[str]:
    """Calcula el digest MD5 hexadecimal en streaming con buffer de 4 MB."""
    h = hashlib.md5()
    try:
        with open(file_path, "rb") as fh:
            while True:
                chunk = fh.read(DOWNLOAD_BUFFER_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _escape_drive_query(value: str) -> str:
    """Escapa barras invertidas y comillas simples para queries de Drive API v3."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _sanitize_local_name(name: str) -> str:
    """Sanitiza un nombre de Drive para crear archivos/carpetas seguros en disco duro."""
    cleaned = _normalize_nfc(name).replace("/", "_").replace("\\", "_").replace("\x00", "_")
    if platform.system() == "Windows":
        for ch in '<>:"|?*':
            cleaned = cleaned.replace(ch, "_")
    cleaned = cleaned.strip()
    if cleaned in ("", ".", ".."):
        return "_"
    return cleaned


def _normalize_nfc(name: str) -> str:
    """Normaliza cadenas Unicode a forma compuesta NFC (compatibilidad macOS NFD → Drive/APFS)."""
    return unicodedata.normalize("NFC", name)


def _format_rfc3339(epoch_ts: Optional[float]) -> Optional[str]:
    """Convierte un timestamp POSIX (mtime) a formato RFC 3339 UTC para Google Drive."""
    if epoch_ts is None:
        return None
    try:
        return datetime.fromtimestamp(epoch_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (OSError, OverflowError, ValueError):
        return None


def _parse_rfc3339_to_epoch(ts_str: Optional[str]) -> Optional[float]:
    """Convierte una fecha RFC 3339 de Google Drive a timestamp POSIX."""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def is_exfat_junk(name: str, is_dir: bool, is_root_level: bool = False) -> bool:
    """
    Detecta archivos fantasma AppleDouble (``._*``) y metadatos ocultos de
    sistema generados en volúmenes exFAT (macOS/Windows/Linux).
    """
    lower = name.lower()
    if is_dir:
        return lower in _EXFAT_SYSTEM_DIRS_LOWER
    if lower in _EXFAT_JUNK_FILES_LOWER:
        return True
    if name.startswith("._") and len(name) > 2:
        return True
    return False


def is_volume_mount_point(path: str) -> bool:
    """Indica si ``path`` apunta al punto de montaje de un disco o volumen externo."""
    if not path:
        return False
    norm = os.path.abspath(path)
    if os.path.ismount(norm):
        return True
    if platform.system() == "Darwin":
        parts = [p for p in norm.split(os.sep) if p]
        if len(parts) == 2 and parts[0] == "Volumes":
            return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
#  3.  MODELOS DE DATOS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScannedEntry:
    """Representa un archivo o directorio leído del origen (local o Google Drive)."""

    path: str                               # Ruta absoluta local o ruta virtual en Drive
    name: str                               # Nombre de archivo o carpeta
    is_dir: bool
    size: int                               # Bytes; en directorios: suma recursiva
    rel_dir: str = ""                       # Ruta relativa del directorio padre respecto al origen
    drive_id: Optional[str] = None          # ID en Google Drive (descarga)
    mime_type: Optional[str] = None         # MIME type en Drive
    md5_checksum: Optional[str] = None      # MD5 reportado por Drive
    export_mime: Optional[str] = None       # MIME de exportación para Google Docs/Sheets/Slides
    export_ext: str = ""                    # Extensión de exportación (.docx, .xlsx, etc.)
    mtime: Optional[float] = None           # Fecha original de modificación (timestamp POSIX)
    children: List["ScannedEntry"] = field(default_factory=list)


@dataclass
class Segment:
    """
    Grupo de :class:`ScannedEntry` listos para migrar en una única pasada.
    El total acumulado nunca supera :data:`LIMIT_BYTES`.
    """

    entries: List[ScannedEntry] = field(default_factory=list)
    total_size: int = 0

    def add(self, entry: ScannedEntry) -> None:
        self.entries.append(entry)
        self.total_size += entry.size

    @property
    def would_overflow(self) -> bool:
        return self.total_size > LIMIT_BYTES


# ══════════════════════════════════════════════════════════════════════════════
#  4.  ESCÁNERES (LOCAL con os.scandir ESTRICTO + GOOGLE DRIVE)
# ══════════════════════════════════════════════════════════════════════════════

def _dir_size(
    path: str,
    error_log: List[Tuple[str, str]],
    log: LogCallback,
) -> int:
    """
    Calcula el tamaño total de un directorio de forma recursiva usando
    ``os.scandir``. Captura errores por entrada individual sin detener el escaneo.
    """
    total = 0
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    if entry.is_file(follow_symlinks=False):
                        total += entry.stat(follow_symlinks=False).st_size
                    elif entry.is_dir(follow_symlinks=False):
                        total += _dir_size(entry.path, error_log, log)
                except (OSError, PermissionError) as exc:
                    error_log.append((entry.path, str(exc)))
                    log(f"[SKIP] No se puede leer '{entry.path}': {exc}", "WARN")
                    continue
    except (OSError, PermissionError) as exc:
        error_log.append((path, str(exc)))
        log(f"[SKIP] No se puede abrir directorio '{path}': {exc}", "WARN")
    return total


def _scan_dir_tree(
    dir_path: str,
    rel_dir: str,
    error_log: List[Tuple[str, str]],
    log: LogCallback,
    filter_exfat_junk: bool = True,
    stats: Optional[Dict[str, int]] = None,
) -> Tuple[List[ScannedEntry], int]:
    """
    Escanea recursivamente ``dir_path`` en una única pasada usando ``os.scandir``
    y construye el árbol completo de :class:`ScannedEntry` con ``rel_dir``,
    ``mtime``, normalización NFC y filtrado opcional de basura exFAT.
    """
    children: List[ScannedEntry] = []
    total = 0
    try:
        with os.scandir(dir_path) as it:
            for entry in it:
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                    if filter_exfat_junk and is_exfat_junk(
                        entry.name, is_dir, is_root_level=False
                    ):
                        if stats is not None:
                            stats["junk_skipped"] = stats.get("junk_skipped", 0) + 1
                        continue

                    norm_name = _normalize_nfc(entry.name)
                    if is_dir:
                        child_rel = os.path.join(rel_dir, norm_name) if rel_dir else norm_name
                        sub_children, size = _scan_dir_tree(
                            entry.path,
                            child_rel,
                            error_log,
                            log,
                            filter_exfat_junk=filter_exfat_junk,
                            stats=stats,
                        )
                        children.append(
                            ScannedEntry(
                                path=entry.path,
                                name=norm_name,
                                is_dir=True,
                                size=size,
                                rel_dir=rel_dir,
                                children=sub_children,
                            )
                        )
                    else:
                        st = entry.stat(follow_symlinks=False)
                        size = st.st_size
                        children.append(
                            ScannedEntry(
                                path=entry.path,
                                name=norm_name,
                                is_dir=False,
                                size=size,
                                rel_dir=rel_dir,
                                mtime=st.st_mtime,
                            )
                        )
                    total += size
                except (OSError, PermissionError) as exc:
                    error_log.append((entry.path, str(exc)))
                    log(f"[SKIP] '{entry.path}': {exc}", "WARN")
                    continue
    except (OSError, PermissionError) as exc:
        error_log.append((dir_path, str(exc)))
        log(f"[SKIP] No se puede abrir directorio '{dir_path}': {exc}", "WARN")

    return children, total


def scan_source(
    source_path: str,
    error_log: List[Tuple[str, str]],
    log: LogCallback,
    filter_exfat_junk: bool = True,
    stats: Optional[Dict[str, int]] = None,
) -> List[ScannedEntry]:
    """
    Escanea el **nivel raíz** y árbol completo de ``source_path`` con ``os.scandir``
    y devuelve una lista de :class:`ScannedEntry` con sus tamaños, ``mtime`` y
    ``children`` calculados.
    """
    if not os.path.isdir(source_path):
        raise NotADirectoryError(f"'{source_path}' no es un directorio válido.")

    scan_stats = stats if stats is not None else {"junk_skipped": 0}
    scan_stats.setdefault("junk_skipped", 0)
    entries: List[ScannedEntry] = []
    log(f"Escaneando directorio raíz: {source_path}", "INFO")

    try:
        with os.scandir(source_path) as it:
            for entry in it:
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                    if filter_exfat_junk and is_exfat_junk(
                        entry.name, is_dir, is_root_level=True
                    ):
                        scan_stats["junk_skipped"] += 1
                        continue

                    norm_name = _normalize_nfc(entry.name)
                    if is_dir:
                        sub_children, size = _scan_dir_tree(
                            entry.path,
                            norm_name,
                            error_log,
                            log,
                            filter_exfat_junk=filter_exfat_junk,
                            stats=scan_stats,
                        )
                        scanned = ScannedEntry(
                            path=entry.path,
                            name=norm_name,
                            is_dir=True,
                            size=size,
                            rel_dir="",
                            children=sub_children,
                        )
                    else:
                        st = entry.stat(follow_symlinks=False)
                        size = st.st_size
                        scanned = ScannedEntry(
                            path=entry.path,
                            name=norm_name,
                            is_dir=False,
                            size=size,
                            rel_dir="",
                            mtime=st.st_mtime,
                        )

                    entries.append(scanned)
                    tipo = "DIR" if is_dir else "FIL"
                    log(f"  {tipo}  {norm_name}  ({_fmt_size(size)})", "INFO")

                except (OSError, PermissionError) as exc:
                    error_log.append((entry.path, str(exc)))
                    log(f"[SKIP] '{entry.path}': {exc}", "WARN")
                    continue

    except (OSError, PermissionError) as exc:
        error_log.append((source_path, str(exc)))
        log(f"[ERROR] No se pudo abrir '{source_path}': {exc}", "ERROR")

    if scan_stats["junk_skipped"] > 0:
        log(
            f"🧹 Omitidos {scan_stats['junk_skipped']} archivos/carpetas de sistema exFAT "
            f"(._*, .Spotlight-V100, .Trashes…)",
            "INFO",
        )
    log(f"Escaneo completo: {len(entries)} entrada(s) en el nivel raíz.", "INFO")
    return entries


def _scan_dir_flat(
    dir_path: str,
    error_log: List[Tuple[str, str]],
    log: LogCallback,
    rel_dir: str = "",
) -> List[ScannedEntry]:
    """
    Escanea los hijos directos de ``dir_path`` usando ``os.scandir``.
    Fallback si :func:`build_segments` recibe entradas sin ``children`` pre-escaneados.
    """
    children, _ = _scan_dir_tree(dir_path, rel_dir, error_log, log)
    return children


def list_drive_folders(
    service: Resource,
    parent_id: str = "root",
) -> List[Dict[str, str]]:
    """
    Lista las subcarpetas directas no eliminadas dentro de ``parent_id`` en Google Drive.
    """
    parent = parent_id or "root"
    query = (
        f"'{_escape_drive_query(parent)}' in parents and "
        f"mimeType='{_MIME_FOLDER}' and trashed=false"
    )
    folders: List[Dict[str, str]] = []
    page_token: Optional[str] = None

    while True:
        res = execute_with_retry(
            lambda pt=page_token: service.files()
            .list(
                q=query,
                fields="nextPageToken, files(id, name)",
                orderBy="name",
                pageSize=1000,
                pageToken=pt,
                supportsAllDrives=True,
                includeItemsFromAllDrives=True,
            )
            .execute(),
            description=f"listado de carpetas en Drive ({parent})",
        )
        for item in res.get("files", []):
            folders.append({"id": item["id"], "name": item["name"]})
        page_token = res.get("nextPageToken")
        if not page_token:
            break

    return folders


def _scan_drive_dir_recursive(
    service: Resource,
    folder_id: str,
    rel_dir: str,
    error_log: List[Tuple[str, str]],
    log: LogCallback,
    creds_pool: Optional[ThreadSafeDrivePool] = None,
) -> Tuple[List[ScannedEntry], int]:
    """Escanea recursivamente una carpeta de Google Drive mediante paginación v3."""
    entries: List[ScannedEntry] = []
    total_size = 0
    seen_names: set[str] = set()
    query = f"'{_escape_drive_query(folder_id)}' in parents and trashed=false"
    page_token: Optional[str] = None

    while True:
        try:
            res = execute_with_retry(
                lambda pt=page_token: service.files()
                .list(
                    q=query,
                    fields="nextPageToken, files(id, name, mimeType, size, md5Checksum, modifiedTime)",
                    pageSize=1000,
                    pageToken=pt,
                    supportsAllDrives=True,
                    includeItemsFromAllDrives=True,
                )
                .execute(),
                log=log,
                description=f"escaneo de carpeta Drive '{rel_dir or 'root'}'",
                creds_pool=creds_pool,
            )
        except Exception as exc:
            error_log.append((rel_dir or folder_id, str(exc)))
            log(f"[SKIP] No se pudo listar carpeta Drive '{rel_dir or folder_id}': {exc}", "WARN")
            break

        for item in res.get("files", []):
            try:
                item_id = item.get("id", "")
                raw_name = item.get("name", "sin_nombre")
                mime = item.get("mimeType", "")
                mtime = _parse_rfc3339_to_epoch(item.get("modifiedTime"))

                if mime == _MIME_SHORTCUT:
                    log(f"  [SKIP] Acceso directo omitido: '{raw_name}'", "WARN")
                    continue

                safe_name = _sanitize_local_name(raw_name)
                export_mime: Optional[str] = None
                export_ext: str = ""

                if mime in GOOGLE_EXPORT_MAP:
                    export_mime, export_ext = GOOGLE_EXPORT_MAP[mime]
                elif mime.startswith("application/vnd.google-apps.") and mime != _MIME_FOLDER:
                    log(
                        f"  [SKIP] Tipo Google Workspace no exportable ({mime}): '{raw_name}'",
                        "WARN",
                    )
                    continue

                # Desambiguar nombres duplicados (case-insensitive para discos APFS/NTFS/exFAT)
                candidate = safe_name
                full_candidate = (
                    f"{candidate}{export_ext}"
                    if (export_ext and not candidate.lower().endswith(export_ext.lower()))
                    else candidate
                )
                if full_candidate.lower() in seen_names:
                    stem, ext = os.path.splitext(safe_name)
                    candidate = f"{stem}_{item_id[:6]}{ext}"
                    full_candidate = (
                        f"{candidate}{export_ext}"
                        if (export_ext and not candidate.lower().endswith(export_ext.lower()))
                        else candidate
                    )
                seen_names.add(full_candidate.lower())

                virtual_path = os.path.join(rel_dir, candidate) if rel_dir else candidate

                if mime == _MIME_FOLDER:
                    sub_children, folder_size = _scan_drive_dir_recursive(
                        service,
                        item_id,
                        virtual_path,
                        error_log,
                        log,
                        creds_pool=creds_pool,
                    )
                    entries.append(
                        ScannedEntry(
                            path=virtual_path,
                            name=candidate,
                            is_dir=True,
                            size=folder_size,
                            rel_dir=rel_dir,
                            drive_id=item_id,
                            mime_type=mime,
                            mtime=mtime,
                            children=sub_children,
                        )
                    )
                    total_size += folder_size
                else:
                    try:
                        file_size = int(item.get("size") or 0)
                    except (TypeError, ValueError):
                        file_size = 0
                    entries.append(
                        ScannedEntry(
                            path=virtual_path,
                            name=candidate,
                            is_dir=False,
                            size=file_size,
                            rel_dir=rel_dir,
                            drive_id=item_id,
                            mime_type=mime,
                            md5_checksum=item.get("md5Checksum"),
                            export_mime=export_mime,
                            export_ext=export_ext,
                            mtime=mtime,
                        )
                    )
                    total_size += file_size
            except Exception as exc:
                bad_name = item.get("name", "?") if isinstance(item, dict) else "?"
                bad_path = os.path.join(rel_dir, str(bad_name)) if rel_dir else str(bad_name)
                error_log.append((bad_path, str(exc)))
                log(f"  [SKIP] Error procesando entrada en Drive '{bad_path}': {exc}", "WARN")
                continue

        page_token = res.get("nextPageToken")
        if not page_token:
            break

    return entries, total_size


def scan_drive_source(
    service: Resource,
    folder_id: Optional[str],
    error_log: List[Tuple[str, str]],
    log: LogCallback,
    creds_pool: Optional[ThreadSafeDrivePool] = None,
) -> List[ScannedEntry]:
    """
    Escanea una carpeta origen en Google Drive (o ``root``) y devuelve la lista
    de :class:`ScannedEntry` de primer nivel con sus subárboles poblados.
    """
    target_id = folder_id or "root"
    log(f"Escaneando origen en Google Drive (ID: {target_id})…", "INFO")
    entries, _ = _scan_drive_dir_recursive(
        service=service,
        folder_id=target_id,
        rel_dir="",
        error_log=error_log,
        log=log,
        creds_pool=creds_pool,
    )
    for entry in entries:
        tipo = "DIR" if entry.is_dir else "FIL"
        log(f"  {tipo}  {entry.name}  ({_fmt_size(entry.size)})", "INFO")
    log(f"Escaneo de Drive completo: {len(entries)} entrada(s) en el nivel raíz.", "INFO")
    return entries


# ══════════════════════════════════════════════════════════════════════════════
#  5.  SEGMENTACIÓN  (límite estricto 1.5 GB)
# ══════════════════════════════════════════════════════════════════════════════

def build_segments(
    entries: List[ScannedEntry],
    error_log: List[Tuple[str, str]],
    log: LogCallback,
    _emit_summary: bool = True,
) -> List[Segment]:
    """
    Agrupa ``entries`` en :class:`Segment` cuyo tamaño acumulado nunca supera
    :data:`LIMIT_BYTES` (1.5 GB), preservando ``rel_dir`` cuando una carpeta
    grande es explotada recursivamente.
    """
    segments: List[Segment] = []
    current = Segment()

    def _flush() -> None:
        nonlocal current
        if current.entries:
            segments.append(current)
            current = Segment()

    for entry in entries:
        if entry.size <= LIMIT_BYTES:
            if current.total_size + entry.size > LIMIT_BYTES:
                _flush()
            current.add(entry)
        else:
            if entry.is_dir:
                log(
                    f"Carpeta grande ({_fmt_size(entry.size)}): "
                    f"'{entry.name}' → procesando hijos conservando jerarquía.",
                    "WARN",
                )
                _flush()
                if entry.children:
                    children = entry.children
                elif os.path.isdir(entry.path):
                    next_rel = os.path.join(entry.rel_dir, entry.name) if entry.rel_dir else entry.name
                    children = _scan_dir_flat(entry.path, error_log, log, rel_dir=next_rel)
                else:
                    children = []
                child_segs = build_segments(
                    children, error_log, log, _emit_summary=False
                )
                segments.extend(child_segs)
            else:
                log(
                    f"Archivo mayor de 1.5 GB ({_fmt_size(entry.size)}): "
                    f"'{entry.name}' → segmento individual.",
                    "WARN",
                )
                _flush()
                solo = Segment()
                solo.add(entry)
                segments.append(solo)

    _flush()

    if _emit_summary:
        log(f"Segmentación completa: {len(segments)} segmento(s) generados.", "OK")
        for i, seg in enumerate(segments, 1):
            log(
                f"  Segmento {i}: {len(seg.entries)} entrada(s), "
                f"{_fmt_size(seg.total_size)}",
                "INFO",
            )
    return segments


def _collect_segment_tasks(
    segment_entries: List[ScannedEntry],
) -> Tuple[List[Tuple[str, str]], List[ScannedEntry]]:
    """
    Extrae de forma ordenada todas las carpetas (como tuplas ``(rel_dir, name)``)
    y todos los archivos hoja (``ScannedEntry``) incluidos en ``segment_entries``.
    """
    dirs: List[Tuple[str, str]] = []
    files: List[ScannedEntry] = []

    def _walk(entry: ScannedEntry) -> None:
        if entry.is_dir:
            dirs.append((entry.rel_dir, entry.name))
            if entry.children:
                for child in entry.children:
                    _walk(child)
        else:
            files.append(entry)

    for item in segment_entries:
        _walk(item)

    return dirs, files


# ══════════════════════════════════════════════════════════════════════════════
#  6.  SUBIDA A GOOGLE DRIVE (MULTIHILO + REANUDABLE + MD5)
# ══════════════════════════════════════════════════════════════════════════════

class DriveUploader:
    """
    Gestiona la creación de carpetas y la subida de archivos a Google Drive,
    preservando la estructura de directorios, con soporte thread-safe y
    deduplicación/verificación por hash MD5.
    """

    _MIME_FOLDER = _MIME_FOLDER

    def __init__(
        self,
        service: Resource,
        root_folder_id: Optional[str] = None,
        service_pool: Optional[ThreadSafeDrivePool] = None,
        verify_checksum: bool = True,
        skip_existing: bool = True,
    ) -> None:
        self._svc = service
        self._root_id = root_folder_id
        self._pool = service_pool or ThreadSafeDrivePool(service=service)
        self._verify_checksum = verify_checksum
        self._skip_existing = skip_existing
        self._lock = threading.Lock()
        self._folder_cache: Dict[str, str] = {}
        self._existing_files_cache: Dict[str, Dict[str, Tuple[str, int, Optional[str]]]] = {}

    def _get_service(self) -> Resource:
        return self._pool.get_service()

    def get_or_create_folder(
        self,
        name: str,
        parent_id: Optional[str],
        log: LogCallback,
    ) -> str:
        """
        Devuelve el Drive ID de la carpeta ``name`` dentro de ``parent_id``.
        Thread-safe mediante bloqueo para evitar carpetas duplicadas entre hilos.
        """
        name = _normalize_nfc(name)
        parent = parent_id or "root"
        cache_key = f"{parent}/{name}"

        with self._lock:
            if cache_key in self._folder_cache:
                return self._folder_cache[cache_key]

            svc = self._get_service()
            escaped = _escape_drive_query(name)
            query = (
                f"name='{escaped}' and "
                f"'{_escape_drive_query(parent)}' in parents and "
                f"mimeType='{self._MIME_FOLDER}' and "
                f"trashed=false"
            )
            try:
                res = execute_with_retry(
                    lambda: svc.files()
                    .list(
                        q=query,
                        fields="files(id)",
                        pageSize=1,
                        supportsAllDrives=True,
                        includeItemsFromAllDrives=True,
                    )
                    .execute(),
                    log=log,
                    description=f"búsqueda de carpeta '{name}'",
                    creds_pool=self._pool,
                )
                files = res.get("files", [])
                if files:
                    folder_id: str = files[0]["id"]
                    log(f"  Carpeta existente en Drive: '{name}'", "INFO")
                    self._folder_cache[cache_key] = folder_id
                    return folder_id
            except Exception as exc:
                log(f"  Advertencia buscando carpeta '{name}': {exc}", "WARN")

            meta = {
                "name": name,
                "mimeType": self._MIME_FOLDER,
                "parents": [parent],
            }
            try:
                folder = execute_with_retry(
                    lambda: svc.files()
                    .create(body=meta, fields="id", supportsAllDrives=True)
                    .execute(),
                    log=log,
                    description=f"creación de carpeta '{name}'",
                    creds_pool=self._pool,
                )
                folder_id = folder["id"]
                log(f"  Carpeta creada en Drive: '{name}' ({folder_id})", "OK")
                self._folder_cache[cache_key] = folder_id
                return folder_id
            except Exception as exc:
                log(f"  [ERROR] No se pudo crear carpeta '{name}': {exc}", "ERROR")
                raise

    def resolve_rel_dir(
        self,
        rel_dir: str,
        root_parent_id: Optional[str],
        log: LogCallback,
    ) -> Optional[str]:
        """Resuelve/crea todas las carpetas intermedias de ``rel_dir`` desde ``root_parent_id``."""
        if not rel_dir:
            return root_parent_id
        current = root_parent_id
        parts = [p for p in rel_dir.replace("\\", "/").split("/") if p and p != "."]
        for part in parts:
            current = self.get_or_create_folder(part, current, log)
        return current

    def _get_existing_files(
        self,
        parent_id: Optional[str],
        log: LogCallback,
    ) -> Dict[str, Tuple[str, int, Optional[str]]]:
        """Obtiene (con caché) los archivos ya existentes en ``parent_id`` para deduplicación."""
        parent = parent_id or "root"
        with self._lock:
            if parent in self._existing_files_cache:
                return self._existing_files_cache[parent]

        svc = self._get_service()
        mapping: Dict[str, Tuple[str, int, Optional[str]]] = {}
        query = (
            f"'{_escape_drive_query(parent)}' in parents and "
            f"mimeType!='{self._MIME_FOLDER}' and trashed=false"
        )
        page_token: Optional[str] = None
        try:
            while True:
                res = execute_with_retry(
                    lambda pt=page_token: svc.files()
                    .list(
                        q=query,
                        fields="nextPageToken, files(id, name, size, md5Checksum)",
                        pageSize=1000,
                        pageToken=pt,
                        supportsAllDrives=True,
                        includeItemsFromAllDrives=True,
                    )
                    .execute(),
                    log=log,
                    description=f"índice de archivos existentes ({parent})",
                    creds_pool=self._pool,
                )
                for item in res.get("files", []):
                    try:
                        sz = int(item.get("size") or 0)
                    except (TypeError, ValueError):
                        sz = 0
                    mapping[_normalize_nfc(item["name"])] = (
                        item["id"],
                        sz,
                        item.get("md5Checksum"),
                    )
                page_token = res.get("nextPageToken")
                if not page_token:
                    break
        except Exception as exc:
            log(f"  Advertencia listando archivos existentes en '{parent}': {exc}", "WARN")

        with self._lock:
            self._existing_files_cache.setdefault(parent, mapping)
            return self._existing_files_cache[parent]

    def upload_file(
        self,
        local_path: str,
        file_name: str,
        parent_id: Optional[str],
        log: LogCallback,
        error_log: List[Tuple[str, str]],
        error_lock: Optional[threading.Lock] = None,
        progress_cb: Optional[Callable[[int], None]] = None,
        mtime: Optional[float] = None,
        result_info: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Sube ``local_path`` a Drive priorizando velocidad, integridad y preservación:
          · Omite archivos idénticos ya existentes en Drive (por tamaño + MD5).
          · Normaliza nombre a NFC y preserva ``modifiedTime`` original del disco.
          · Subida directa en 1 petición HTTP si ≤ 4 MB; chunked de 16 MB si > 4 MB.
          · Reintentos exponenciales en cada chunk sin reiniciar el archivo.
          · Verificación posterior de hash MD5.
        """
        def _record_error(msg: str) -> None:
            if error_lock:
                with error_lock:
                    error_log.append((local_path, msg))
            else:
                error_log.append((local_path, msg))

        file_name = _normalize_nfc(file_name)
        parent = parent_id or "root"
        try:
            st = os.stat(local_path)
            file_size = st.st_size
            if mtime is None:
                mtime = st.st_mtime
        except (OSError, PermissionError) as exc:
            _record_error(str(exc))
            log(f"  [SKIP] No se puede leer '{local_path}': {exc}", "WARN")
            return None

        local_md5: Optional[str] = None
        if self._verify_checksum or self._skip_existing:
            local_md5 = _compute_md5(local_path)

        # Deduplicación inteligente: evitar re-subir archivos ya íntegros en Drive
        if self._skip_existing and local_md5 is not None:
            existing = self._get_existing_files(parent, log)
            match = existing.get(file_name)
            if match is not None:
                ex_id, ex_size, ex_md5 = match
                if ex_md5 == local_md5 and ex_size == file_size:
                    if progress_cb:
                        progress_cb(file_size)
                    if result_info is not None:
                        result_info.update(
                            {
                                "drive_id": ex_id,
                                "md5": ex_md5,
                                "skipped": True,
                                "size": file_size,
                            }
                        )
                    log(f"  ⏭ '{file_name}' ya existe e íntegro en Drive (omitido)", "INFO")
                    return ex_id

        meta: Dict[str, Any] = {"name": file_name, "parents": [parent]}
        modified_rfc3339 = _format_rfc3339(mtime)
        if modified_rfc3339 is not None:
            meta["modifiedTime"] = modified_rfc3339
        svc = self._get_service()

        try:
            if file_size <= DIRECT_UPLOAD_THRESHOLD:
                media = MediaFileUpload(local_path, resumable=False)
                resp = execute_with_retry(
                    lambda: svc.files()
                    .create(
                        body=meta,
                        media_body=media,
                        fields="id, md5Checksum, size",
                        supportsAllDrives=True,
                    )
                    .execute(),
                    log=log,
                    description=f"subida directa '{file_name}'",
                    creds_pool=self._pool,
                )
                if progress_cb:
                    progress_cb(file_size)
            else:
                media = MediaFileUpload(
                    local_path,
                    chunksize=CHUNK_SIZE,
                    resumable=True,
                )
                request = svc.files().create(
                    body=meta,
                    media_body=media,
                    fields="id, md5Checksum, size",
                    supportsAllDrives=True,
                )
                resp = None
                while resp is None:
                    status, resp = execute_with_retry(
                        lambda: request.next_chunk(),
                        log=log,
                        description=f"chunk de '{file_name}'",
                        creds_pool=self._pool,
                    )
                    if status is not None and progress_cb:
                        progress_cb(int(status.resumable_progress))
                if progress_cb:
                    progress_cb(file_size)
        except (OSError, PermissionError) as exc:
            _record_error(str(exc))
            log(f"  [SKIP] Error de lectura en '{local_path}': {exc}", "WARN")
            return None
        except HttpError as exc:
            _record_error(str(exc))
            log(f"  [SKIP] Error HTTP subiendo '{file_name}': {exc}", "WARN")
            return None
        except Exception as exc:
            _record_error(str(exc))
            log(f"  [SKIP] Error inesperado subiendo '{file_name}': {exc}", "WARN")
            return None

        drive_id: str = resp.get("id", "?")
        drive_md5: Optional[str] = resp.get("md5Checksum")

        if self._verify_checksum and local_md5 and drive_md5 and local_md5 != drive_md5:
            msg = f"Integridad MD5 no coincide (local={local_md5}, drive={drive_md5})"
            _record_error(msg)
            log(f"  [ERROR] '{file_name}': {msg}", "ERROR")
            return None

        verified_md5 = drive_md5 or local_md5
        with self._lock:
            self._existing_files_cache.setdefault(parent, {})[file_name] = (
                drive_id,
                file_size,
                verified_md5,
            )

        if result_info is not None:
            result_info.update(
                {
                    "drive_id": drive_id,
                    "md5": verified_md5,
                    "skipped": False,
                    "size": file_size,
                }
            )

        log(f"  ✔ '{file_name}'  →  Drive ({drive_id})", "OK")
        return drive_id

    def upload_entry(
        self,
        entry: ScannedEntry,
        parent_id: Optional[str],
        log: LogCallback,
        error_log: List[Tuple[str, str]],
    ) -> None:
        """
        Sube una :class:`ScannedEntry` individual preservando la jerarquía de carpetas.
        Se mantiene para compatibilidad con llamadas directas secuenciales.
        """
        try:
            target_parent = self.resolve_rel_dir(entry.rel_dir, parent_id, log)
        except Exception as exc:
            error_log.append((entry.path, str(exc)))
            log(f"  [SKIP] No se pudo resolver ruta destino para '{entry.name}': {exc}", "ERROR")
            return

        if entry.is_dir:
            try:
                folder_id = self.get_or_create_folder(entry.name, target_parent, log)
            except Exception as exc:
                error_log.append((entry.path, str(exc)))
                log(f"  [SKIP] No se pudo crear '{entry.name}' en Drive: {exc}", "ERROR")
                return

            children = entry.children
            if not children and os.path.isdir(entry.path):
                next_rel = os.path.join(entry.rel_dir, entry.name) if entry.rel_dir else entry.name
                children = _scan_dir_flat(entry.path, error_log, log, rel_dir=next_rel)

            for child in children:
                try:
                    self.upload_entry(child, parent_id if child.rel_dir else folder_id, log, error_log)
                except Exception as exc:
                    error_log.append((child.path, str(exc)))
                    log(f"  [SKIP] Error inesperado en '{child.name}': {exc}", "ERROR")
        else:
            self.upload_file(entry.path, entry.name, target_parent, log, error_log)


class StepMigrator:
    """
    Orquesta la migración Local → Google Drive en 3 fases con concurrencia
    multihilo, filtrado de basura exFAT, preservación de fechas, control de
    bus USB/exFAT, certificación pre-formateo y protección anti-suspensión.
    """

    def __init__(
        self,
        source_path: str,
        drive_service: Resource,
        log_callback: LogCallback,
        drive_folder_id: Optional[str] = None,
        max_workers: int = DEFAULT_MAX_WORKERS,
        progress_callback: Optional[ProgressCallback] = None,
        verify_checksum: bool = True,
        skip_existing: bool = True,
        check_quota: bool = True,
        service_pool: Optional[ThreadSafeDrivePool] = None,
        filter_exfat_junk: bool = True,
        manifest_path: Optional[str] = None,
    ) -> None:
        self.source_path = source_path
        self._service = drive_service
        self._log = log_callback
        self._folder_id = drive_folder_id
        self._max_workers = max(1, int(max_workers))
        self._progress_cb = progress_callback
        self._verify_checksum = verify_checksum
        self._skip_existing = skip_existing
        self._check_quota = check_quota
        self._filter_exfat_junk = filter_exfat_junk
        self._pool = service_pool or ThreadSafeDrivePool(service=drive_service)
        self.error_log: List[Tuple[str, str]] = []
        self._error_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._large_io_sem = threading.Semaphore(2)

        # Contadores de auditoría pre-formateo
        self.total_files_scanned: int = 0
        self.files_uploaded_ok: int = 0
        self.files_skipped_identical: int = 0
        self.bytes_verified: int = 0
        self.junk_skipped: int = 0
        self.manifest_path: str = manifest_path or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), MANIFEST_FILE
        )
        self._manifest_entries: List[Dict[str, Any]] = []

    @property
    def is_safe_to_format(self) -> bool:
        """
        Devuelve ``True`` únicamente si no hubo ningún error, se escaneó al menos
        un archivo y el 100 % de los archivos fueron subidos o verificados en Drive.
        """
        return (
            len(self.error_log) == 0
            and self.total_files_scanned > 0
            and (self.files_uploaded_ok + self.files_skipped_identical)
            == self.total_files_scanned
        )

    def _write_manifest(self) -> None:
        """Guarda el manifiesto de respaldo verificado fuera del volumen origen."""
        manifest_dir = os.path.dirname(os.path.abspath(self.manifest_path))
        if manifest_dir:
            os.makedirs(manifest_dir, exist_ok=True)
        payload = {
            "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
            "source_path": os.path.abspath(self.source_path),
            "drive_folder_id": self._folder_id or "root",
            "total_files": self.total_files_scanned,
            "files_uploaded_ok": self.files_uploaded_ok,
            "files_skipped_identical": self.files_skipped_identical,
            "bytes_verified": self.bytes_verified,
            "junk_skipped": self.junk_skipped,
            "verified_all_md5": self._verify_checksum,
            "files": sorted(self._manifest_entries, key=lambda x: x["rel_path"]),
        }
        with open(self.manifest_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        harden_file_permissions(self.manifest_path)

    def run(self) -> List[Tuple[str, str]]:
        """Ejecuta Escaneo → Verificación de cuota → Segmentación → Subida paralela → Auditoría."""
        self.total_files_scanned = 0
        self.files_uploaded_ok = 0
        self.files_skipped_identical = 0
        self.bytes_verified = 0
        self.junk_skipped = 0
        self._manifest_entries = []

        self._log("━━━  FASE 1 / 3: ESCANEO LOCAL  ━━━", "SECTION")
        scan_stats: Dict[str, int] = {"junk_skipped": 0}
        try:
            entries = scan_source(
                self.source_path,
                self.error_log,
                self._log,
                filter_exfat_junk=self._filter_exfat_junk,
                stats=scan_stats,
            )
        except NotADirectoryError as exc:
            self._log(f"[ERROR] {exc}", "ERROR")
            return self.error_log

        self.junk_skipped = scan_stats.get("junk_skipped", 0)
        if not entries:
            self._log("No se encontraron archivos válidos en el origen.", "WARN")
            return self.error_log

        total_bytes = sum(e.size for e in entries)

        # Verificación preventiva de cuota en Drive
        if self._check_quota:
            try:
                info = get_account_info(self._service)
                free_bytes = info.get("free")
                if free_bytes is not None and total_bytes > free_bytes:
                    msg = (
                        f"Espacio insuficiente en Google Drive: necesitas {_fmt_size(total_bytes)}, "
                        f"disponibles {_fmt_size(free_bytes)} ({info.get('email')})."
                    )
                    self._log(f"[ERROR] {msg}", "ERROR")
                    self.error_log.append((self.source_path, msg))
                    return self.error_log
                if free_bytes is not None:
                    self._log(
                        f"Cuota verificada en {info.get('email')}: {_fmt_size(free_bytes)} libres.",
                        "OK",
                    )
            except Exception as exc:
                self._log(f"No se pudo verificar cuota previa ({exc}); continuando…", "WARN")

        self._log("", "INFO")
        self._log("━━━  FASE 2 / 3: SEGMENTACIÓN  ━━━", "SECTION")
        segments = build_segments(entries, self.error_log, self._log)
        self.total_files_scanned = sum(
            len(_collect_segment_tasks(seg.entries)[1]) for seg in segments
        )
        self.total_files_scanned = sum(
            len(_collect_segment_tasks(seg.entries)[1]) for seg in segments
        )

        self._log("", "INFO")
        self._log(
            f"━━━  FASE 3 / 3: SUBIDA A DRIVE ({self._max_workers} hilo(s))  ━━━",
            "SECTION",
        )

        uploader = DriveUploader(
            service=self._service,
            root_folder_id=self._folder_id,
            service_pool=self._pool,
            verify_checksum=self._verify_checksum,
            skip_existing=self._skip_existing,
        )
        tracker = _TransferProgressTracker(total_bytes, self._progress_cb)
        rel_dir_ids: Dict[str, Optional[str]] = {"": self._folder_id}

        with SystemWakeLock(log=self._log):
            total_segs = len(segments)
            for idx, segment in enumerate(segments, 1):
                self._log(
                    f"Segmento {idx}/{total_segs}  ·  {len(segment.entries)} entrada(s)"
                    f"  ·  {_fmt_size(segment.total_size)}",
                    "SECTION",
                )
                dirs_to_create, file_tasks = _collect_segment_tasks(segment.entries)
                failed_rel_dirs: set[str] = set()

                # Pre-crear todas las carpetas requeridas en orden jerárquico
                all_rel_dirs_needed = set()
                for d_rel, d_name in dirs_to_create:
                    full_rel = os.path.join(d_rel, d_name) if d_rel else d_name
                    all_rel_dirs_needed.add(full_rel)
                for f_entry in file_tasks:
                    if f_entry.rel_dir:
                        all_rel_dirs_needed.add(f_entry.rel_dir)

                for rel in sorted(all_rel_dirs_needed, key=lambda s: s.count("/") + s.count("\\")):
                    norm_rel = rel.replace("\\", "/")
                    if norm_rel in rel_dir_ids or any(
                        norm_rel == fd or norm_rel.startswith(fd + "/") for fd in failed_rel_dirs
                    ):
                        continue
                    try:
                        rel_dir_ids[norm_rel] = uploader.resolve_rel_dir(
                            norm_rel, self._folder_id, self._log
                        )
                    except Exception as exc:
                        failed_rel_dirs.add(norm_rel)
                        with self._error_lock:
                            self.error_log.append((rel, str(exc)))
                        self._log(
                            f"[ERROR] No se pudo preparar carpeta '{rel}' en Drive: {exc}",
                            "ERROR",
                        )

                # Subida paralela con control anti-saturación para archivos > 64 MB
                def _upload_task(file_entry: ScannedEntry) -> None:
                    file_key = file_entry.path
                    try:
                        norm_rel = file_entry.rel_dir.replace("\\", "/")
                        if any(
                            norm_rel == fd or norm_rel.startswith(fd + "/")
                            for fd in failed_rel_dirs
                        ):
                            with self._error_lock:
                                self.error_log.append(
                                    (
                                        file_entry.path,
                                        f"Carpeta padre '{norm_rel}' fallida; archivo omitido.",
                                    )
                                )
                            self._log(
                                f"  [SKIP] '{file_entry.name}' omitido por fallo en carpeta padre '{norm_rel}'.",
                                "WARN",
                            )
                            return

                        parent_drive_id = rel_dir_ids.get(norm_rel)
                        if parent_drive_id is None and norm_rel:
                            parent_drive_id = uploader.resolve_rel_dir(
                                norm_rel, self._folder_id, self._log
                            )

                        res_info: Dict[str, Any] = {}
                        io_guard = (
                            self._large_io_sem
                            if file_entry.size > LARGE_IO_THRESHOLD
                            else nullcontext()
                        )
                        with io_guard:
                            drive_id = uploader.upload_file(
                                local_path=file_entry.path,
                                file_name=file_entry.name,
                                parent_id=parent_drive_id,
                                log=self._log,
                                error_log=self.error_log,
                                error_lock=self._error_lock,
                                progress_cb=lambda b, k=file_key: tracker.update_file(k, b),
                                mtime=file_entry.mtime,
                                result_info=res_info,
                            )
                        if drive_id is not None:
                            rel_path = (
                                os.path.join(file_entry.rel_dir, file_entry.name)
                                if file_entry.rel_dir
                                else file_entry.name
                            )
                            with self._stats_lock:
                                if res_info.get("skipped"):
                                    self.files_skipped_identical += 1
                                else:
                                    self.files_uploaded_ok += 1
                                self.bytes_verified += file_entry.size
                                self._manifest_entries.append(
                                    {
                                        "rel_path": rel_path.replace("\\", "/"),
                                        "size": file_entry.size,
                                        "md5": res_info.get("md5"),
                                        "drive_id": drive_id,
                                        "skipped": bool(res_info.get("skipped")),
                                    }
                                )
                    except Exception as exc:
                        with self._error_lock:
                            self.error_log.append((file_entry.path, str(exc)))
                        self._log(
                            f"  [SKIP] Fallo aislado en '{file_entry.name}': {exc}",
                            "ERROR",
                        )
                    finally:
                        tracker.complete_file(file_key, file_entry.size)

                with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
                    futures = [executor.submit(_upload_task, f_entry) for f_entry in file_tasks]
                    for fut in as_completed(futures):
                        try:
                            fut.result()
                        except Exception as exc:
                            with self._error_lock:
                                self.error_log.append((self.source_path, str(exc)))
                            self._log(f"[ERROR] Fallo inesperado en hilo de subida: {exc}", "ERROR")

        tracker.finish()

        self._log("", "INFO")
        if self.is_safe_to_format:
            try:
                self._write_manifest()
                self._log(
                    f"📜 Manifiesto de respaldo guardado en '{self.manifest_path}'.",
                    "OK",
                )
            except OSError as exc:
                self._log(f"No se pudo guardar manifiesto de respaldo: {exc}", "WARN")
            self._log(
                f"🟢 APTO PARA FORMATEAR: {self.total_files_scanned} archivo(s) "
                f"({_fmt_size(self.bytes_verified)}) verificados en Google Drive.",
                "OK",
            )
        elif self.error_log:
            self._log(
                f"🔴 NO FORMATEAR EL DISCO: {len(self.error_log)} archivo(s) tuvieron "
                f"incidencias y deben revisarse antes de formatear.",
                "ERROR",
            )
            for path, err in self.error_log:
                self._log(f"  · {path}: {err}", "WARN")
        else:
            self._log("Migración completada.", "OK")

        return self.error_log


# ══════════════════════════════════════════════════════════════════════════════
#  7.  PROCESO INVERSO: NUBE (GOOGLE DRIVE) → DISCO DURO
# ══════════════════════════════════════════════════════════════════════════════

class DriveDownloader:
    """
    Descarga archivos desde Google Drive al disco duro local en modo
    **estrictamente solo lectura** sobre Drive, con escritura atómica (``.part``),
    chunks de 16 MB, reintentos por chunk y verificación de integridad MD5.
    """

    def __init__(
        self,
        service: Resource,
        dest_path: str,
        root_folder_id: Optional[str] = None,
        service_pool: Optional[ThreadSafeDrivePool] = None,
        verify_checksum: bool = True,
        skip_existing: bool = True,
    ) -> None:
        self._svc = service
        self._dest_path = dest_path
        self._root_id = root_folder_id
        self._pool = service_pool or ThreadSafeDrivePool(service=service)
        self._verify_checksum = verify_checksum
        self._skip_existing = skip_existing

    def download_file(
        self,
        entry: ScannedEntry,
        target_dir: str,
        log: LogCallback,
        error_log: List[Tuple[str, str]],
        error_lock: Optional[threading.Lock] = None,
        progress_cb: Optional[Callable[[int], None]] = None,
        result_info: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Descarga ``entry`` a ``target_dir`` de forma atómica y tolerante a cortes."""

        def _record_error(path: str, msg: str) -> None:
            if error_lock:
                with error_lock:
                    error_log.append((path, msg))
            else:
                error_log.append((path, msg))

        out_name = entry.name
        if entry.export_ext and not out_name.lower().endswith(entry.export_ext.lower()):
            out_name = f"{out_name}{entry.export_ext}"

        local_path = os.path.join(target_dir, out_name)
        part_path = f"{local_path}.part"

        try:
            os.makedirs(target_dir, exist_ok=True)
        except OSError as exc:
            _record_error(local_path, str(exc))
            log(f"  [ERROR] No se pudo crear directorio local '{target_dir}': {exc}", "ERROR")
            return None

        # Deduplicación: si el archivo ya está íntegro en disco duro, omitir
        if (
            self._skip_existing
            and not entry.export_mime
            and entry.md5_checksum
            and os.path.isfile(local_path)
        ):
            try:
                if (
                    os.path.getsize(local_path) == entry.size
                    and _compute_md5(local_path) == entry.md5_checksum
                ):
                    if progress_cb:
                        progress_cb(entry.size)
                    if result_info is not None:
                        result_info.update({"skipped": True, "size": entry.size})
                    log(f"  ⏭ '{out_name}' ya existe e íntegro en disco (omitido)", "INFO")
                    return local_path
            except OSError:
                pass

        if not entry.drive_id:
            _record_error(local_path, "Falta drive_id para descargar el archivo.")
            return None

        svc = self._pool.get_service()
        try:
            if entry.export_mime:
                request = svc.files().export_media(
                    fileId=entry.drive_id,
                    mimeType=entry.export_mime,
                )
            else:
                request = svc.files().get_media(
                    fileId=entry.drive_id,
                    supportsAllDrives=True,
                )

            with open(part_path, "wb", buffering=DOWNLOAD_BUFFER_SIZE) as fh:
                downloader = MediaIoBaseDownload(fh, request, chunksize=CHUNK_SIZE)
                done = False
                while not done:
                    status, done = execute_with_retry(
                        lambda: downloader.next_chunk(),
                        log=log,
                        description=f"descarga '{out_name}'",
                        creds_pool=self._pool,
                    )
                    if status is not None and progress_cb:
                        progress_cb(int(status.resumable_progress))
                fh.flush()

            actual_size = os.path.getsize(part_path)

            if self._verify_checksum and entry.md5_checksum and not entry.export_mime:
                local_md5 = _compute_md5(part_path)
                if local_md5 != entry.md5_checksum:
                    try:
                        os.remove(part_path)
                    except OSError:
                        pass
                    msg = f"Integridad MD5 fallida (esperado={entry.md5_checksum}, obtenido={local_md5})"
                    _record_error(local_path, msg)
                    log(f"  [ERROR] '{out_name}': {msg}", "ERROR")
                    return None

            os.replace(part_path, local_path)
            if entry.mtime is not None:
                try:
                    os.utime(local_path, (entry.mtime, entry.mtime))
                except OSError:
                    pass
            if progress_cb:
                progress_cb(entry.size or actual_size)
            if result_info is not None:
                result_info.update({"skipped": False, "size": actual_size})
            log(f"  ✔ Drive  →  '{out_name}' ({_fmt_size(actual_size)})", "OK")
            return local_path

        except (OSError, PermissionError) as exc:
            _cleanup_part(part_path)
            _record_error(local_path, str(exc))
            log(f"  [SKIP] Error de escritura en '{local_path}': {exc}", "WARN")
            return None
        except HttpError as exc:
            _cleanup_part(part_path)
            _record_error(local_path, str(exc))
            log(f"  [SKIP] Error HTTP descargando '{out_name}': {exc}", "WARN")
            return None
        except Exception as exc:
            _cleanup_part(part_path)
            _record_error(local_path, str(exc))
            log(f"  [SKIP] Error inesperado descargando '{out_name}': {exc}", "WARN")
            return None


def _cleanup_part(part_path: str) -> None:
    if os.path.exists(part_path):
        try:
            os.remove(part_path)
        except OSError:
            pass


class StepDownloader:
    """
    Orquesta el proceso inverso (Google Drive → Disco Duro) en 3 fases:
      1. Escaneo en Drive (solo lectura).
      2. Segmentación ≤ 1.5 GB preservando jerarquía.
      3. Descarga multihilo atómica con verificación MD5 y anti-suspensión.
    """

    def __init__(
        self,
        dest_path: str,
        drive_service: Resource,
        log_callback: LogCallback,
        drive_folder_id: Optional[str] = None,
        max_workers: int = DEFAULT_MAX_WORKERS,
        progress_callback: Optional[ProgressCallback] = None,
        verify_checksum: bool = True,
        skip_existing: bool = True,
        service_pool: Optional[ThreadSafeDrivePool] = None,
    ) -> None:
        self.dest_path = dest_path
        self._service = drive_service
        self._log = log_callback
        self._folder_id = drive_folder_id
        self._max_workers = max(1, int(max_workers))
        self._progress_cb = progress_callback
        self._verify_checksum = verify_checksum
        self._skip_existing = skip_existing
        self._pool = service_pool or ThreadSafeDrivePool(service=drive_service)
        self.error_log: List[Tuple[str, str]] = []
        self._error_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._large_io_sem = threading.Semaphore(2)

        self.total_files_scanned: int = 0
        self.files_downloaded_ok: int = 0
        self.files_skipped_identical: int = 0
        self.bytes_verified: int = 0

    def run(self) -> List[Tuple[str, str]]:
        """Ejecuta Escaneo en Drive → Comprobación de disco → Segmentación → Descarga paralela."""
        self.total_files_scanned = 0
        self.files_downloaded_ok = 0
        self.files_skipped_identical = 0
        self.bytes_verified = 0

        if not os.path.isdir(self.dest_path):
            try:
                os.makedirs(self.dest_path, exist_ok=True)
            except OSError as exc:
                msg = f"No se pudo preparar destino '{self.dest_path}': {exc}"
                self._log(f"[ERROR] {msg}", "ERROR")
                self.error_log.append((self.dest_path, msg))
                return self.error_log

        self._log("━━━  FASE 1 / 3: ESCANEO EN DRIVE (SOLO LECTURA)  ━━━", "SECTION")
        entries = scan_drive_source(
            service=self._service,
            folder_id=self._folder_id,
            error_log=self.error_log,
            log=self._log,
            creds_pool=self._pool,
        )

        if not entries:
            self._log("No se encontraron archivos en la carpeta de Drive.", "WARN")
            return self.error_log

        total_bytes = sum(e.size for e in entries)

        # Comprobar espacio libre en disco duro antes de descargar
        try:
            free_disk = shutil.disk_usage(self.dest_path).free
            if total_bytes > free_disk:
                msg = (
                    f"Espacio insuficiente en disco duro: necesitas {_fmt_size(total_bytes)}, "
                    f"disponibles {_fmt_size(free_disk)} en '{self.dest_path}'."
                )
                self._log(f"[ERROR] {msg}", "ERROR")
                self.error_log.append((self.dest_path, msg))
                return self.error_log
            self._log(f"Espacio libre en disco verificado: {_fmt_size(free_disk)}.", "OK")
        except OSError as exc:
            self._log(f"No se pudo verificar espacio libre en disco ({exc}); continuando…", "WARN")

        self._log("", "INFO")
        self._log("━━━  FASE 2 / 3: SEGMENTACIÓN  ━━━", "SECTION")
        segments = build_segments(entries, self.error_log, self._log)
        self.total_files_scanned = sum(
            len(_collect_segment_tasks(seg.entries)[1]) for seg in segments
        )

        self._log("", "INFO")
        self._log(
            f"━━━  FASE 3 / 3: DESCARGA A DISCO DURO ({self._max_workers} hilo(s))  ━━━",
            "SECTION",
        )

        downloader = DriveDownloader(
            service=self._service,
            dest_path=self.dest_path,
            root_folder_id=self._folder_id,
            service_pool=self._pool,
            verify_checksum=self._verify_checksum,
            skip_existing=self._skip_existing,
        )
        tracker = _TransferProgressTracker(total_bytes, self._progress_cb)

        with SystemWakeLock(log=self._log):
            total_segs = len(segments)
            for idx, segment in enumerate(segments, 1):
                self._log(
                    f"Segmento {idx}/{total_segs}  ·  {len(segment.entries)} entrada(s)"
                    f"  ·  {_fmt_size(segment.total_size)}",
                    "SECTION",
                )
                dirs_to_create, file_tasks = _collect_segment_tasks(segment.entries)

                # Crear jerarquía de directorios locales (incluidas carpetas vacías)
                for d_rel, d_name in dirs_to_create:
                    rel_path = os.path.join(d_rel, d_name) if d_rel else d_name
                    local_dir = os.path.join(self.dest_path, rel_path)
                    try:
                        os.makedirs(local_dir, exist_ok=True)
                    except OSError as exc:
                        with self._error_lock:
                            self.error_log.append((local_dir, str(exc)))
                        self._log(f"  [ERROR] No se pudo crear '{local_dir}': {exc}", "ERROR")

                def _download_task(file_entry: ScannedEntry) -> None:
                    file_key = file_entry.drive_id or file_entry.path
                    try:
                        target_dir = (
                            os.path.join(self.dest_path, file_entry.rel_dir)
                            if file_entry.rel_dir
                            else self.dest_path
                        )
                        io_guard = (
                            self._large_io_sem
                            if file_entry.size > LARGE_IO_THRESHOLD
                            else nullcontext()
                        )
                        res_info: Dict[str, Any] = {}
                        with io_guard:
                            local_res = downloader.download_file(
                                entry=file_entry,
                                target_dir=target_dir,
                                log=self._log,
                                error_log=self.error_log,
                                error_lock=self._error_lock,
                                progress_cb=lambda b, k=file_key: tracker.update_file(k, b),
                                result_info=res_info,
                            )
                        if local_res is not None:
                            with self._stats_lock:
                                if res_info.get("skipped"):
                                    self.files_skipped_identical += 1
                                else:
                                    self.files_downloaded_ok += 1
                                self.bytes_verified += int(res_info.get("size") or file_entry.size)
                    except Exception as exc:
                        with self._error_lock:
                            self.error_log.append((file_entry.path, str(exc)))
                        self._log(
                            f"  [SKIP] Fallo aislado descargando '{file_entry.name}': {exc}",
                            "ERROR",
                        )
                    finally:
                        tracker.complete_file(file_key, file_entry.size)

                with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
                    futures = [executor.submit(_download_task, f_entry) for f_entry in file_tasks]
                    for fut in as_completed(futures):
                        try:
                            fut.result()
                        except Exception as exc:
                            with self._error_lock:
                                self.error_log.append((self.dest_path, str(exc)))
                            self._log(f"[ERROR] Fallo inesperado en hilo de descarga: {exc}", "ERROR")

        tracker.finish()

        self._log("", "INFO")
        if self.error_log:
            self._log(
                f"Descarga finalizada con {len(self.error_log)} advertencia(s).",
                "WARN",
            )
            for path, err in self.error_log:
                self._log(f"  · {path}: {err}", "WARN")
        else:
            self._log(
                "Descarga completada sin errores. Tus archivos en Google Drive permanecen intactos.",
                "OK",
            )

        return self.error_log


# ══════════════════════════════════════════════════════════════════════════════
#  8.  EXPORTACIÓN DE INFORME DE TRANSFERENCIA A PDF (SIN DEPENDENCIAS EXTERNAS)
# ══════════════════════════════════════════════════════════════════════════════

def _pdf_safe_text(text: str) -> str:
    """Normaliza caracteres fuera de WinAnsi/Latin-1 y escapa operadores PDF."""
    replacements = {
        "➔": "->",
        "→": "->",
        "⇄": "<->",
        "·": "-",
        "—": "-",
        "–": "-",
        "✔": "[OK]",
        "✖": "[ERROR]",
        "⚠": "[AVISO]",
        "…": "...",
    }
    for src_ch, dst_ch in replacements.items():
        text = text.replace(src_ch, dst_ch)
    latin1 = text.encode("latin-1", errors="replace").decode("latin-1")
    return latin1.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def export_transfer_report_pdf(report: Dict[str, Any], output_path: str) -> str:
    """
    Genera un informe PDF A4 multipágina con el resumen de la transferencia y el
    listado completo de fallos encontrados (sin dependencias externas).
    """
    page_w, page_h = 595, 842
    margin = 42
    usable_w = page_w - 2 * margin
    bottom_limit = 54

    pages_ops: List[List[str]] = []
    cur_ops: List[str] = []
    y = page_h - margin

    def _new_page() -> None:
        nonlocal cur_ops, y
        if cur_ops:
            pages_ops.append(cur_ops)
        cur_ops = []
        y = page_h - margin

    def _draw_text(
        x: float,
        y_pos: float,
        txt: str,
        font: str = "/F1",
        size: int = 10,
        rgb: Tuple[float, float, float] = (0.12, 0.12, 0.18),
    ) -> None:
        r, g, b = rgb
        safe = _pdf_safe_text(txt)
        cur_ops.append(
            f"BT {font} {size} Tf {r:.3f} {g:.3f} {b:.3f} rg 1 0 0 1 {x:.1f} {y_pos:.1f} Tm ({safe}) Tj ET"
        )

    def _draw_rect(
        x: float,
        y_pos: float,
        w: float,
        h: float,
        rgb: Tuple[float, float, float],
    ) -> None:
        r, g, b = rgb
        cur_ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg {x:.1f} {y_pos:.1f} {w:.1f} {h:.1f} re f")

    def _ensure_space(needed: float) -> None:
        if y - needed < bottom_limit:
            _new_page()

    # ── Cabecera principal ────────────────────────────────────────────────
    _draw_rect(margin, y - 52, usable_w, 52, (0.09, 0.08, 0.17))
    _draw_text(
        margin + 14,
        y - 24,
        "StepMigratorDrive - Informe Final de Transferencia",
        font="/F2",
        size=15,
        rgb=(0.95, 0.94, 1.0),
    )
    _draw_text(
        margin + 14,
        y - 42,
        f"Generado: {report.get('timestamp', '')}   |   {report.get('direction_label', '')}",
        font="/F1",
        size=9,
        rgb=(0.75, 0.72, 0.88),
    )
    y -= 66

    # ── Banner de estado ──────────────────────────────────────────────────
    errors: List[Tuple[str, str]] = list(report.get("errors") or [])
    failed_count = len(errors)
    if failed_count == 0:
        _draw_rect(margin, y - 24, usable_w, 24, (0.86, 0.97, 0.91))
        status_msg = "ESTADO: COMPLETADO SIN ERRORES (100 % VERIFICADO)"
        status_rgb = (0.04, 0.45, 0.25)
    else:
        _draw_rect(margin, y - 24, usable_w, 24, (0.99, 0.89, 0.90))
        status_msg = f"ESTADO: FINALIZADO CON {failed_count} FALLO(S) - REVISAR ANTES DE FORMATEAR"
        status_rgb = (0.72, 0.11, 0.20)
    _draw_text(margin + 12, y - 16, status_msg, font="/F2", size=10, rgb=status_rgb)
    y -= 38

    # ── Bloque de resumen ─────────────────────────────────────────────────
    _draw_text(margin, y, "RESUMEN DE LA OPERACION", font="/F2", size=11, rgb=(0.25, 0.19, 0.55))
    y -= 16

    summary_rows = [
        ("Cuenta Drive", str(report.get("account_email") or "No especificada")),
        ("Origen", str(report.get("source_path") or "-")),
        ("Destino", str(report.get("destination") or "-")),
        ("Duracion", f"{float(report.get('duration_seconds', 0.0)):.1f} s"),
        ("Archivos escaneados", str(report.get("total_files", 0))),
        ("Transferidos OK", str(report.get("transferred_ok", 0))),
        ("Omitidos (ya integros MD5)", str(report.get("skipped_identical", 0))),
        ("Basura exFAT filtrada", str(report.get("junk_skipped", 0))),
        ("Datos verificados", _fmt_size(int(report.get("bytes_verified", 0)))),
        ("Total de fallos", str(failed_count)),
    ]

    for label, val in summary_rows:
        wrapped_val = textwrap.wrap(f"{label}: {val}", width=86) or [f"{label}: {val}"]
        for idx_line, line in enumerate(wrapped_val):
            _ensure_space(14)
            _draw_text(
                margin + 8,
                y,
                line,
                font="/F2" if idx_line == 0 and label == "Total de fallos" and failed_count > 0 else "/F1",
                size=10,
                rgb=(0.72, 0.11, 0.20) if (label == "Total de fallos" and failed_count > 0) else (0.15, 0.15, 0.20),
            )
            y -= 14

    y -= 10
    _ensure_space(28)
    _draw_text(margin, y, f"DETALLE DE FALLOS ({failed_count})", font="/F2", size=11, rgb=(0.25, 0.19, 0.55))
    y -= 16

    if not errors:
        _ensure_space(18)
        _draw_text(
            margin + 8,
            y,
            "No se registraron fallos durante la transferencia. Todos los archivos fueron verificados.",
            font="/F1",
            size=10,
            rgb=(0.04, 0.45, 0.25),
        )
        y -= 16
    else:
        for idx_err, (err_path, err_desc) in enumerate(errors, 1):
            path_lines = textwrap.wrap(f"{idx_err}. Archivo: {err_path}", width=88) or [f"{idx_err}. Archivo: {err_path}"]
            desc_lines = textwrap.wrap(f"   Motivo: {err_desc}", width=88) or [f"   Motivo: {err_desc}"]
            _ensure_space((len(path_lines) + len(desc_lines)) * 13 + 8)
            for pl in path_lines:
                _draw_text(margin + 6, y, pl, font="/F2", size=9, rgb=(0.15, 0.15, 0.22))
                y -= 13
            for dl in desc_lines:
                _draw_text(margin + 6, y, dl, font="/F1", size=9, rgb=(0.68, 0.12, 0.20))
                y -= 13
            y -= 5

    if cur_ops:
        pages_ops.append(cur_ops)

    # Numeración de páginas en pie de página
    total_pages = len(pages_ops)
    for page_idx, ops in enumerate(pages_ops, 1):
        footer_txt = _pdf_safe_text(f"StepMigratorDrive - Pagina {page_idx} de {total_pages}")
        ops.append(
            f"BT /F1 8 Tf 0.45 0.45 0.55 rg 1 0 0 1 {margin:.1f} 28.0 Tm ({footer_txt}) Tj ET"
        )

    # ── Ensamblado del documento PDF 1.4 ──────────────────────────────────
    objects: List[bytes] = []
    # 1: Catalog, 2: Pages, 3: Font F1 (Helvetica), 4: Font F2 (Helvetica-Bold)
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    page_obj_nums = [5 + i * 2 for i in range(total_pages)]
    kids_str = " ".join(f"{n} 0 R" for n in page_obj_nums)
    objects.append(f"<< /Type /Pages /Kids [ {kids_str} ] /Count {total_pages} >>".encode("ascii"))
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")

    for i, ops in enumerate(pages_ops):
        page_num = 5 + i * 2
        content_num = page_num + 1
        stream_bytes = "\n".join(ops).encode("latin-1", errors="replace")
        page_dict = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page_w} {page_h}] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
            f"/Contents {content_num} 0 R >>"
        ).encode("ascii")
        content_obj = (
            f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
            + stream_bytes
            + b"\nendstream"
        )
        objects.append(page_dict)
        objects.append(content_obj)

    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    buf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: List[int] = [0]
    for obj_id, body in enumerate(objects, 1):
        offsets.append(len(buf))
        buf.extend(f"{obj_id} 0 obj\n".encode("ascii"))
        buf.extend(body)
        buf.extend(b"\nendobj\n")

    xref_pos = len(buf)
    buf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    buf.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        buf.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    buf.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n"
        ).encode("ascii")
    )

    with open(output_path, "wb") as fh:
        fh.write(buf)
    return output_path


# ──────────────────────────────────────────────────────────────────────────────
#  Utilidades internas
# ──────────────────────────────────────────────────────────────────────────────

def _fmt_size(size_bytes: int) -> str:
    """Convierte bytes a una cadena legible (B / KB / MB / GB)."""
    if size_bytes < 1_024:
        return f"{size_bytes} B"
    if size_bytes < 1_024 ** 2:
        return f"{size_bytes / 1_024:.1f} KB"
    if size_bytes < 1_024 ** 3:
        return f"{size_bytes / 1_024 ** 2:.1f} MB"
    return f"{size_bytes / 1_024 ** 3:.2f} GB"


def _fmt_eta(remaining_bytes: int, speed_bps: float) -> str:
    """Convierte bytes restantes y velocidad en tiempo estimado restante legible."""
    if remaining_bytes <= 0:
        return "0s"
    if speed_bps <= 0:
        return "Calculando…"
    secs = int(remaining_bytes / speed_bps)
    if secs < 60:
        return f"{secs}s"
    mins, sec = divmod(secs, 60)
    if mins < 60:
        return f"{mins}m {sec:02d}s"
    hours, mins = divmod(mins, 60)
    return f"{hours}h {mins:02d}m"
