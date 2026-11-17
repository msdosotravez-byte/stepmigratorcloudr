"""
app_gui.py — Interfaz gráfica de StepMigratorDrive
Migración bidireccional segura y de alta velocidad entre almacenamiento local
y Google Drive.
"""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox
from typing import Any, Callable, Dict, List, Optional, Tuple

import customtkinter as ctk
from send2trash import send2trash

# ── Backend de migración ───────────────────────────────────────────────────
from migrador import (
    DEFAULT_MAX_WORKERS,
    ENC_TOKEN_FILE,
    TOKEN_FILE,
    StepDownloader,
    StepMigrator,
    TokenDecryptionError,
    _fmt_eta,
    _fmt_size,
    authenticate,
    export_transfer_report_pdf,
    get_account_info,
    has_saved_token,
    is_volume_mount_point,
    list_drive_folders,
    revoke_and_logout,
    secure_wipe_file,
)

# ──────────────────────────────────────────────
#  Configuración global de CustomTkinter
# ──────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


def _center_toplevel(parent: ctk.CTk, dialog: ctk.CTkToplevel, width: int, height: int) -> None:
    """Centra una ventana modal sobre la ventana principal."""
    parent.update_idletasks()
    x = parent.winfo_x() + max(0, (parent.winfo_width() - width) // 2)
    y = parent.winfo_y() + max(0, (parent.winfo_height() - height) // 2)
    dialog.geometry(f"{width}x{height}+{x}+{y}")


def _apply_mist_alpha(window: ctk.CTkBaseClass, alpha: float) -> None:
    """Aplica transparencia sutil para lograr el efecto cristalino vaporoso."""
    try:
        window.attributes("-alpha", alpha)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  Diálogo de Seguridad de Cuenta (PIN / Bóveda Cifrada / Sesión Efímera)
# ══════════════════════════════════════════════════════════════════════════════

class SecurityAuthDialog(ctk.CTkToplevel):
    """Solicita la contraseña maestra de protección de cuenta o activa modo efímero."""

    def __init__(self, master: "StepMigratorApp", error_hint: str = "") -> None:
        super().__init__(master)
        self.result: Optional[Tuple[Optional[str], bool]] = None  # (passphrase, persist_token)

        self.title("Protección de Cuenta Google Drive")
        self.resizable(False, False)
        self.configure(fg_color=master._BG_PANEL)
        _apply_mist_alpha(self, 0.98)
        _center_toplevel(master, self, 500, 370)
        self.grab_set()
        self.focus_force()

        has_tok, is_enc = has_saved_token()
        if error_hint:
            subtitle = error_hint
            subtitle_color = master._DANGER
        elif is_enc:
            subtitle = (
                f"Se detectó una bóveda cifrada ({ENC_TOKEN_FILE}).\n"
                "Introduce tu contraseña maestra para desbloquear tu sesión."
            )
            subtitle_color = master._TEXT_SEC
        elif has_tok:
            subtitle = (
                f"Se detectó una sesión previa sin cifrar ({TOKEN_FILE}).\n"
                "Define una contraseña maestra para cifrarla y proteger tu cuenta."
            )
            subtitle_color = master._WARNING
        else:
            subtitle = (
                "Protege tu token de Google Drive con cifrado local (PBKDF2 + Fernet).\n"
                "Se recomienda definir una contraseña maestra o usar sesión efímera."
            )
            subtitle_color = master._TEXT_SEC

        card = ctk.CTkFrame(
            self,
            fg_color=master._BG_CARD,
            corner_radius=16,
            border_width=1,
            border_color=master._BORDER_GLOW,
        )
        card.pack(fill="both", expand=True, padx=16, pady=16)

        ctk.CTkLabel(
            card,
            text="🛡️  Seguridad de Cuenta Drive",
            font=ctk.CTkFont(size=17, weight="bold"),
            text_color=master._TEXT_PRI,
        ).pack(pady=(20, 6))

        ctk.CTkLabel(
            card,
            text=subtitle,
            font=ctk.CTkFont(size=12),
            text_color=subtitle_color,
            justify="center",
        ).pack(padx=24, pady=(0, 14))

        # Entrada de contraseña maestra
        pw_frame = ctk.CTkFrame(card, fg_color="transparent")
        pw_frame.pack(fill="x", padx=24, pady=(0, 8))
        pw_frame.grid_columnconfigure(0, weight=1)

        self._pw_entry = ctk.CTkEntry(
            pw_frame,
            placeholder_text="Contraseña maestra / PIN de bóveda…",
            show="•",
            height=40,
            corner_radius=10,
            fg_color=master._BG_DEEP,
            border_color=master._BORDER,
            text_color=master._TEXT_PRI,
        )
        self._pw_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self._pw_entry.bind("<Return>", lambda _e: self._on_accept())

        self._show_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            pw_frame,
            text="Ver",
            width=55,
            variable=self._show_var,
            command=self._toggle_show,
            fg_color=master._ACCENT,
            hover_color=master._ACCENT_HOV,
            border_color=master._BORDER_GLOW,
            text_color=master._TEXT_SEC,
        ).grid(row=0, column=1)

        # Opción sesión efímera
        self._ephemeral_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            card,
            text="Sesión efímera (solo en RAM; no guardar ningún token en disco)",
            variable=self._ephemeral_var,
            command=self._toggle_ephemeral,
            font=ctk.CTkFont(size=12),
            fg_color=master._ACCENT,
            hover_color=master._ACCENT_HOV,
            border_color=master._BORDER_GLOW,
            text_color=master._TEXT_PRI,
        ).pack(anchor="w", padx=24, pady=(6, 12))

        # Botones de acción
        btns = ctk.CTkFrame(card, fg_color="transparent")
        btns.pack(fill="x", padx=24, pady=(8, 10))

        ctk.CTkButton(
            btns,
            text="Desbloquear / Conectar",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=40,
            corner_radius=12,
            fg_color=master._ACCENT,
            hover_color=master._ACCENT_HOV,
            text_color=master._TEXT_PRI,
            command=self._on_accept,
        ).pack(side="left", expand=True, fill="x", padx=(0, 8))

        ctk.CTkButton(
            btns,
            text="Cancelar",
            height=40,
            width=104,
            corner_radius=12,
            fg_color=master._BG_MIST,
            hover_color=master._BG_DEEP,
            border_width=1,
            border_color=master._BORDER,
            text_color=master._TEXT_PRI,
            command=self.destroy,
        ).pack(side="right")

        if is_enc:
            ctk.CTkButton(
                card,
                text="Olvidé mi PIN — borrar bóveda y reautenticar",
                font=ctk.CTkFont(size=11),
                height=26,
                corner_radius=10,
                fg_color="transparent",
                hover_color=master._BG_MIST,
                text_color=master._WARNING,
                command=self._on_reset_vault,
            ).pack(pady=(0, 10))

        self.after(50, self._pw_entry.focus_set)

    def _toggle_show(self) -> None:
        self._pw_entry.configure(show="" if self._show_var.get() else "•")

    def _toggle_ephemeral(self) -> None:
        if self._ephemeral_var.get():
            self._pw_entry.configure(state="disabled")
        else:
            self._pw_entry.configure(state="normal")

    def _on_reset_vault(self) -> None:
        if messagebox.askyesno(
            "Restablecer bóveda cifrada",
            "Se eliminará de forma segura el token cifrado local (token.enc) "
            "para iniciar una nueva sesión OAuth2 en el navegador.\n¿Continuar?",
            parent=self,
        ):
            secure_wipe_file(ENC_TOKEN_FILE)
            secure_wipe_file(TOKEN_FILE)
            self.result = (None, True)
            self.destroy()

    def _on_accept(self) -> None:
        ephemeral = self._ephemeral_var.get()
        if ephemeral:
            self.result = (None, False)
            self.destroy()
            return

        pw = self._pw_entry.get().strip()
        _, is_enc = has_saved_token()
        if is_enc and not pw:
            messagebox.showwarning(
                "Contraseña requerida",
                "Introduce la contraseña maestra para descifrar token.enc.",
                parent=self,
            )
            return

        if not pw:
            confirm = messagebox.askyesno(
                "Sin contraseña maestra",
                "Si continúas sin contraseña maestra, el token se guardará con permisos "
                "restringidos (0600) pero sin cifrado por PIN.\n"
                "¿Deseas continuar sin PIN?",
                icon="warning",
                parent=self,
            )
            if not confirm:
                return

        self.result = (pw or None, True)
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
#  Diálogo de Cierre de Sesión / Revocación de Cuenta
# ══════════════════════════════════════════════════════════════════════════════

class LogoutSecurityDialog(ctk.CTkToplevel):
    """Permite desconectar la sesión actual o revocar completamente el token OAuth2."""

    def __init__(self, master: "StepMigratorApp", email: str) -> None:
        super().__init__(master)
        self.choice: Optional[str] = None  # "disconnect" | "revoke"

        self.title("Protección de Cuenta")
        self.resizable(False, False)
        self.configure(fg_color=master._BG_PANEL)
        _apply_mist_alpha(self, 0.98)
        _center_toplevel(master, self, 480, 270)
        self.grab_set()
        self.focus_force()

        card = ctk.CTkFrame(
            self,
            fg_color=master._BG_CARD,
            corner_radius=16,
            border_width=1,
            border_color=master._BORDER_GLOW,
        )
        card.pack(fill="both", expand=True, padx=16, pady=16)

        ctk.CTkLabel(
            card,
            text="🔒  Gestión de Sesión de Drive",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=master._TEXT_PRI,
        ).pack(pady=(20, 6))

        ctk.CTkLabel(
            card,
            text=f"Cuenta activa: {email}\nElige cómo quieres cerrar la sesión:",
            font=ctk.CTkFont(size=12),
            text_color=master._TEXT_SEC,
            justify="center",
        ).pack(pady=(0, 14))

        ctk.CTkButton(
            card,
            text="Desconectar ahora (conservar bóveda cifrada)",
            height=38,
            corner_radius=12,
            fg_color=master._BG_MIST,
            hover_color=master._BG_DEEP,
            border_width=1,
            border_color=master._BORDER_GLOW,
            text_color=master._TEXT_PRI,
            command=lambda: self._select("disconnect"),
        ).pack(fill="x", padx=24, pady=(0, 8))

        ctk.CTkButton(
            card,
            text="Revocar acceso en Google y destruir tokens locales",
            height=38,
            corner_radius=12,
            fg_color=master._DANGER,
            hover_color="#E11D48",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=master._TEXT_PRI,
            command=lambda: self._select("revoke"),
        ).pack(fill="x", padx=24, pady=(0, 8))

        ctk.CTkButton(
            card,
            text="Cancelar",
            height=30,
            corner_radius=10,
            fg_color="transparent",
            hover_color=master._BG_MIST,
            text_color=master._TEXT_SEC,
            command=self.destroy,
        ).pack(pady=(2, 10))

    def _select(self, choice: str) -> None:
        self.choice = choice
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
#  Diálogo Selector de Carpetas en Google Drive
# ══════════════════════════════════════════════════════════════════════════════

class DriveFolderPickerDialog(ctk.CTkToplevel):
    """Navegador visual de carpetas en Google Drive para elegir origen o destino."""

    def __init__(
        self,
        master: "StepMigratorApp",
        drive_service: Any,
        initial_stack: Optional[List[Tuple[Optional[str], str]]] = None,
    ) -> None:
        super().__init__(master)
        self._master_app = master
        self._service = drive_service
        self._stack: List[Tuple[Optional[str], str]] = (
            list(initial_stack) if initial_stack else [(None, "Mi Unidad (Raíz)")]
        )
        self.selected: Optional[Tuple[Optional[str], str]] = None

        self.title("Seleccionar carpeta en Google Drive")
        self.resizable(True, True)
        self.minsize(480, 400)
        self.configure(fg_color=master._BG_PANEL)
        _apply_mist_alpha(self, 0.98)
        _center_toplevel(master, self, 560, 450)
        self.grab_set()
        self.focus_force()

        # Barra superior de ruta
        top = ctk.CTkFrame(
            self,
            fg_color=master._BG_CARD,
            corner_radius=14,
            border_width=1,
            border_color=master._BORDER,
        )
        top.pack(fill="x", padx=16, pady=(16, 8))
        top.grid_columnconfigure(1, weight=1)

        self._btn_up = ctk.CTkButton(
            top,
            text="⬅ Subir",
            width=82,
            height=30,
            corner_radius=10,
            fg_color=master._BG_MIST,
            hover_color=master._BG_DEEP,
            border_width=1,
            border_color=master._BORDER_GLOW,
            text_color=master._TEXT_PRI,
            command=self._go_up,
        )
        self._btn_up.grid(row=0, column=0, padx=(10, 8), pady=8)

        self._crumb_label = ctk.CTkLabel(
            top,
            text="",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=master._TEXT_PRI,
            anchor="w",
        )
        self._crumb_label.grid(row=0, column=1, padx=(4, 10), pady=8, sticky="ew")

        # Lista desplazable de carpetas
        self._list_frame = ctk.CTkScrollableFrame(
            self,
            fg_color=master._BG_DEEP,
            border_width=1,
            border_color=master._BORDER,
            corner_radius=14,
            scrollbar_button_color=master._BG_MIST,
            scrollbar_button_hover_color=master._ACCENT,
        )
        self._list_frame.pack(fill="both", expand=True, padx=16, pady=4)

        # Pie del diálogo
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(fill="x", padx=16, pady=(8, 16))

        ctk.CTkButton(
            bottom,
            text="✔ Seleccionar carpeta actual",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=38,
            corner_radius=12,
            fg_color=master._ACCENT,
            hover_color=master._ACCENT_HOV,
            text_color=master._TEXT_PRI,
            command=self._choose_current,
        ).pack(side="left", expand=True, fill="x", padx=(0, 8))

        ctk.CTkButton(
            bottom,
            text="Cancelar",
            width=104,
            height=38,
            corner_radius=12,
            fg_color=master._BG_MIST,
            hover_color=master._BG_CARD,
            border_width=1,
            border_color=master._BORDER,
            text_color=master._TEXT_PRI,
            command=self.destroy,
        ).pack(side="right")

        self._load_current_folder()

    def _current_id(self) -> str:
        return self._stack[-1][0] or "root"

    def _update_breadcrumbs(self) -> None:
        path_str = " / ".join(name for _, name in self._stack)
        self._crumb_label.configure(text=path_str)
        self._btn_up.configure(state="normal" if len(self._stack) > 1 else "disabled")

    def _clear_list(self, message: str = "") -> None:
        for widget in self._list_frame.winfo_children():
            widget.destroy()
        if message:
            ctk.CTkLabel(
                self._list_frame,
                text=message,
                font=ctk.CTkFont(size=12),
                text_color=self._master_app._TEXT_SEC,
            ).pack(pady=24)

    def _load_current_folder(self) -> None:
        self._update_breadcrumbs()
        self._clear_list("Cargando carpetas desde Google Drive…")
        target_id = self._current_id()

        def _worker() -> None:
            try:
                folders = list_drive_folders(self._service, target_id)
                self.after(0, lambda: self._render_folders(target_id, folders))
            except Exception as exc:
                self.after(0, lambda: self._clear_list(f"Error cargando carpetas: {exc}"))

        threading.Thread(target=_worker, daemon=True).start()

    def _render_folders(self, loaded_id: str, folders: List[Dict[str, str]]) -> None:
        if not self.winfo_exists() or loaded_id != self._current_id():
            return
        if not folders:
            self._clear_list("No hay subcarpetas en esta ubicación.")
            return

        self._clear_list()
        for folder in folders:
            row = ctk.CTkFrame(
                self._list_frame,
                fg_color=self._master_app._BG_CARD,
                corner_radius=10,
                border_width=1,
                border_color=self._master_app._BORDER,
            )
            row.pack(fill="x", padx=6, pady=4)
            row.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(
                row,
                text=f"📁  {folder['name']}",
                font=ctk.CTkFont(size=13),
                text_color=self._master_app._TEXT_PRI,
                anchor="w",
            ).grid(row=0, column=0, padx=10, pady=7, sticky="ew")

            ctk.CTkButton(
                row,
                text="Abrir",
                width=64,
                height=28,
                corner_radius=8,
                fg_color=self._master_app._BG_MIST,
                hover_color=self._master_app._BG_DEEP,
                border_width=1,
                border_color=self._master_app._BORDER,
                text_color=self._master_app._TEXT_PRI,
                command=lambda fid=folder["id"], fname=folder["name"]: self._enter_folder(fid, fname),
            ).grid(row=0, column=1, padx=(4, 6), pady=6)

            ctk.CTkButton(
                row,
                text="Elegir",
                width=64,
                height=28,
                corner_radius=8,
                fg_color=self._master_app._ACCENT,
                hover_color=self._master_app._ACCENT_HOV,
                text_color=self._master_app._TEXT_PRI,
                command=lambda fid=folder["id"], fname=folder["name"]: self._select_specific(fid, fname),
            ).grid(row=0, column=2, padx=(0, 8), pady=6)

    def _enter_folder(self, folder_id: str, folder_name: str) -> None:
        self._stack.append((folder_id, folder_name))
        self._load_current_folder()

    def _go_up(self) -> None:
        if len(self._stack) > 1:
            self._stack.pop()
            self._load_current_folder()

    def _select_specific(self, folder_id: str, folder_name: str) -> None:
        full_label = " / ".join([name for _, name in self._stack] + [folder_name])
        self.selected = (folder_id, full_label)
        self.destroy()

    def _choose_current(self) -> None:
        folder_id = self._stack[-1][0]
        full_label = " / ".join(name for _, name in self._stack)
        self.selected = (folder_id, full_label)
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
#  Diálogo de Informe Final de Transferencia + Exportación a PDF
# ══════════════════════════════════════════════════════════════════════════════

class TransferReportDialog(ctk.CTkToplevel):
    """Muestra el resumen final, el listado completo de fallos y permite exportar a PDF."""

    def __init__(self, master: "StepMigratorApp", report: Dict[str, Any]) -> None:
        super().__init__(master)
        self._master_app = master
        self._report = report

        errors: List[Tuple[str, str]] = list(report.get("errors") or [])
        failed_count = len(errors)
        is_upload = report.get("direction") == "upload"
        is_safe = bool(report.get("safe_to_format"))
        is_mount = is_volume_mount_point(str(report.get("source_path") or ""))

        self.title("Informe Final de Transferencia")
        self.resizable(True, True)
        self.minsize(580, 440)
        self.configure(fg_color=master._BG_PANEL)
        _apply_mist_alpha(self, 0.98)
        _center_toplevel(master, self, 660, 520)
        self.grab_set()
        self.focus_force()

        card = ctk.CTkFrame(
            self,
            fg_color=master._BG_CARD,
            corner_radius=16,
            border_width=1,
            border_color=master._BORDER_GLOW,
        )
        card.pack(fill="both", expand=True, padx=14, pady=14)
        card.grid_rowconfigure(3, weight=1)
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card,
            text="📊  Informe Final de Transferencia",
            font=ctk.CTkFont(size=17, weight="bold"),
            text_color=master._TEXT_PRI,
        ).grid(row=0, column=0, padx=18, pady=(16, 6), sticky="w")

        # Banner de estado
        if failed_count == 0:
            if is_upload and is_safe:
                banner_txt = "🟢  100 % VERIFICADO (MD5) — APTO PARA FORMATEAR EL DISCO"
            else:
                banner_txt = "🟢  TRANSFERENCIA COMPLETADA SIN ERRORES"
            banner_color = master._SUCCESS
        else:
            if is_upload:
                banner_txt = f"🔴  {failed_count} FALLO(S) DETECTADO(S) — NO FORMATEAR EL DISCO"
            else:
                banner_txt = f"🔴  DESCARGA FINALIZADA CON {failed_count} FALLO(S)"
            banner_color = master._DANGER

        ctk.CTkLabel(
            card,
            text=banner_txt,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=banner_color,
            fg_color=master._BG_MIST,
            corner_radius=10,
            padx=12,
            pady=6,
        ).grid(row=1, column=0, padx=18, pady=(0, 10), sticky="ew")

        # Resumen numérico
        summary_lines = [
            f"Dirección: {report.get('direction_label', '')}   ·   Duración: {float(report.get('duration_seconds', 0.0)):.1f} s",
            (
                f"Archivos: {report.get('total_files', 0)}   ·   "
                f"Transferidos: {report.get('transferred_ok', 0)}   ·   "
                f"Omitidos (MD5): {report.get('skipped_identical', 0)}   ·   "
                f"Fallos: {failed_count}"
            ),
            f"Datos verificados: {_fmt_size(int(report.get('bytes_verified', 0)))}",
        ]
        if is_upload and report.get("junk_skipped", 0):
            summary_lines.append(
                f"Basura exFAT filtrada: {report['junk_skipped']} (._*, .Spotlight, etc.)"
            )
        if is_upload and is_safe and report.get("manifest_path"):
            summary_lines.append(f"Manifiesto: {report['manifest_path']}")

        ctk.CTkLabel(
            card,
            text="\n".join(summary_lines),
            font=ctk.CTkFont(size=12),
            text_color=master._TEXT_SEC,
            justify="left",
            anchor="w",
        ).grid(row=2, column=0, padx=18, pady=(0, 10), sticky="ew")

        # Caja con el detalle de fallos
        box = ctk.CTkTextbox(
            card,
            font=ctk.CTkFont(family="Menlo", size=12),
            fg_color=master._BG_DEEP,
            text_color=master._TEXT_PRI,
            corner_radius=12,
            border_width=1,
            border_color=master._BORDER,
            wrap="word",
            scrollbar_button_color=master._BG_MIST,
            scrollbar_button_hover_color=master._ACCENT,
        )
        box.grid(row=3, column=0, padx=18, pady=(0, 12), sticky="nsew")

        if not errors:
            box.insert(
                "end",
                "✔ No se registraron fallos durante toda la transferencia.\n"
                "Todos los archivos procesados pasaron la verificación de integridad.",
            )
        else:
            box.insert("end", f"Listado de {failed_count} incidencia(s) aisladas:\n\n")
            for idx, (path, err) in enumerate(errors, 1):
                box.insert("end", f"{idx}. {path}\n   ✖ {err}\n\n")
        box.configure(state="disabled")

        # Botonera inferior
        btns = ctk.CTkFrame(card, fg_color="transparent")
        btns.grid(row=4, column=0, padx=18, pady=(0, 14), sticky="ew")

        ctk.CTkButton(
            btns,
            text="📄  Exportar a PDF…",
            font=ctk.CTkFont(size=13, weight="bold"),
            width=180,
            height=38,
            fg_color=master._ACCENT,
            hover_color=master._ACCENT_HOV,
            text_color=master._TEXT_PRI,
            corner_radius=12,
            command=self._on_export_pdf,
        ).pack(side="left")

        if is_upload and failed_count == 0 and not is_mount and report.get("source_path"):
            ctk.CTkButton(
                btns,
                text="🗑️ Enviar origen a papelera",
                font=ctk.CTkFont(size=12, weight="bold"),
                width=200,
                height=38,
                fg_color=master._DANGER,
                hover_color="#E11D48",
                text_color=master._TEXT_PRI,
                corner_radius=12,
                command=self._on_trash,
            ).pack(side="left", padx=(10, 0))

        ctk.CTkButton(
            btns,
            text="Cerrar",
            font=ctk.CTkFont(size=13),
            width=110,
            height=38,
            fg_color=master._BG_MIST,
            hover_color=master._BG_DEEP,
            border_width=1,
            border_color=master._BORDER,
            text_color=master._TEXT_PRI,
            corner_radius=12,
            command=self.destroy,
        ).pack(side="right")

    def _on_export_pdf(self) -> None:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"informe_stepmigrator_{stamp}.pdf"
        out_path = filedialog.asksaveasfilename(
            parent=self,
            title="Guardar informe de transferencia como PDF",
            defaultextension=".pdf",
            initialfile=default_name,
            filetypes=[("Documento PDF", "*.pdf")],
        )
        if not out_path:
            return
        try:
            saved = export_transfer_report_pdf(self._report, out_path)
            self._master_app._log(f"📄 Informe PDF exportado en: {saved}", level="OK")
            messagebox.showinfo(
                "Informe exportado",
                f"El informe PDF se guardó correctamente en:\n{saved}",
                parent=self,
            )
        except Exception as exc:
            self._master_app._log(f"Error al exportar PDF: {exc}", level="ERROR")
            messagebox.showerror(
                "Error exportando PDF",
                f"No se pudo guardar el informe PDF:\n{exc}",
                parent=self,
            )

    def _on_trash(self) -> None:
        self.destroy()
        self._master_app._send_source_to_trash()


# ══════════════════════════════════════════════════════════════════════════════
#  Clase principal de la aplicación
# ══════════════════════════════════════════════════════════════════════════════

class StepMigratorApp(ctk.CTk):
    """Ventana principal de StepMigratorDrive con estética oscura vaporosa."""

    _BG_DEEP     = "#080711"
    _BG_PANEL    = "#100E1E"
    _BG_CARD     = "#17142B"
    _BG_MIST     = "#211C3D"
    _ACCENT      = "#8B5CF6"
    _ACCENT_HOV  = "#A78BFA"
    _ACCENT_GLOW = "#38BDF8"
    _SUCCESS     = "#34D399"
    _WARNING     = "#FBBF24"
    _DANGER      = "#FB7185"
    _TEXT_PRI    = "#F3F0FF"
    _TEXT_SEC    = "#9E96BF"
    _BORDER      = "#2B244D"
    _BORDER_GLOW = "#4C3D8F"

    _SPEED_PROFILES: Dict[str, int] = {
        "⚡ Turbo (8 hilos)": 8,
        "🚀 Rápido (6 hilos)": DEFAULT_MAX_WORKERS,
        "⚖ Equilibrado (4 hilos)": 4,
        "🐢 Secuencial (1 hilo)": 1,
    }

    _MODE_UPLOAD = "⬆ Local ➔ Drive"
    _MODE_DOWNLOAD = "⬇ Drive ➔ Disco Duro"

    def __init__(self) -> None:
        super().__init__()

        # ── Estado interno ────────────────────────────────────────────────
        self._source_path: str = ""
        self._drive_folder_id: Optional[str] = None
        self._drive_folder_label: str = "Mi Unidad (Raíz)"
        self._drive_connected: bool = False
        self._migration_running: bool = False
        self._closing: bool = False
        self._drive_service: Any = None
        self._account_email: str = ""
        self._account_free_bytes: Optional[int] = None
        self._direction: str = "upload"  # "upload" | "download"
        self._last_report: Optional[Dict[str, Any]] = None
        self._ui_queue: queue.Queue[Tuple[str, Any]] = queue.Queue()

        # ── Configuración de la ventana ───────────────────────────────────
        self.title("StepMigratorDrive")
        self.geometry("960x720")
        self.minsize(800, 620)
        self.configure(fg_color=self._BG_DEEP)
        self.resizable(True, True)
        _apply_mist_alpha(self, 0.97)

        try:
            self.iconbitmap("assets/icon.ico")
        except Exception:
            pass

        self._build_ui()
        self._update_security_badge()

        # Drenado seguro de eventos de hilos secundarios hacia Tk
        self.after(40, self._drain_ui_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ──────────────────────────────────────────────────────────────────────
    #  Construcción de la interfaz
    # ──────────────────────────────────────────────────────────────────────
    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)  # fila del log expandible

        self._build_header()        # fila 0
        self._build_separator()     # fila 1
        self._build_controls_bar()  # fila 2
        self._build_paths_card()    # fila 3
        self._build_log_panel()     # fila 4
        self._build_footer()        # fila 5

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color=self._BG_PANEL, corner_radius=0, border_width=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        title_wrap = ctk.CTkFrame(header, fg_color="transparent")
        title_wrap.grid(row=0, column=0, padx=(24, 12), pady=14, sticky="w")

        ctk.CTkLabel(
            title_wrap,
            text="✦  StepMigratorDrive",
            font=ctk.CTkFont(family="Helvetica Neue", size=20, weight="bold"),
            text_color=self._TEXT_PRI,
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_wrap,
            text="Nube ⇄ Disco Duro · Bóveda cifrada & alta velocidad",
            font=ctk.CTkFont(size=11),
            text_color=self._TEXT_SEC,
        ).pack(anchor="w")

        # Insignia de seguridad de cuenta tipo cápsula
        self._sec_badge = ctk.CTkLabel(
            header,
            text="🔒 Protección",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=self._TEXT_SEC,
            fg_color=self._BG_MIST,
            corner_radius=12,
            padx=12,
            pady=4,
        )
        self._sec_badge.grid(row=0, column=1, padx=8, pady=14, sticky="w")

        self._conn_dot = ctk.CTkLabel(
            header,
            text="●",
            font=ctk.CTkFont(size=14),
            text_color=self._DANGER,
        )
        self._conn_dot.grid(row=0, column=2, padx=(8, 6), pady=14, sticky="e")

        self._conn_label = ctk.CTkLabel(
            header,
            text="Sin conexión a Drive",
            font=ctk.CTkFont(size=12),
            text_color=self._TEXT_SEC,
        )
        self._conn_label.grid(row=0, column=3, padx=(0, 14), pady=14, sticky="e")

        self._btn_connect = ctk.CTkButton(
            header,
            text="Conectar Drive",
            font=ctk.CTkFont(size=12, weight="bold"),
            width=132,
            height=36,
            fg_color=self._ACCENT,
            hover_color=self._ACCENT_HOV,
            text_color=self._TEXT_PRI,
            corner_radius=12,
            command=self._on_connect_drive,
        )
        self._btn_connect.grid(row=0, column=4, padx=(0, 8), pady=14, sticky="e")

        self._btn_logout = ctk.CTkButton(
            header,
            text="🔒 Cerrar / Revocar",
            font=ctk.CTkFont(size=12),
            width=142,
            height=36,
            fg_color=self._BG_MIST,
            hover_color=self._BG_CARD,
            border_width=1,
            border_color=self._BORDER,
            text_color=self._TEXT_SEC,
            corner_radius=12,
            state="disabled",
            command=self._on_logout_clicked,
        )
        self._btn_logout.grid(row=0, column=5, padx=(0, 22), pady=14, sticky="e")

    def _build_separator(self) -> None:
        separator = tk.Frame(self, bg=self._BORDER_GLOW, height=1)
        separator.grid(row=1, column=0, sticky="ew")

    def _build_controls_bar(self) -> None:
        bar = ctk.CTkFrame(
            self,
            fg_color=self._BG_CARD,
            corner_radius=16,
            border_width=1,
            border_color=self._BORDER,
        )
        bar.grid(row=2, column=0, sticky="ew", padx=22, pady=(16, 7))
        bar.grid_columnconfigure(1, weight=1)

        self._mode_seg = ctk.CTkSegmentedButton(
            bar,
            values=[self._MODE_UPLOAD, self._MODE_DOWNLOAD],
            font=ctk.CTkFont(size=12, weight="bold"),
            height=36,
            corner_radius=12,
            fg_color=self._BG_DEEP,
            selected_color=self._ACCENT,
            selected_hover_color=self._ACCENT_HOV,
            unselected_color=self._BG_PANEL,
            unselected_hover_color=self._BG_MIST,
            text_color=self._TEXT_PRI,
            command=self._on_mode_changed,
        )
        self._mode_seg.set(self._MODE_UPLOAD)
        self._mode_seg.grid(row=0, column=0, padx=(14, 12), pady=(11, 6), sticky="w")

        ctk.CTkLabel(
            bar,
            text="Velocidad:",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=self._TEXT_SEC,
        ).grid(row=0, column=2, padx=(8, 6), pady=(11, 6), sticky="e")

        self._speed_menu = ctk.CTkOptionMenu(
            bar,
            values=list(self._SPEED_PROFILES.keys()),
            width=188,
            height=34,
            corner_radius=12,
            fg_color=self._BG_MIST,
            button_color=self._ACCENT,
            button_hover_color=self._ACCENT_HOV,
            dropdown_fg_color=self._BG_PANEL,
            dropdown_hover_color=self._BG_MIST,
            dropdown_text_color=self._TEXT_PRI,
            text_color=self._TEXT_PRI,
            font=ctk.CTkFont(size=12),
        )
        self._speed_menu.set("🚀 Rápido (6 hilos)")
        self._speed_menu.grid(row=0, column=3, padx=(0, 14), pady=(11, 6), sticky="e")

        # Fila de opciones de seguridad e higiene exFAT
        opts = ctk.CTkFrame(bar, fg_color="transparent")
        opts.grid(row=1, column=0, columnspan=4, sticky="ew", padx=14, pady=(2, 10))

        self._verify_var = ctk.BooleanVar(value=True)
        self._verify_chk = ctk.CTkCheckBox(
            opts,
            text="Verificar MD5 y omitir existentes",
            variable=self._verify_var,
            font=ctk.CTkFont(size=12),
            fg_color=self._ACCENT,
            hover_color=self._ACCENT_HOV,
            border_color=self._BORDER_GLOW,
            text_color=self._TEXT_PRI,
        )
        self._verify_chk.pack(side="left", padx=(0, 18))

        self._filter_exfat_var = ctk.BooleanVar(value=True)
        self._exfat_chk = ctk.CTkCheckBox(
            opts,
            text="Limpiar basura exFAT (._*, .Spotlight, etc.)",
            variable=self._filter_exfat_var,
            font=ctk.CTkFont(size=12),
            fg_color=self._ACCENT,
            hover_color=self._ACCENT_HOV,
            border_color=self._BORDER_GLOW,
            text_color=self._TEXT_PRI,
        )
        self._exfat_chk.pack(side="left")

    def _build_paths_card(self) -> None:
        card = ctk.CTkFrame(
            self,
            fg_color=self._BG_CARD,
            corner_radius=16,
            border_width=1,
            border_color=self._BORDER,
        )
        card.grid(row=3, column=0, sticky="ew", padx=22, pady=7)
        card.grid_columnconfigure(1, weight=1)

        # Fila 0: Carpeta Local
        self._local_title_label = ctk.CTkLabel(
            card,
            text="Carpeta local de origen",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=self._TEXT_PRI,
            width=185,
            anchor="w",
        )
        self._local_title_label.grid(row=0, column=0, padx=(18, 8), pady=(14, 7), sticky="w")

        self._path_entry = ctk.CTkEntry(
            card,
            placeholder_text="Selecciona una carpeta en tu disco duro…",
            font=ctk.CTkFont(size=13),
            fg_color=self._BG_DEEP,
            border_color=self._BORDER,
            text_color=self._TEXT_PRI,
            height=38,
            corner_radius=10,
            state="readonly",
        )
        self._path_entry.grid(row=0, column=1, padx=8, pady=(14, 7), sticky="ew")

        self._btn_browse_local = ctk.CTkButton(
            card,
            text="Examinar…",
            font=ctk.CTkFont(size=13),
            width=136,
            height=38,
            fg_color=self._BG_MIST,
            hover_color=self._BG_DEEP,
            border_width=1,
            border_color=self._BORDER_GLOW,
            text_color=self._TEXT_PRI,
            corner_radius=12,
            command=self._on_select_source,
        )
        self._btn_browse_local.grid(row=0, column=2, columnspan=2, padx=(8, 18), pady=(14, 7), sticky="ew")

        # Fila 1: Carpeta en Google Drive
        self._drive_title_label = ctk.CTkLabel(
            card,
            text="Carpeta destino en Drive",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=self._TEXT_PRI,
            width=185,
            anchor="w",
        )
        self._drive_title_label.grid(row=1, column=0, padx=(18, 8), pady=(7, 14), sticky="w")

        self._drive_path_entry = ctk.CTkEntry(
            card,
            font=ctk.CTkFont(size=13),
            fg_color=self._BG_DEEP,
            border_color=self._BORDER,
            text_color=self._TEXT_PRI,
            height=38,
            corner_radius=10,
            state="normal",
        )
        self._drive_path_entry.insert(0, self._drive_folder_label)
        self._drive_path_entry.configure(state="readonly")
        self._drive_path_entry.grid(row=1, column=1, padx=8, pady=(7, 14), sticky="ew")

        self._btn_pick_drive = ctk.CTkButton(
            card,
            text="Elegir en Drive…",
            font=ctk.CTkFont(size=12),
            width=136,
            height=38,
            fg_color=self._BG_MIST,
            hover_color=self._BG_DEEP,
            border_width=1,
            border_color=self._BORDER_GLOW,
            text_color=self._TEXT_PRI,
            corner_radius=12,
            state="disabled",
            command=self._on_pick_drive_folder,
        )
        self._btn_pick_drive.grid(row=1, column=2, padx=(8, 6), pady=(7, 14))

        self._btn_reset_drive = ctk.CTkButton(
            card,
            text="Raíz",
            font=ctk.CTkFont(size=12),
            width=64,
            height=38,
            fg_color="transparent",
            hover_color=self._BG_MIST,
            border_width=1,
            border_color=self._BORDER,
            text_color=self._TEXT_SEC,
            corner_radius=12,
            command=self._on_reset_drive_folder,
        )
        self._btn_reset_drive.grid(row=1, column=3, padx=(0, 18), pady=(7, 14))

    def _build_log_panel(self) -> None:
        frame = ctk.CTkFrame(
            self,
            fg_color=self._BG_CARD,
            corner_radius=16,
            border_width=1,
            border_color=self._BORDER,
        )
        frame.grid(row=4, column=0, sticky="nsew", padx=22, pady=(7, 14))
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        log_header = ctk.CTkFrame(frame, fg_color="transparent")
        log_header.grid(row=0, column=0, sticky="ew", padx=18, pady=(12, 0))
        log_header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            log_header,
            text="✦  Registro del sistema",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=self._TEXT_PRI,
        ).grid(row=0, column=0, sticky="w")

        self._btn_last_report = ctk.CTkButton(
            log_header,
            text="📊 Último informe / PDF",
            font=ctk.CTkFont(size=11, weight="bold"),
            width=165,
            height=28,
            fg_color=self._BG_MIST,
            hover_color=self._BG_DEEP,
            border_width=1,
            border_color=self._BORDER_GLOW,
            text_color=self._TEXT_PRI,
            corner_radius=10,
            state="disabled",
            command=self._on_open_last_report,
        )
        self._btn_last_report.grid(row=0, column=1, padx=(0, 8), sticky="e")

        ctk.CTkButton(
            log_header,
            text="Limpiar",
            font=ctk.CTkFont(size=11),
            width=74,
            height=28,
            fg_color=self._BG_MIST,
            hover_color=self._BG_DEEP,
            border_width=1,
            border_color=self._BORDER,
            text_color=self._TEXT_SEC,
            corner_radius=10,
            command=self._clear_log,
        ).grid(row=0, column=2, sticky="e")

        self._log_box = ctk.CTkTextbox(
            frame,
            font=ctk.CTkFont(family="Menlo", size=12),
            fg_color=self._BG_DEEP,
            text_color=self._TEXT_PRI,
            corner_radius=12,
            border_width=1,
            border_color=self._BORDER,
            wrap="word",
            state="disabled",
            scrollbar_button_color=self._BG_MIST,
            scrollbar_button_hover_color=self._ACCENT,
        )
        self._log_box.grid(row=1, column=0, sticky="nsew", padx=18, pady=(10, 16))

        self._log("StepMigratorDrive iniciado. Esperando conexión y selección de ruta…", level="INFO")

    def _build_footer(self) -> None:
        footer = ctk.CTkFrame(self, fg_color=self._BG_PANEL, corner_radius=0)
        footer.grid(row=5, column=0, sticky="ew")
        footer.grid_columnconfigure(0, weight=1)

        self._progress = ctk.CTkProgressBar(
            footer,
            mode="indeterminate",
            height=6,
            corner_radius=0,
            fg_color=self._BG_MIST,
            progress_color=self._ACCENT_GLOW,
        )
        self._progress.grid(row=0, column=0, columnspan=3, sticky="ew")
        self._progress.set(0)

        self._status_label = ctk.CTkLabel(
            footer,
            text="Listo",
            font=ctk.CTkFont(size=12),
            text_color=self._TEXT_SEC,
            anchor="w",
        )
        self._status_label.grid(row=1, column=0, padx=24, pady=14, sticky="ew")

        self._btn_migrate = ctk.CTkButton(
            footer,
            text="▶  Iniciar Subida",
            font=ctk.CTkFont(size=14, weight="bold"),
            width=220,
            height=44,
            fg_color=self._ACCENT,
            hover_color=self._ACCENT_HOV,
            text_color=self._TEXT_PRI,
            corner_radius=12,
            state="disabled",
            command=self._on_start_migration,
        )
        self._btn_migrate.grid(row=1, column=2, padx=24, pady=14, sticky="e")

    # ──────────────────────────────────────────────────────────────────────
    #  Cola thread-safe hacia la GUI
    # ──────────────────────────────────────────────────────────────────────
    def _enqueue(self, kind: str, payload: Any) -> None:
        self._ui_queue.put((kind, payload))

    def _drain_ui_queue(self) -> None:
        if self._closing:
            return
        try:
            for _ in range(120):
                kind, payload = self._ui_queue.get_nowait()
                if kind == "log":
                    msg, lvl = payload
                    self._log(msg, level=lvl)
                elif kind == "progress":
                    transferred, total, speed_bps = payload
                    self._on_progress_update(transferred, total, speed_bps)
                elif kind == "auth_ok":
                    service, info = payload
                    self._on_auth_success(service, info)
                elif kind == "auth_err":
                    self._on_auth_error(payload)
                elif kind == "auth_dec_err":
                    self._on_auth_decryption_error(payload)
                elif kind == "logout_done":
                    self._on_logout_complete(payload)
                elif kind == "migration_done":
                    errors, direction, audit = payload
                    self._on_migration_complete(errors, direction, audit)
        except queue.Empty:
            pass
        if not self._closing:
            self.after(40, self._drain_ui_queue)

    # ──────────────────────────────────────────────────────────────────────
    #  Logging y estado visual
    # ──────────────────────────────────────────────────────────────────────
    def _log(self, message: str, level: str = "INFO") -> None:
        prefixes = {
            "INFO":    ("ℹ", self._TEXT_SEC),
            "OK":      ("✔", self._SUCCESS),
            "WARN":    ("⚠", self._WARNING),
            "ERROR":   ("✖", self._DANGER),
            "SECTION": ("━", self._ACCENT),
        }
        symbol, color = prefixes.get(level, ("·", self._TEXT_PRI))

        self._log_box.configure(state="normal")
        self._log_box.insert("end", f"  {symbol}  {message}\n")

        last_line_start = self._log_box.index("end-2l linestart")
        last_line_end   = self._log_box.index("end-1c")
        self._log_box._textbox.tag_add(f"lvl_{level}", last_line_start, last_line_end)
        self._log_box._textbox.tag_configure(f"lvl_{level}", foreground=color)

        self._log_box.see("end")
        self._log_box.configure(state="disabled")

    def _clear_log(self) -> None:
        self._log_box.configure(state="normal")
        self._log_box.delete("1.0", "end")
        self._log_box.configure(state="disabled")
        self._log("Log limpiado.", level="INFO")

    def _update_security_badge(self) -> None:
        if self._drive_connected and self._drive_service is not None:
            if getattr(self._drive_service, "_step_ephemeral", False):
                self._sec_badge.configure(text="⚡ Sesión efímera (RAM)", text_color=self._ACCENT)
                return
            if getattr(self._drive_service, "_step_encrypted", False):
                self._sec_badge.configure(text="🔒 Bóveda cifrada (0600)", text_color=self._SUCCESS)
                return
            self._sec_badge.configure(text="⚠ Sesión sin PIN", text_color=self._WARNING)
            return

        has_tok, is_enc = has_saved_token()
        if is_enc:
            self._sec_badge.configure(text="🔒 Bóveda cifrada lista", text_color=self._SUCCESS)
        elif has_tok:
            self._sec_badge.configure(text="⚠ Token plano detectado", text_color=self._WARNING)
        else:
            self._sec_badge.configure(text="🛡️ Protección activa", text_color=self._TEXT_SEC)

    # ──────────────────────────────────────────────────────────────────────
    #  Selector de dirección y carpeta de Drive
    # ──────────────────────────────────────────────────────────────────────
    def _on_mode_changed(self, value: str) -> None:
        if self._migration_running:
            # No permitir cambio de modo en medio de una transferencia
            self._mode_seg.set(
                self._MODE_UPLOAD if self._direction == "upload" else self._MODE_DOWNLOAD
            )
            return

        if value == self._MODE_DOWNLOAD:
            self._direction = "download"
            self._local_title_label.configure(text="Carpeta destino en disco")
            self._drive_title_label.configure(text="Carpeta origen en Drive")
            self._path_entry.configure(placeholder_text="Selecciona dónde guardar en disco duro…")
            self._btn_migrate.configure(text="▶  Iniciar Descarga")
            self._exfat_chk.configure(state="disabled")
            self._log("Modo cambiado: ⬇ Nube (Google Drive) ➔ Disco Duro (solo lectura en Drive).", "INFO")
        else:
            self._direction = "upload"
            self._local_title_label.configure(text="Carpeta local de origen")
            self._drive_title_label.configure(text="Carpeta destino en Drive")
            self._path_entry.configure(placeholder_text="Selecciona una carpeta en tu disco duro…")
            self._btn_migrate.configure(text="▶  Iniciar Subida")
            self._exfat_chk.configure(state="normal")
            self._log("Modo cambiado: ⬆ Local ➔ Google Drive.", "INFO")

    def _on_pick_drive_folder(self) -> None:
        if not self._drive_connected or self._drive_service is None or self._migration_running:
            return
        dlg = DriveFolderPickerDialog(self, self._drive_service)
        self.wait_window(dlg)
        if dlg.selected is not None:
            folder_id, label = dlg.selected
            self._drive_folder_id = folder_id
            self._drive_folder_label = label
            self._drive_path_entry.configure(state="normal")
            self._drive_path_entry.delete(0, "end")
            self._drive_path_entry.insert(0, label)
            self._drive_path_entry.configure(state="readonly")
            self._log(f"Carpeta de Drive seleccionada: {label}", "OK")

    def _on_reset_drive_folder(self) -> None:
        if self._migration_running:
            return
        self._drive_folder_id = None
        self._drive_folder_label = "Mi Unidad (Raíz)"
        self._drive_path_entry.configure(state="normal")
        self._drive_path_entry.delete(0, "end")
        self._drive_path_entry.insert(0, self._drive_folder_label)
        self._drive_path_entry.configure(state="readonly")
        self._log("Carpeta de Drive restablecida a Mi Unidad (Raíz).", "INFO")

    # ──────────────────────────────────────────────────────────────────────
    #  Conexión, seguridad y cierre de sesión
    # ──────────────────────────────────────────────────────────────────────
    def _on_connect_drive(self, error_hint: str = "") -> None:
        if self._migration_running:
            return

        dlg = SecurityAuthDialog(self, error_hint=error_hint)
        self.wait_window(dlg)
        if dlg.result is None:
            return

        passphrase, persist_token = dlg.result
        self._log("Iniciando autenticación segura con Google Drive…", level="INFO")
        self._set_status("Autenticando con Google…")
        self._btn_connect.configure(state="disabled")
        self._progress.configure(mode="indeterminate")
        self._progress.start()

        def _auth_thread() -> None:
            try:
                service = authenticate(
                    log=lambda msg, lvl: self._enqueue("log", (msg, lvl)),
                    passphrase=passphrase,
                    persist_token=persist_token,
                )
                info: Dict[str, Any] = {}
                try:
                    info = get_account_info(service)
                except Exception as exc:
                    self._enqueue("log", (f"No se pudo consultar cuota de cuenta: {exc}", "WARN"))
                self._enqueue("auth_ok", (service, info))
            except TokenDecryptionError as exc:
                self._enqueue("auth_dec_err", str(exc))
            except Exception as exc:
                self._enqueue("auth_err", str(exc))

        threading.Thread(target=_auth_thread, daemon=True).start()

    def _on_auth_success(self, service: Any, info: Dict[str, Any]) -> None:
        self._drive_service = service
        self._drive_connected = True
        self._account_email = info.get("email", "Drive conectado")
        self._account_free_bytes = info.get("free")

        self._progress.stop()
        self._progress.configure(mode="determinate")
        self._progress.set(0)
        self._conn_dot.configure(text_color=self._SUCCESS)

        if self._account_free_bytes is not None:
            conn_text = f"{self._account_email} ({_fmt_size(self._account_free_bytes)} libres)"
        else:
            conn_text = self._account_email

        self._conn_label.configure(text=conn_text, text_color=self._TEXT_PRI)
        self._btn_connect.configure(
            text="Reconectar",
            state="normal",
            fg_color=self._BG_MIST,
            border_width=1,
            border_color=self._BORDER_GLOW,
            text_color=self._TEXT_SEC,
            hover_color=self._BG_CARD,
        )
        self._btn_logout.configure(state="normal")
        self._btn_pick_drive.configure(state="normal")
        self._update_security_badge()
        self._log(f"Cuenta verificada: {conn_text}", level="OK")
        self._set_status("Conectado a Google Drive")
        self._refresh_migrate_button()

    def _on_auth_decryption_error(self, error_msg: str) -> None:
        self._on_auth_error(error_msg)
        self._on_connect_drive(error_hint=error_msg)

    def _on_auth_error(self, error_msg: str) -> None:
        self._progress.stop()
        self._progress.configure(mode="determinate")
        self._progress.set(0)
        self._conn_dot.configure(text_color=self._DANGER)
        self._conn_label.configure(text="Error de conexión", text_color=self._TEXT_SEC)
        self._btn_connect.configure(state="normal")
        self._update_security_badge()
        self._log(f"Error de autenticación: {error_msg}", level="ERROR")
        self._set_status("Error de autenticación")
        self._refresh_migrate_button()

    def _on_logout_clicked(self) -> None:
        if not self._drive_connected or self._migration_running:
            return
        dlg = LogoutSecurityDialog(self, self._account_email or "Google Drive")
        self.wait_window(dlg)
        if dlg.choice is None:
            return

        if dlg.choice == "disconnect":
            self._on_logout_complete("Sesión desconectada en la aplicación (bóveda local conservada).")
            return

        # Revocación completa en Google + destrucción de tokens locales
        self._btn_logout.configure(state="disabled")
        self._btn_connect.configure(state="disabled")
        svc = self._drive_service

        def _revoke_thread() -> None:
            revoke_and_logout(
                svc,
                log=lambda msg, lvl: self._enqueue("log", (msg, lvl)),
            )
            self._enqueue("logout_done", "Acceso revocado en Google y tokens destruidos.")

        threading.Thread(target=_revoke_thread, daemon=True).start()

    def _on_logout_complete(self, message: str) -> None:
        self._drive_service = None
        self._drive_connected = False
        self._account_email = ""
        self._account_free_bytes = None
        self._on_reset_drive_folder()

        self._conn_dot.configure(text_color=self._DANGER)
        self._conn_label.configure(text="Sin conexión a Drive", text_color=self._TEXT_SEC)
        self._btn_connect.configure(
            text="Conectar Drive",
            state="normal",
            fg_color=self._ACCENT,
            hover_color=self._ACCENT_HOV,
            border_width=0,
            text_color=self._TEXT_PRI,
        )
        self._btn_logout.configure(state="disabled")
        self._btn_pick_drive.configure(state="disabled")
        self._update_security_badge()
        self._log(message, level="OK")
        self._set_status("Sesión cerrada")
        self._refresh_migrate_button()

    # ──────────────────────────────────────────────────────────────────────
    #  Selección de carpeta local
    # ──────────────────────────────────────────────────────────────────────
    def _on_select_source(self) -> None:
        if self._migration_running:
            return
        title = (
            "Selecciona la carpeta local de origen"
            if self._direction == "upload"
            else "Selecciona la carpeta de destino en disco duro"
        )
        path = filedialog.askdirectory(title=title, mustexist=True)
        if path:
            self._source_path = path
            self._path_entry.configure(state="normal")
            self._path_entry.delete(0, "end")
            self._path_entry.insert(0, path)
            self._path_entry.configure(state="readonly")
            label = "origen local" if self._direction == "upload" else "destino en disco duro"
            self._log(f"Carpeta de {label} seleccionada: {path}", level="OK")
            if self._direction == "upload" and is_volume_mount_point(path):
                self._log(
                    "💿 Volumen/disco externo detectado: se ejecutará auditoría de certificación pre-formateo al finalizar.",
                    level="INFO",
                )
            self._refresh_migrate_button()

    # ──────────────────────────────────────────────────────────────────────
    #  Ejecución de transferencia (Subida o Descarga)
    # ──────────────────────────────────────────────────────────────────────
    def _on_start_migration(self) -> None:
        if self._migration_running:
            return

        direction = self._direction
        max_workers = self._SPEED_PROFILES.get(self._speed_menu.get(), DEFAULT_MAX_WORKERS)
        verify_md5 = bool(self._verify_var.get())
        filter_exfat = bool(self._filter_exfat_var.get())

        self._migration_running = True
        self._refresh_controls_for_run(running=True)
        self._progress.configure(mode="indeterminate")
        self._progress.start()

        action_label = "Subiendo" if direction == "upload" else "Descargando"
        self._set_status(f"{action_label} ({max_workers} hilos)…")
        self._log("", level="INFO")

        if direction == "upload":
            self._log("━━━━━━  INICIANDO SUBIDA (LOCAL ➔ DRIVE)  ━━━━━━", level="SECTION")
            self._log(f"Origen local  : {self._source_path}", level="INFO")
            self._log(f"Destino Drive : {self._drive_folder_label}", level="INFO")
            self._log(
                f"Perfil: {max_workers} hilo(s) · Chunks 16 MB · Integridad MD5={'Sí' if verify_md5 else 'No'} · Limpieza exFAT={'Sí' if filter_exfat else 'No'}",
                level="INFO",
            )
        else:
            self._log("━━━━━━  INICIANDO DESCARGA (DRIVE ➔ DISCO DURO)  ━━━━━━", level="SECTION")
            self._log(f"Origen Drive  : {self._drive_folder_label}", level="INFO")
            self._log(f"Destino local : {self._source_path}", level="INFO")
            self._log(
                f"Perfil: {max_workers} hilo(s) · Chunks 16 MB · Integridad MD5={'Sí' if verify_md5 else 'No'}",
                level="INFO",
            )

        threading.Thread(
            target=self._run_transfer_worker,
            args=(direction, max_workers, verify_md5, filter_exfat),
            daemon=True,
        ).start()

    def _run_transfer_worker(
        self,
        direction: str,
        max_workers: int,
        verify_md5: bool,
        filter_exfat: bool = True,
    ) -> None:
        log_cb = lambda msg, lvl: self._enqueue("log", (msg, lvl))
        prog_cb = lambda done, total, bps: self._enqueue("progress", (done, total, bps))
        audit: Dict[str, Any] = {}
        t0 = time.monotonic()

        try:
            if direction == "upload":
                runner = StepMigrator(
                    source_path=self._source_path,
                    drive_service=self._drive_service,
                    log_callback=log_cb,
                    drive_folder_id=self._drive_folder_id,
                    max_workers=max_workers,
                    progress_callback=prog_cb,
                    verify_checksum=verify_md5,
                    skip_existing=verify_md5,
                    filter_exfat_junk=filter_exfat,
                )
                errors = runner.run()
                audit = {
                    "safe_to_format": runner.is_safe_to_format,
                    "total_files": runner.total_files_scanned,
                    "uploaded_ok": runner.files_uploaded_ok,
                    "skipped_ok": runner.files_skipped_identical,
                    "bytes_verified": runner.bytes_verified,
                    "junk_skipped": runner.junk_skipped,
                    "manifest_path": runner.manifest_path,
                }
            else:
                runner = StepDownloader(
                    dest_path=self._source_path,
                    drive_service=self._drive_service,
                    log_callback=log_cb,
                    drive_folder_id=self._drive_folder_id,
                    max_workers=max_workers,
                    progress_callback=prog_cb,
                    verify_checksum=verify_md5,
                    skip_existing=verify_md5,
                )
                errors = runner.run()
                audit = {
                    "safe_to_format": False,
                    "total_files": runner.total_files_scanned,
                    "uploaded_ok": runner.files_downloaded_ok,
                    "skipped_ok": runner.files_skipped_identical,
                    "bytes_verified": runner.bytes_verified,
                    "junk_skipped": 0,
                    "manifest_path": "",
                }
        except Exception as exc:
            errors = [(self._source_path, f"Error inesperado: {exc}")]
            self._enqueue("log", (f"[CRÍTICO] Error inesperado en la transferencia: {exc}", "ERROR"))

        audit["duration_seconds"] = max(0.0, time.monotonic() - t0)
        self._enqueue("migration_done", (errors, direction, audit))

    def _on_progress_update(self, transferred: int, total: int, speed_bps: float) -> None:
        if not self._migration_running:
            return
        if total > 0:
            ratio = min(1.0, max(0.0, transferred / total))
            if self._progress.cget("mode") != "determinate":
                self._progress.stop()
                self._progress.configure(mode="determinate")
            self._progress.set(ratio)
            pct = ratio * 100.0
            speed_mbs = speed_bps / (1_024 * 1_024)
            eta_str = _fmt_eta(max(0, total - transferred), speed_bps)
            self._set_status(
                f"{_fmt_size(transferred)} / {_fmt_size(total)} ({pct:.1f}%)  ·  "
                f"{speed_mbs:.1f} MB/s  ·  ⏳ Restante: {eta_str}  ·  🛡️ Anti-suspensión activo"
            )

    def _build_report(
        self,
        errors: List[Tuple[str, str]],
        direction: str,
        audit: Dict[str, Any],
    ) -> Dict[str, Any]:
        is_upload = direction == "upload"
        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "direction": direction,
            "direction_label": (
                "Subida (Local ➔ Google Drive)"
                if is_upload
                else "Descarga (Google Drive ➔ Disco Duro)"
            ),
            "account_email": self._account_email or "Google Drive",
            "source_path": self._source_path if is_upload else self._drive_folder_label,
            "destination": self._drive_folder_label if is_upload else self._source_path,
            "duration_seconds": audit.get("duration_seconds", 0.0),
            "total_files": audit.get("total_files", 0),
            "transferred_ok": audit.get("uploaded_ok", 0),
            "skipped_identical": audit.get("skipped_ok", 0),
            "failed_count": len(errors),
            "bytes_verified": audit.get("bytes_verified", 0),
            "junk_skipped": audit.get("junk_skipped", 0),
            "safe_to_format": bool(audit.get("safe_to_format", False)),
            "manifest_path": audit.get("manifest_path", ""),
            "errors": list(errors),
        }

    def _on_open_last_report(self) -> None:
        if self._last_report is not None:
            TransferReportDialog(self, self._last_report)

    def _on_migration_complete(
        self,
        errors: Optional[List[Tuple[str, str]]],
        direction: str,
        audit: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._progress.stop()
        self._progress.configure(mode="determinate")
        self._progress.set(0)
        self._migration_running = False
        self._refresh_controls_for_run(running=False)

        errors = errors or []
        audit_data = audit or {}
        is_upload = direction == "upload"
        verb = "MIGRACIÓN" if is_upload else "DESCARGA"

        self._last_report = self._build_report(errors, direction, audit_data)
        self._btn_last_report.configure(state="normal")

        if errors:
            self._log(
                f"━━━━━━  {verb} FINALIZADA CON {len(errors)} ADVERTENCIA(S)  ━━━━━━",
                level="WARN",
            )
            self._set_status(f"Completada con {len(errors)} advertencia(s)")
            if is_upload:
                self._log(
                    f"🔴 NO FORMATEAR EL DISCO: {len(errors)} incidencia(s) detectada(s). "
                    "Revisa el informe final antes de borrar o formatear el volumen.",
                    level="ERROR",
                )
        else:
            self._log(f"━━━━━━  {verb} COMPLETADA  ━━━━━━", level="SECTION")
            if is_upload:
                self._log("Todos los archivos fueron subidos y verificados en Drive.", level="OK")
                self._set_status("Respaldo verificado al 100 % ✔")
            else:
                self._log(
                    "Todos los archivos fueron descargados al disco duro con fechas originales restauradas. Drive permanece intacto.",
                    level="OK",
                )
                self._set_status("Restauración completada ✔")

        self._refresh_migrate_button()
        TransferReportDialog(self, self._last_report)

    def _refresh_controls_for_run(self, running: bool) -> None:
        state_ctrl = "disabled" if running else "normal"
        self._mode_seg.configure(state=state_ctrl)
        self._speed_menu.configure(state=state_ctrl)
        self._verify_chk.configure(state=state_ctrl)
        self._exfat_chk.configure(
            state="disabled" if (running or self._direction != "upload") else "normal"
        )
        self._btn_browse_local.configure(state=state_ctrl)
        self._btn_reset_drive.configure(state=state_ctrl)
        self._btn_connect.configure(state=state_ctrl)
        self._btn_logout.configure(state=state_ctrl if self._drive_connected else "disabled")
        self._btn_pick_drive.configure(state=state_ctrl if self._drive_connected else "disabled")

        if running:
            label = "Subiendo…" if self._direction == "upload" else "Descargando…"
            self._btn_migrate.configure(state="disabled", text=label)
        else:
            label = "▶  Iniciar Subida" if self._direction == "upload" else "▶  Iniciar Descarga"
            self._btn_migrate.configure(text=label)

    # ──────────────────────────────────────────────────────────────────────
    #  Certificación Pre-Formateo / Papelera opcional (solo tras subida 100%)
    # ──────────────────────────────────────────────────────────────────────
    def _show_preformat_certification_dialog(self, audit: Dict[str, Any]) -> None:
        """
        Muestra el sello de certificación pre-formateo cuando el 100 % de los
        archivos fueron verificados en Google Drive sin errores.
        """
        is_mount = is_volume_mount_point(self._source_path)
        total_files = audit.get("total_files", 0)
        bytes_verified = audit.get("bytes_verified", 0)
        junk_skipped = audit.get("junk_skipped", 0)
        manifest_path = audit.get("manifest_path", "")

        dialog = ctk.CTkToplevel(self)
        dialog.title("Certificación Pre-Formateo")
        dialog.resizable(False, False)
        dialog.configure(fg_color=self._BG_PANEL)
        _apply_mist_alpha(dialog, 0.98)
        _center_toplevel(self, dialog, 540, 340 if not is_mount else 310)
        dialog.grab_set()
        dialog.focus_force()

        card = ctk.CTkFrame(
            dialog,
            fg_color=self._BG_CARD,
            corner_radius=16,
            border_width=1,
            border_color=self._BORDER_GLOW,
        )
        card.pack(fill="both", expand=True, padx=14, pady=14)

        ctk.CTkLabel(
            card,
            text="🟢  DISCO VERIFICADO AL 100 % (MD5) — APTO PARA FORMATEAR",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=self._SUCCESS,
            fg_color=self._BG_MIST,
            corner_radius=10,
            padx=12,
            pady=6,
        ).pack(pady=(18, 10))

        summary_lines = []
        if total_files:
            summary_lines.append(
                f"Archivos íntegros en Drive: {total_files} ({_fmt_size(bytes_verified)})"
            )
        if junk_skipped:
            summary_lines.append(
                f"Metadatos basura exFAT filtrados: {junk_skipped} (._*, .Spotlight, etc.)"
            )
        if manifest_path:
            summary_lines.append(f"Manifiesto guardado fuera del disco: {manifest_path}")

        if is_mount:
            summary_lines.append(
                "\nYa puedes formatear este volumen a APFS / NTFS desde Utilidad de Discos.\n"
                "Después, usa el modo '⬇ Drive ➔ Disco Duro' para restaurar todo con sus fechas."
            )
        else:
            summary_lines.append(
                "\nTodo el contenido está a salvo en Google Drive.\n"
                "Si estás respaldando un disco para formatear, ya puedes proceder con seguridad."
            )

        ctk.CTkLabel(
            card,
            text="\n".join(summary_lines),
            font=ctk.CTkFont(size=12),
            text_color=self._TEXT_PRI,
            justify="center",
            wraplength=470,
        ).pack(padx=20, pady=(4, 16))

        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(pady=(0, 12))

        def _on_keep() -> None:
            dialog.destroy()
            self._log(
                "Certificación completada. Origen local conservado para formateo manual.",
                level="INFO",
            )

        def _on_trash() -> None:
            dialog.destroy()
            self._send_source_to_trash()

        if not is_mount:
            ctk.CTkButton(
                btn_frame,
                text="Enviar carpeta a la papelera",
                font=ctk.CTkFont(size=12, weight="bold"),
                width=210,
                height=38,
                fg_color=self._DANGER,
                hover_color="#E11D48",
                text_color=self._TEXT_PRI,
                corner_radius=12,
                command=_on_trash,
            ).grid(row=0, column=0, padx=(0, 8))

            ctk.CTkButton(
                btn_frame,
                text="Conservar (Listo para formatear)",
                font=ctk.CTkFont(size=12, weight="bold"),
                width=230,
                height=38,
                fg_color=self._ACCENT,
                hover_color=self._ACCENT_HOV,
                text_color=self._TEXT_PRI,
                corner_radius=12,
                command=_on_keep,
            ).grid(row=0, column=1)
        else:
            ctk.CTkButton(
                btn_frame,
                text="✔  Entendido — Listo para formatear",
                font=ctk.CTkFont(size=13, weight="bold"),
                width=280,
                height=40,
                fg_color=self._ACCENT,
                hover_color=self._ACCENT_HOV,
                text_color=self._TEXT_PRI,
                corner_radius=12,
                command=_on_keep,
            ).pack()

    def _send_source_to_trash(self) -> None:
        self._log(f"Enviando '{self._source_path}' a la papelera…", level="WARN")
        try:
            send2trash(self._source_path)
            self._log("Carpeta de origen enviada a la papelera correctamente.", level="OK")
            self._set_status("Carpeta de origen eliminada (papelera)")
        except Exception as exc:
            self._log(f"Error al enviar a la papelera: {exc}", level="ERROR")

    # ──────────────────────────────────────────────────────────────────────
    #  Utilidades
    # ──────────────────────────────────────────────────────────────────────
    def _refresh_migrate_button(self) -> None:
        ready = self._drive_connected and bool(self._source_path) and not self._migration_running
        self._btn_migrate.configure(state="normal" if ready else "disabled")

    def _set_status(self, text: str) -> None:
        self._status_label.configure(text=text)

    def _on_close(self) -> None:
        if self._migration_running:
            confirm = messagebox.askyesno(
                "Transferencia en curso",
                "Hay una transferencia en progreso.\n"
                "¿Deseas cerrar de todas formas? Los archivos ya completados se conservarán.",
                icon="warning",
            )
            if not confirm:
                return
        self._closing = True
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
#  Punto de entrada
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = StepMigratorApp()
    app.mainloop()
