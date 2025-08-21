from __future__ import annotations

import json
import os
import shlex
import subprocess
import logging
import hashlib
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from mkdocs.plugins import BasePlugin
from mkdocs.config import config_options

log = logging.getLogger("mkdocs.plugins.pandoc")


class PandocPlugin(BasePlugin):
    """
    MkDocs Pandoc plugin with **incremental builds**.

    Features:
      - Exports each Markdown page to one or more Pandoc formats (default: PDF).
      - Optional combined export (single file for the whole site).
      - Skips running Pandoc for pages that *haven't changed* since the last build
        (tracked via file mtime/size, template mtime, Pandoc version and config fingerprint).

    Supported configuration keys (mkdocs.yml):
      - enabled_if_env: str | None
          Only run when the named environment variable is set (truthy).

      - combined: bool (default False)
          If True, produce a single combined document instead of per-page outputs.

      - combined_output_path: str (default "pandoc/combined.pdf")
          Output path (under site_dir) for combined mode. Extension decides the format
          (e.g. .pdf, .docx). Parent dirs are created automatically.

      - pandoc_template: str (optional)
          Passed to Pandoc as --template=<value>. May be a short name (e.g. "eisvogel")
          or an absolute path.

      - pandoc_extra_args: str (default "")
          Extra CLI arguments passed to Pandoc for *all* formats.

      - pandoc_args: dict[str, str] (default {})
          Per-format extra arguments, keyed by format/extension (e.g. "pdf", "docx").
          Each value is a single string (parsed with shlex.split) appended to the Pandoc
          command when building that format.

      - incremental: bool (default True)
          Enable incremental builds (skip unchanged pages).

      - cache_file: str (default ".mkdocs-pandoc-cache.json")
          Cache file written under site_dir to store fingerprints.
    """

    config_scheme = (
        ("enabled_if_env", config_options.Type(str)),
        ("combined", config_options.Type(bool, default=False)),
        ("combined_output_path", config_options.Type(str, default="pandoc/combined.pdf")),
        ("pandoc_template", config_options.Type(str, default="")),
        ("pandoc_extra_args", config_options.Type(str, default="")),
        ("pandoc_args", config_options.Type(dict, default={})),
        # incremental additions
        ("incremental", config_options.Type(bool, default=True)),
        ("cache_file", config_options.Type(str, default=".mkdocs-pandoc-cache.json")),
    )

    # --------------------------- MkDocs lifecycle ---------------------------

    def on_config(self, config):
        self.site_dir = Path(config["site_dir"])  # type: ignore[assignment]
        self.docs_dir = Path(config["docs_dir"])  # type: ignore[assignment]
        self.enabled_var = (self.config.get("enabled_if_env") or "").strip()

        self.cache_path = self.site_dir / self.config.get("cache_file", ".mkdocs-pandoc-cache.json")
        self.cache: Dict[str, str] = {}
        if self.cache_path.exists():
            try:
                self.cache = json.loads(self.cache_path.read_text(encoding="utf-8"))
            except Exception:
                self.cache = {}

        self._pandoc_ver = self._pandoc_version()
        self._cfg_fp = self._config_fingerprint()
        # reset cache if config changed
        if self.cache.get("_config") != self._cfg_fp:
            self.cache = {"_config": self._cfg_fp}

        return config

    def on_files(self, files, config):
        # Remember only documentation pages (skip assets)
        self._pages = [f for f in files.documentation_pages()]  # type: ignore[attr-defined]
        return files

    def on_post_build(self, config):
        if not self._is_enabled():
            log.info("pandoc: disabled (enabled_if_env=%s)", self.enabled_var or "<none>")
            return None

        fmts = self._detect_formats()
        built = skipped = 0

        if self.config.get("combined", False):
            out_rel = self.config.get("combined_output_path", "pandoc/combined.pdf")
            out_path = self.site_dir / out_rel
            out_path.parent.mkdir(parents=True, exist_ok=True)

            # Rebuild combined output only if any source changed (or output missing)
            any_changed = not out_path.exists()
            fmt = Path(out_rel).suffix.lstrip(".") or "pdf"
            for f in self._pages:
                src = Path(f.abs_src_path)
                if self._should_build(src, fmt):
                    any_changed = True
                    break

            if any_changed:
                self._export_combined(out_path, fmt)
                # Mark all sources as built for this fmt
                for f in self._pages:
                    self._mark_built(Path(f.abs_src_path), fmt)
                built += 1
            else:
                skipped += 1
        else:
            # Per-page outputs live under site_dir / pandoc / <relpath>.<fmt>
            out_root = self.site_dir / "pandoc"
            for f in self._pages:
                src = Path(f.abs_src_path)
                rel = src.relative_to(self.docs_dir)
                for fmt in fmts:
                    out = out_root / rel.with_suffix(f".{fmt}")
                    out.parent.mkdir(parents=True, exist_ok=True)
                    if self._should_build(src, fmt) or not out.exists():
                        self._export_single(src, out, fmt)
                        self._mark_built(src, fmt)
                        built += 1
                    else:
                        skipped += 1

        # Persist cache
        try:
            self.cache["_config"] = self._cfg_fp
            self.cache_path.write_text(json.dumps(self.cache, indent=2), encoding="utf-8")
        except Exception:
            pass

        log.info("pandoc: %s built, %s skipped (incremental=%s)", built, skipped, self.config.get("incremental", True))
        return None

    # ------------------------------ Build logic -----------------------------

    def _export_single(self, src: Path, out: Path, fmt: str):
        """Export a single Markdown source file to the requested format."""
        cmd = self._build_pandoc_cmd([src], out, fmt)
        self._run(cmd, cwd=self.docs_dir)

    def _export_combined(self, out: Path, fmt: str):
        """Export all documentation pages into a single combined document."""
        inputs = [Path(f.abs_src_path) for f in self._pages]
        # Sort deterministically by relative path (you can customize to follow nav order)
        inputs.sort(key=lambda p: str(p.relative_to(self.docs_dir)))
        cmd = self._build_pandoc_cmd(inputs, out, fmt)
        self._run(cmd, cwd=self.docs_dir)

    def _build_pandoc_cmd(self, inputs: List[Path], out: Path, fmt: str) -> List[str]:
        # Use paths relative to docs_dir so relative links resolve similarly to MkDocs
        rel_inputs = [str(p.relative_to(self.docs_dir)) for p in inputs]
        cmd: List[str] = ["pandoc", *rel_inputs, "-o", str(out)]

        template = (self.config.get("pandoc_template") or "").strip()
        if template:
            # Accept either a short name (e.g., "eisvogel") or an absolute path
            if template and not any(template.endswith(ext) for ext in (".tex", ".latex", ".html", ".tpl")):
                # Short names are fine; pandoc will resolve from its templates path
                pass
            cmd.extend(["--template", template])

        extra_all = (self.config.get("pandoc_extra_args") or "").strip()
        if extra_all:
            cmd.extend(shlex.split(extra_all))

        per_fmt: Dict[str, str] = self.config.get("pandoc_args", {}) or {}
        if fmt in per_fmt and per_fmt[fmt]:
            cmd.extend(shlex.split(per_fmt[fmt]))

        # If format implies PDF but no engine chosen, leave to pandoc defaults.
        return cmd

    def _run(self, cmd: List[str], cwd: Optional[Path] = None) -> None:
        log.debug("pandoc: cwd=%s cmd=%s", cwd or os.getcwd(), " ".join(shlex.quote(x) for x in cmd))
        try:
            subprocess.run(cmd, check=True, cwd=str(cwd) if cwd else None)
        except subprocess.CalledProcessError as e:
            log.error("pandoc: command failed with exit code %s", e.returncode)
            raise

    # ------------------------------ Incremental -----------------------------

    def _is_enabled(self) -> bool:
        if not self.enabled_var:
            return True
        return bool(os.environ.get(self.enabled_var))

    def _detect_formats(self) -> List[str]:
        # Per-page build can emit multiple formats; infer from pandoc_args keys or default to ["pdf"]
        per_fmt: Dict[str, str] = self.config.get("pandoc_args", {}) or {}
        fmts = [k.strip().lstrip(".") for k in per_fmt.keys() if k]
        return fmts or ["pdf"]

    def _pandoc_version(self) -> str:
        try:
            out = subprocess.check_output(["pandoc", "--version"], text=True)
            return out.splitlines()[0].strip()
        except Exception:
            return "unknown"

    def _config_fingerprint(self) -> str:
        subset = {
            "combined": self.config.get("combined", False),
            "combined_output_path": self.config.get("combined_output_path", ""),
            "pandoc_template": self.config.get("pandoc_template", ""),
            "pandoc_extra_args": self.config.get("pandoc_extra_args", ""),
            "pandoc_args": self.config.get("pandoc_args", {}),
            "pandoc_version": self._pandoc_ver,
        }
        raw = json.dumps(subset, sort_keys=True, ensure_ascii=False)
        return hashlib.blake2b(raw.encode("utf-8"), digest_size=16).hexdigest()

    def _template_mtime_ns(self) -> int:
        tpl = (self.config.get("pandoc_template") or "").strip()
        if not tpl:
            return 0
        p = Path(tpl)
        if not p.is_absolute():
            for base in ("/usr/local/share/pandoc/templates", "/usr/share/pandoc/templates"):
                # Try common pandoc template dirs; support short names like "eisvogel"
                name = tpl if any(tpl.endswith(ext) for ext in (".latex", ".tex", ".html", ".tpl")) else f"{tpl}.latex"
                cand = Path(base) / name
                if cand.exists():
                    p = cand
                    break
        try:
            return p.stat().st_mtime_ns
        except Exception:
            return 0

    def _src_fingerprint(self, src_path: Path, fmt: str) -> str:
        st = src_path.stat()
        key = f"{src_path.resolve()}|{st.st_mtime_ns}|{st.st_size}|{self._template_mtime_ns()}|{fmt}"
        return hashlib.blake2b(key.encode("utf-8"), digest_size=16).hexdigest()

    def _should_build(self, src: Path, fmt: str) -> bool:
        if not self.config.get("incremental", True):
            return True
        prev = self.cache.get(self._cache_key(src, fmt))
        cur = self._src_fingerprint(src, fmt)
        if self.cache.get("_config") != self._cfg_fp:
            return True
        return prev != cur

    def _mark_built(self, src: Path, fmt: str) -> None:
        self.cache[self._cache_key(src, fmt)] = self._src_fingerprint(src, fmt)

    @staticmethod
    def _cache_key(src: Path, fmt: str) -> str:
        return f"{src.resolve()}::{fmt}"
