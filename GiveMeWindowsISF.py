import logging
import os
from typing import Dict, List, Optional, Tuple

from volatility3.framework import (
    automagic,
    constants,
    exceptions,
    interfaces,
    renderers,
)
from volatility3.framework.automagic import symbol_cache
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.plugins import construct_plugin
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows import pdbutil

vollog = logging.getLogger(__name__)


class GiveMeWindowsISF(plugins.PluginInterface):
    """Detects Windows kernel PDB records, downloads matching PDBs from the
    Microsoft Symbol Server, and converts them into Volatility3 ISFs."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    def _log_progress(self, message: str) -> None:
        vollog.info(f"[GiveMeWindowsSymbol] {message}")

    def _log_overall_progress(self, done: int, total: int, detail: str = "") -> None:
        if total <= 0:
            percent = 100.0
            total = 1
            done = 1
        else:
            percent = (float(done) / float(total)) * 100.0

        bar = self._render_progress_bar(percent)
        suffix = f" {detail}" if detail else ""
        vollog.warning(
            f"[GiveMeWindowsSymbol] progress {bar} {percent:5.1f}% ({done}/{total}){suffix}"
        )

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        default_symbol_path = os.path.join(constants.SYMBOL_BASEPATHS[0], "windows")
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Memory layer to scan"
            ),
            requirements.BooleanRequirement(
                name="auto_build",
                description="Try to download/convert ISF from Microsoft Symbol Server",
                default=True,
                optional=True,
            ),
            requirements.StringRequirement(
                name="symbols_path",
                description="Destination directory for Windows symbols",
                default=default_symbol_path,
                optional=True,
            ),
            requirements.StringRequirement(
                name="symbol_server_url",
                description="Override the Microsoft Symbol Server URL",
                default="",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="validate_psscan",
                description="Validate generated symbols by attempting windows.psscan",
                default=True,
                optional=True,
            ),
            requirements.ListRequirement(
                name="kernel_pdb_names",
                element_type=str,
                description="Override list of kernel PDB names to scan for",
                default=None,
                optional=True,
            ),
        ]

    @staticmethod
    def _render_progress_bar(percent: float, width: int = 24) -> str:
        normalized = max(0.0, min(100.0, percent))
        filled = int((normalized / 100.0) * width)
        return "[" + ("#" * filled) + ("-" * (width - filled)) + "]"

    @staticmethod
    def _shorten_message(message: str, limit: int = 260) -> str:
        compact = " ".join((message or "").split())
        if len(compact) <= limit:
            return compact
        return compact[: limit - 3] + "..."

    @staticmethod
    def _ensure_directory(path: str) -> str:
        full_path = os.path.abspath(os.path.expanduser(path))
        os.makedirs(full_path, exist_ok=True)
        return full_path

    def _get_scan_layer_name(self) -> str:
        layer = self.context.layers[self.config["primary"]]
        memory_layer = layer.config.get("memory_layer")
        if memory_layer and memory_layer in self.context.layers:
            return memory_layer
        return layer.name

    def _kernel_pdb_names_bytes(self) -> List[bytes]:
        configured = self.config.get("kernel_pdb_names")
        if configured:
            names = []
            for name in configured:
                if not name:
                    continue
                base = name if name.lower().endswith(".pdb") else f"{name}.pdb"
                names.append(bytes(base, "utf-8"))
            if names:
                return names
        return [
            bytes(name + ".pdb", "utf-8")
            for name in constants.windows.KERNEL_MODULE_NAMES
        ]

    def _collect_kernel_pdbs(
        self, layer_name: str
    ) -> List[Dict[str, object]]:
        """Scan the layer for kernel RSDS records and return one entry per
        unique (pdb_name, GUID, age) tuple."""
        layer = self.context.layers[layer_name]
        page_size = getattr(layer, "page_size", 0x1000) or 0x1000

        seen: Dict[Tuple[str, str, int], Dict[str, object]] = {}
        for record in pdbutil.PDBUtility.pdbname_scan(
            ctx=self.context,
            layer_name=layer_name,
            page_size=page_size,
            pdb_names=self._kernel_pdb_names_bytes(),
            progress_callback=self._progress_callback,
        ):
            key = (
                str(record.get("pdb_name", "")),
                str(record.get("GUID", "")).upper(),
                int(record.get("age", 0) or 0),
            )
            if not key[0] or not key[1]:
                continue
            if key in seen:
                continue
            seen[key] = record

        results = list(seen.values())
        results.sort(key=lambda r: int(r.get("signature_offset", 0) or 0))
        return results

    def _load_local_windows_identifiers(self) -> Dict[bytes, str]:
        cache_file = os.path.join(
            constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME
        )
        cache = symbol_cache.SqliteCache(cache_file)
        cache.update(progress_callback=self._progress_callback)
        return cache.get_identifier_dictionary(
            operating_system="windows", local_only=True
        )

    @staticmethod
    def _find_local_symbol(
        local_identifiers: Dict[bytes, str], pdb_name: str, guid: str, age: int
    ) -> Optional[str]:
        identifier = symbol_cache.WindowsIdentifier.generate(
            pdb_name.strip("\x00"), guid.upper(), age
        )
        return local_identifiers.get(identifier)

    def _download_pdb_isf(
        self, pdb_name: str, guid: str, age: int
    ) -> Tuple[bool, str, str]:
        """Download the PDB from the symbol server and convert it to ISF.

        Returns (ok, isf_path, message).
        """
        clean_pdb = pdb_name.strip("\x00")
        guid_upper = guid.upper()

        original_server = constants.SYMBOL_SERVER_URL
        override = (self.config.get("symbol_server_url") or "").strip()
        if override:
            constants.SYMBOL_SERVER_URL = override
            self._log_progress(f"Overriding symbol server URL: {override}")

        try:
            self._log_progress(
                f"Downloading PDB {clean_pdb} {guid_upper}-{age} "
                f"from {constants.SYMBOL_SERVER_URL}"
            )
            try:
                pdbutil.PDBUtility.download_pdb_isf(
                    self.context,
                    guid_upper,
                    age,
                    clean_pdb,
                    progress_callback=self._progress_callback,
                )
            except Exception as exc:
                hint = ""
                if "did not download completely" in str(exc):
                    hint = (
                        " (likely a partial cache from a previous interrupted run; "
                        "rerun with --clear-cache or delete the matching "
                        "data_*.cache file under volatility3 cache dir)"
                    )
                return False, "", f"download_pdb_isf raised: {exc}{hint}"
        finally:
            if override:
                constants.SYMBOL_SERVER_URL = original_server

        local_identifiers = self._load_local_windows_identifiers()
        isf_path = self._find_local_symbol(local_identifiers, clean_pdb, guid_upper, age)
        if not isf_path:
            return (
                False,
                "",
                "PDB download/convert finished but ISF was not registered "
                "in the local symbol cache",
            )
        return True, isf_path, f"Downloaded and converted PDB to {isf_path}"

    def _validate_with_windows_psscan(self) -> Tuple[bool, str]:
        try:
            from volatility3.plugins.windows import psscan as windows_psscan

            psscan_plugin = windows_psscan.PsScan
        except Exception as excp:
            return False, f"Unable to import windows.psscan: {excp}"

        try:
            available_automagics = automagic.available(self.context)
            chosen_automagics = automagic.choose_automagic(
                available_automagics, psscan_plugin
            )
            psscan_instance = construct_plugin(
                self.context,
                chosen_automagics,
                psscan_plugin,
                "plugins",
                self._progress_callback,
                self.open,
            )
            grid = psscan_instance.run()

            row_count = 0
            for _level, _item in grid._generator:
                row_count += 1
                if row_count >= 1:
                    break
            if row_count == 0:
                return (
                    False,
                    "windows.psscan returned 0 processes "
                    "(symbols may not match this memory image)",
                )
            return True, f"windows.psscan validation passed (rows={row_count})"
        except exceptions.UnsatisfiedException as excp:
            details = ", ".join(str(item) for item in excp.unsatisfied)
            return False, f"windows.psscan unsatisfied: {details}"
        except Exception as excp:
            return False, f"windows.psscan validation failed: {excp}"

    def _generator(self):
        # Touch ensure_directory so users get a friendly error if the path is bad,
        # even though PDBUtility writes under volatility3.symbols.__path__.
        self._ensure_directory(self.config.get("symbols_path"))

        layer_name = self._get_scan_layer_name()
        self._log_progress(f"Scanning Windows kernel PDB records from layer: {layer_name}")
        kernel_records = self._collect_kernel_pdbs(layer_name)

        self._log_progress(
            f"Found {len(kernel_records)} kernel PDB candidate(s)"
        )

        if not kernel_records:
            self._log_overall_progress(1, 1, "no kernel PDB records found")
            yield (
                0,
                (
                    format_hints.Hex(0),
                    "",
                    "",
                    0,
                    format_hints.Hex(0),
                    "none",
                    "",
                    "failed",
                    "No kernel PDB record found in memory layer",
                ),
            )
            return

        local_identifiers = self._load_local_windows_identifiers()
        total = len(kernel_records)
        processed = 0
        self._log_overall_progress(0, total, "start")

        for idx, record in enumerate(kernel_records, start=1):
            pdb_name = str(record.get("pdb_name", ""))
            guid = str(record.get("GUID", "")).upper()
            age = int(record.get("age", 0) or 0)
            sig_offset = int(record.get("signature_offset", 0) or 0)
            mz_offset = int(record.get("mz_offset") or 0)

            self._log_progress(
                f"[{idx}/{total}] Processing PDB: name={pdb_name} "
                f"guid={guid} age={age} mz=0x{mz_offset:x}"
            )

            local_symbol = self._find_local_symbol(
                local_identifiers, pdb_name, guid, age
            )
            if local_symbol:
                self._log_progress(f"Local symbol already available: {local_symbol}")
                yield (
                    0,
                    (
                        format_hints.Hex(sig_offset),
                        pdb_name,
                        guid,
                        age,
                        format_hints.Hex(mz_offset),
                        "local",
                        local_symbol,
                        "ready",
                        "Matching local symbol file found",
                    ),
                )
                processed += 1
                self._log_overall_progress(
                    processed, total, f"pdb {idx}/{total}: local symbol"
                )
                continue

            if not self.config.get("auto_build", True):
                yield (
                    0,
                    (
                        format_hints.Hex(sig_offset),
                        pdb_name,
                        guid,
                        age,
                        format_hints.Hex(mz_offset),
                        "msdl",
                        "",
                        "failed",
                        "auto_build disabled",
                    ),
                )
                processed += 1
                self._log_overall_progress(
                    processed, total, f"pdb {idx}/{total}: skipped"
                )
                continue

            try:
                downloaded_ok, isf_path, message = self._download_pdb_isf(
                    pdb_name, guid, age
                )
            except Exception as excp:
                downloaded_ok = False
                isf_path = ""
                message = f"Unexpected download error: {excp}"

            if not downloaded_ok:
                self._log_progress(
                    f"PDB ISF download failed for {pdb_name} {guid}-{age}: {message}"
                )
                yield (
                    0,
                    (
                        format_hints.Hex(sig_offset),
                        pdb_name,
                        guid,
                        age,
                        format_hints.Hex(mz_offset),
                        "msdl",
                        "",
                        "failed",
                        self._shorten_message(message),
                    ),
                )
                processed += 1
                self._log_overall_progress(
                    processed, total, f"pdb {idx}/{total}: failed"
                )
                continue

            self._log_progress(f"PDB ISF download succeeded: {isf_path}")
            local_identifiers = self._load_local_windows_identifiers()

            validation_status = "downloaded"
            validation_message = message
            if self.config.get("validate_psscan", True):
                self._log_progress(
                    "Validating generated symbols with windows.psscan"
                )
                valid_ok, valid_message = self._validate_with_windows_psscan()
                if valid_ok:
                    validation_status = "validated"
                    validation_message = f"{message}; {valid_message}"
                    self._log_progress(
                        "windows.psscan validation passed, "
                        "stopping further PDB downloads"
                    )
                    yield (
                        0,
                        (
                            format_hints.Hex(sig_offset),
                            pdb_name,
                            guid,
                            age,
                            format_hints.Hex(mz_offset),
                            "msdl",
                            isf_path,
                            validation_status,
                            validation_message,
                        ),
                    )
                    processed += 1
                    self._log_overall_progress(
                        processed, total, f"pdb {idx}/{total}: validated"
                    )
                    return

                self._log_progress(
                    f"windows.psscan validation failed, continuing: {valid_message}"
                )
                # ISF on disk is still useful (Windows GUID match is exact);
                # leave status as "downloaded" rather than degrading to "failed".
                validation_status = "downloaded"
                validation_message = (
                    f"{message}; psscan validation failed: {valid_message}"
                )

            yield (
                0,
                (
                    format_hints.Hex(sig_offset),
                    pdb_name,
                    guid,
                    age,
                    format_hints.Hex(mz_offset),
                    "msdl",
                    isf_path,
                    validation_status,
                    validation_message,
                ),
            )
            processed += 1
            self._log_overall_progress(
                processed, total, f"pdb {idx}/{total}: downloaded"
            )

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("PDB Name", str),
                ("GUID", str),
                ("Age", int),
                ("MZ Offset", format_hints.Hex),
                ("Source", str),
                ("Symbol File", str),
                ("Status", str),
                ("Message", str),
            ],
            self._generator(),
        )
