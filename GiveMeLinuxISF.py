import base64
import json
import logging
import os
import queue
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Dict, List, Optional, Sequence, Tuple

from volatility3.framework import automagic, constants, exceptions, interfaces, renderers
from volatility3.framework.automagic import symbol_cache
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.plugins import construct_plugin
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


class GiveMeLinuxISF(plugins.PluginInterface):
    """Detects Linux banners, infers distro/kernel, and prepares Linux ISFs."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    def _log_progress(self, message: str) -> None:
        vollog.info(f"[GiveMeLinuxISF] {message}")

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
            f"[GiveMeLinuxISF] progress {bar} {percent:5.1f}% ({done}/{total}){suffix}"
        )

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        default_symbol_path = os.path.join(constants.SYMBOL_BASEPATHS[0], "linux")
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer to scan"
            ),
            requirements.BooleanRequirement(
                name="auto_build",
                description="Try to build ISF from Docker kernel files first",
                default=True,
                optional=True,
            ),
            requirements.StringRequirement(
                name="symbols_path",
                description="Destination directory for Linux symbols",
                default=default_symbol_path,
                optional=True,
            ),
            requirements.StringRequirement(
                name="docker_image",
                description="Single Docker image to copy kernel files from",
                default="",
                optional=True,
            ),
            requirements.StringRequirement(
                name="docker_images",
                description="Comma-separated Docker images to try",
                default="",
                optional=True,
            ),
            requirements.StringRequirement(
                name="dwarf2json_go_fallback_image",
                description="Go Docker image used to build/run dwarf2json",
                default="golang:1.24",
                optional=True,
            ),
            requirements.StringRequirement(
                name="docker_platform",
                description="Docker platform override (for example linux/amd64)",
                default="",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="docker_auto_pull",
                description="Automatically pull Docker images before use",
                default=True,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="docker_prepare_kernel_packages",
                description="Try to install matching kernel/debug packages inside Docker",
                default=True,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="validate_psscan",
                description="Validate generated symbols by attempting linux.psscan",
                default=True,
                optional=True,
            ),
            requirements.IntRequirement(
                name="max_auto_images",
                description="Maximum guessed Docker images to try per banner",
                default=3,
                optional=True,
            ),
        ]

    @staticmethod
    def _infer_kernel_release(banner: str) -> str:
        match = re.search(r"Linux version\s+([^\s]+)", banner)
        if not match:
            return ""
        return match.group(1)

    @staticmethod
    def _infer_distribution(banner: str) -> str:
        lower_banner = banner.lower()
        patterns = [
            (("ubuntu",), "ubuntu"),
            (("debian",), "debian"),
            (("arch linux", "archlinux"), "archlinux"),
            (("kali",), "kali"),
            (("almalinux",), "almalinux"),
            (("rocky",), "rockylinux"),
            (("centos",), "centos"),
            (("fedora",), "fedora"),
            (("red hat", "rhel"), "rhel"),
            (("suse", "opensuse"), "suse"),
            (("amzn", "amazon linux"), "amazonlinux"),
        ]
        for keywords, name in patterns:
            if any(keyword in lower_banner for keyword in keywords):
                return name
        return "unknown"

    @staticmethod
    def _infer_architecture(banner: str, kernel_release: str) -> str:
        combined = f"{banner} {kernel_release}".lower()
        patterns = [
            (("x86_64", "amd64"), "amd64"),
            (("i386", "i686"), "386"),
            (("aarch64", "arm64"), "arm64"),
            (("armv7", "armv6", " arm "), "arm"),
        ]
        for keywords, name in patterns:
            if any(keyword in combined for keyword in keywords):
                return name
        return "unknown"

    @staticmethod
    def _infer_ubuntu_version(banner: str) -> str:
        """Infer the Ubuntu release version from a kernel banner.

        Ubuntu kernel package versions embed a backport marker like
        ``~24.04.1``.  When present we know the target Ubuntu release.
        When absent the package is *native* to the release that shipped it,
        and we fall back to the GCC major version as a rough heuristic.
        """
        # Backport marker: (Ubuntu 6.17.0-14.14~24.04.1-generic ...)
        backport = re.search(r"\(Ubuntu\s+\S+~(\d+\.\d+)", banner)
        if backport:
            return backport.group(1)

        # Native package — map GCC major to Ubuntu release (approximate)
        gcc = re.search(r"gcc[- ]\S*\s*\(Ubuntu\s+(\d+)\.", banner)
        if gcc:
            gcc_to_ubuntu = {
                15: "26.04",
                14: "25.10",
                13: "24.04",
                12: "22.04",
                11: "22.04",
            }
            return gcc_to_ubuntu.get(int(gcc.group(1)), "")
        return ""

    @classmethod
    def _candidate_docker_images(
        cls, distribution: str, architecture: str, banner: str = ""
    ) -> List[str]:
        guessed = {
            "ubuntu": [
                "ubuntu:latest",
                "ubuntu:26.04",
                "ubuntu:25.10",
                "ubuntu:24.04",
                "ubuntu:22.04",
            ],
            "debian": ["debian:bookworm", "debian:bullseye", "debian:buster"],
            "archlinux": ["archlinux:latest"],
            "kali": ["kalilinux/kali-rolling:latest"],
            "almalinux": ["almalinux:9", "almalinux:8"],
            "rockylinux": ["rockylinux:9", "rockylinux:8"],
            "centos": ["quay.io/centos/centos:stream9", "quay.io/centos/centos:stream8"],
            "fedora": ["fedora:41", "fedora:40"],
            "rhel": [
                "registry.access.redhat.com/ubi9/ubi:latest",
                "registry.access.redhat.com/ubi8/ubi:latest",
            ],
            "suse": ["opensuse/leap:15.6", "opensuse/tumbleweed:latest"],
            "amazonlinux": ["amazonlinux:2023", "amazonlinux:2"],
            "unknown": [],
        }

        images = guessed.get(distribution, [])

        # For Ubuntu, try to prioritize the exact release inferred from the banner
        if distribution == "ubuntu" and banner:
            ubuntu_ver = cls._infer_ubuntu_version(banner)
            if ubuntu_ver:
                exact_tag = f"ubuntu:{ubuntu_ver}"
                # Put the exact match first, then the rest (without duplicates)
                prioritized = [exact_tag]
                for img in images:
                    if img != exact_tag:
                        prioritized.append(img)
                images = prioritized

        return images

    @staticmethod
    def _parse_csv_config(value: str) -> List[str]:
        if not value:
            return []
        return [item.strip() for item in value.split(",") if item.strip()]

    def _get_scan_layer_name(self) -> str:
        layer = self.context.layers[self.config["primary"]]
        memory_layer = layer.config.get("memory_layer")
        if memory_layer and memory_layer in self.context.layers:
            return memory_layer
        return layer.name

    @staticmethod
    def _banner_byte_candidates(banner: str) -> List[bytes]:
        encoded = banner.encode("latin-1", errors="ignore")
        return [
            encoded,
            encoded + b"\x00",
            encoded + b"\x00\n",
            encoded.rstrip(b"\x00\n"),
        ]

    @staticmethod
    def _extract_banner_text(raw_data: bytes) -> Optional[str]:
        start = raw_data.find(b"Linux version ")
        if start < 0:
            return None

        data = raw_data[start:]
        cut_positions = [pos for pos in (data.find(b"\x00"), data.find(b"\n")) if pos >= 0]
        if cut_positions:
            data = data[: min(cut_positions)]

        data = data.strip()
        if not data:
            return None

        allowed = b" #()+,;/-.0123456789:@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
        if any(char not in allowed for char in data):
            return None

        banner = str(data, encoding="latin-1", errors="replace")
        if not banner.startswith("Linux version "):
            return None

        # Trim trailing garbage after the final distro package marker.
        # Ubuntu/Debian banners end with e.g. "(Ubuntu 6.17.0-14.14-generic 6.17.9)".
        # Memory scans can pick up adjacent printable bytes (e.g. "...6.17.9)9)").
        trim_matches = list(re.finditer(
            r'\((Ubuntu|Debian)\s+[^)\s]+(?:\s+[^)\s]+)*\)', banner
        ))
        if trim_matches:
            banner = banner[:trim_matches[-1].end()]

        return banner

    @staticmethod
    def _banner_quality_score(banner: str) -> int:
        score = len(banner)
        if "SMP" in banner:
            score += 200
        if "PREEMPT" in banner:
            score += 100
        if "(" in banner and ")" in banner:
            score += 80
        if "#" in banner:
            score += 50
        return score

    def _collect_linux_banners(
        self, layer_name: str
    ) -> List[Tuple[format_hints.Hex, str]]:
        best_by_kernel: Dict[str, Tuple[int, format_hints.Hex, str]] = {}
        layer = self.context.layers[layer_name]
        for offset in layer.scan(
            context=self.context,
            scanner=scanners.RegExScanner(rb"Linux version [0-9]+\.[0-9]+\.[0-9]+"),
        ):
            data = layer.read(offset, 0xFFF)
            banner = self._extract_banner_text(data)
            if not banner:
                continue

            kernel_release = self._infer_kernel_release(banner) or banner
            score = self._banner_quality_score(banner)
            current = best_by_kernel.get(kernel_release)
            if current is None or score > current[0]:
                best_by_kernel[kernel_release] = (score, format_hints.Hex(offset), banner)

        selected = list(best_by_kernel.values())
        selected.sort(key=lambda item: int(item[1]))
        return [(offset, banner) for _, offset, banner in selected]

    @staticmethod
    def _ensure_directory(path: str) -> str:
        full_path = os.path.abspath(os.path.expanduser(path))
        os.makedirs(full_path, exist_ok=True)
        return full_path

    def _load_local_linux_identifiers(self) -> Dict[bytes, str]:
        cache_file = os.path.join(constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME)
        cache = symbol_cache.SqliteCache(cache_file)
        cache.update(progress_callback=self._progress_callback)
        return cache.get_identifier_dictionary(operating_system="linux", local_only=True)

    @classmethod
    def _find_local_symbol(
        cls, local_identifiers: Dict[bytes, str], banner: str
    ) -> Optional[str]:
        for candidate in cls._banner_byte_candidates(banner):
            if candidate in local_identifiers:
                return local_identifiers[candidate]
        return None

    def _run_command(
        self,
        command: Sequence[str],
        stream_output: bool = False,
        output_prefix: str = "",
    ) -> subprocess.CompletedProcess:
        if command and command[0] == "docker":
            rendered = " ".join(shlex.quote(str(part)) for part in command)
            self._log_progress(
                f"Container command: {self._shorten_message(rendered, 600)}"
            )
        if stream_output:
            pkg_container_id = ""
            if (
                output_prefix == "pkg> "
                and len(command) >= 3
                and command[0] == "docker"
                and command[1] == "exec"
            ):
                pkg_container_id = str(command[2])

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            collected = []
            last_progress_percent = -1.0
            expected_total_bytes = 0.0
            last_polled_bytes = -1.0
            rx_baseline_bytes: Optional[float] = None
            stream_start_time = time.monotonic()
            last_heartbeat_time = stream_start_time
            assert process.stdout is not None
            for line in self._iter_stream_lines_with_idle(process.stdout):
                if line is None:
                    if output_prefix == "pkg> " and pkg_container_id:
                        polled_bytes = self._poll_container_downloaded_bytes(pkg_container_id)
                        if polled_bytes is None and expected_total_bytes > 0:
                            rx_bytes = self._poll_container_rx_bytes(pkg_container_id)
                            if rx_bytes is not None:
                                if rx_baseline_bytes is None:
                                    rx_baseline_bytes = rx_bytes
                                polled_bytes = max(0.0, rx_bytes - rx_baseline_bytes)

                        if polled_bytes is not None and polled_bytes >= 0:
                            should_log = (
                                last_polled_bytes < 0
                                or polled_bytes - last_polled_bytes >= (5 * 1024 * 1024)
                            )
                            if should_log:
                                if expected_total_bytes > 0:
                                    polled_percent = min(
                                        99.9,
                                        (polled_bytes / expected_total_bytes) * 100.0,
                                    )
                                    if polled_percent - last_progress_percent >= 0.5:
                                        self._log_progress(
                                            "pkg-progress> "
                                            f"{self._render_progress_bar(polled_percent)} "
                                            f"{polled_percent:5.1f}% "
                                            f"downloaded {polled_bytes / (1024.0 * 1024.0):.1f} MB"
                                        )
                                        last_progress_percent = polled_percent
                                        last_heartbeat_time = time.monotonic()
                                else:
                                    self._log_progress(
                                        "pkg-progress> "
                                        f"downloaded {polled_bytes / (1024.0 * 1024.0):.1f} MB"
                                    )
                                    last_heartbeat_time = time.monotonic()
                                last_polled_bytes = polled_bytes

                        now = time.monotonic()
                        if (
                            expected_total_bytes > 0
                            and now - last_heartbeat_time >= 10.0
                        ):
                            elapsed = int(now - stream_start_time)
                            self._log_progress(
                                "pkg-progress> "
                                f"downloading... elapsed {elapsed}s"
                            )
                            last_heartbeat_time = now
                    continue

                line = line.strip()
                if line:
                    apt_progress = None
                    if output_prefix == "pkg> ":
                        total_bytes = self._apt_total_bytes_from_line(line)
                        if total_bytes is not None:
                            expected_total_bytes = max(expected_total_bytes, total_bytes)

                        marker_bytes = self._apt_bytes_marker_from_line(line)
                        if marker_bytes is not None:
                            if expected_total_bytes > 0:
                                marker_percent = min(
                                    99.9, (marker_bytes / expected_total_bytes) * 100.0
                                )
                                should_log_marker = (
                                    marker_percent - last_progress_percent >= 1.0
                                )
                                if should_log_marker:
                                    self._log_progress(
                                        "pkg-progress> "
                                        f"{self._render_progress_bar(marker_percent)} "
                                        f"{marker_percent:5.1f}% "
                                        f"downloaded {marker_bytes / (1024.0 * 1024.0):.1f} MB"
                                    )
                                    last_progress_percent = marker_percent
                            else:
                                self._log_progress(
                                    "pkg-progress> "
                                    f"downloaded {marker_bytes / (1024.0 * 1024.0):.1f} MB"
                                )
                            continue

                        apt_progress = self._apt_progress_from_line(line)
                        if apt_progress is None:
                            apt_progress = self._apt_progress_fallback_from_line(line)
                    if apt_progress:
                        progress_percent, progress_detail = apt_progress
                        should_log_progress = (
                            progress_percent >= 100.0
                            or progress_percent - last_progress_percent >= 1.0
                        )
                        if should_log_progress:
                            self._log_progress(
                                "pkg-progress> "
                                f"{self._render_progress_bar(progress_percent)} "
                                f"{progress_percent:5.1f}% {progress_detail}"
                            )
                            last_progress_percent = progress_percent
                        continue
                    collected.append(line)
                    self._log_progress(f"{output_prefix}{line}")
            process.wait()
            result = subprocess.CompletedProcess(
                args=command,
                returncode=process.returncode,
                stdout="\n".join(collected),
                stderr="",
            )
        else:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )

        if command and command[0] == "docker":
            self._log_progress(f"Container command finished (rc={result.returncode})")
        return result

    @staticmethod
    def _iter_stream_lines_with_idle(stream, idle_seconds: float = 2.0):
        sentinel = object()
        chunks: "queue.Queue[object]" = queue.Queue()

        def _reader_thread() -> None:
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        break
                    chunks.put(chunk)
            finally:
                chunks.put(sentinel)

        thread = threading.Thread(target=_reader_thread, daemon=True)
        thread.start()

        buffer = ""

        while True:
            try:
                chunk = chunks.get(timeout=idle_seconds)
            except queue.Empty:
                yield None
                continue

            if chunk is sentinel:
                if buffer:
                    yield buffer
                return

            text = (
                chunk
                if isinstance(chunk, str)
                else chunk.decode("utf-8", errors="replace")
            )
            for char in text:
                if char in ("\n", "\r"):
                    if buffer:
                        yield buffer
                        buffer = ""
                else:
                    buffer += char

    def _docker_exec_float(self, container_id: str, script: str) -> Optional[float]:
        command = self._docker_command_base() + ["exec", container_id, "sh", "-lc", script]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
        except Exception:
            return None
        if result.returncode != 0:
            return None
        output = (result.stdout or "").strip()
        if not output:
            return None
        try:
            return float(output.splitlines()[-1].strip())
        except ValueError:
            return None

    def _poll_container_downloaded_bytes(self, container_id: str) -> Optional[float]:
        return self._docker_exec_float(
            container_id,
            "bytes=0; "
            "if [ -d /var/cache/apt/archives ]; then "
            "  set -- $(du -sk /var/cache/apt/archives 2>/dev/null); "
            "  [ -n \"$1\" ] && bytes=$(( $1 * 1024 )); "
            "fi; "
            "printf '%s\\n' \"$bytes\"",
        )

    def _poll_container_rx_bytes(self, container_id: str) -> Optional[float]:
        return self._docker_exec_float(
            container_id,
            "awk -F'[: ]+' '/:/{if($1!~\"lo\" && NF>2){sum+=$3}} END{printf \"%.0f\\n\", sum+0}' /proc/net/dev",
        )

    @staticmethod
    def _render_progress_bar(percent: float, width: int = 24) -> str:
        normalized = max(0.0, min(100.0, percent))
        filled = int((normalized / 100.0) * width)
        return "[" + ("#" * filled) + ("-" * (width - filled)) + "]"

    @staticmethod
    def _apt_progress_from_line(line: str) -> Optional[Tuple[float, str]]:
        match = re.match(r"^(?:dlstatus|pmstatus):[^:]*:([0-9]+(?:\.[0-9]+)?):(.*)$", line)
        if not match:
            return None
        percentage = float(match.group(1))
        detail = " ".join(match.group(2).split())
        return percentage, detail

    @classmethod
    def _apt_progress_fallback_from_line(cls, line: str) -> Optional[Tuple[float, str]]:
        size_match = re.search(
            r"([0-9]+(?:\.[0-9]+)?)\s*([kmg]b)/([0-9]+(?:\.[0-9]+)?)\s*([kmg]b)",
            line,
            flags=re.IGNORECASE,
        )
        if size_match:
            current_value = float(size_match.group(1))
            current_unit = size_match.group(2).lower()
            total_value = float(size_match.group(3))
            total_unit = size_match.group(4).lower()
            current_bytes = cls._to_bytes(current_value, current_unit)
            total_bytes = cls._to_bytes(total_value, total_unit)
            if total_bytes > 0:
                percentage = (current_bytes / total_bytes) * 100.0
                return percentage, " ".join(line.split())

        percent_match = re.search(r"\b([0-9]{1,3}(?:\.[0-9]+)?)%\b", line)
        if percent_match and any(
            token in line.lower() for token in ["working", "download", "fetch", "install"]
        ):
            return float(percent_match.group(1)), " ".join(line.split())

        return None

    @classmethod
    def _apt_total_bytes_from_line(cls, line: str) -> Optional[float]:
        for pattern in [
            r"Need to get\s+([0-9]+(?:\.[0-9]+)?)\s*([kmgte]?b)",
            r"\[\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgte]?b)\s*\]",
        ]:
            match = re.search(pattern, line, flags=re.IGNORECASE)
            if match:
                value = float(match.group(1))
                unit = match.group(2).lower()
                return cls._to_bytes(value, unit)
        return None

    @staticmethod
    def _apt_bytes_marker_from_line(line: str) -> Optional[float]:
        match = re.search(r"VOL3_DL_BYTES:([0-9]+)", line)
        if not match:
            return None
        return float(match.group(1))

    @staticmethod
    def _to_bytes(value: float, unit: str) -> float:
        units = {
            "b": 1.0,
            "kb": 1024.0,
            "mb": 1024.0 * 1024.0,
            "gb": 1024.0 * 1024.0 * 1024.0,
            "tb": 1024.0 * 1024.0 * 1024.0 * 1024.0,
        }
        return value * units.get(unit, 1.0)

    @staticmethod
    def _command_available(command_name: str) -> bool:
        return shutil.which(command_name) is not None

    def _docker_command_base(self) -> List[str]:
        return ["docker"]

    def _docker_with_platform(self, base: List[str], action: str) -> List[str]:
        command = list(base)
        command.append(action)
        platform = (self.config.get("docker_platform") or "").strip()
        if not platform:
            active_arch = getattr(self, "_active_architecture", "")
            platform_map = {
                "amd64": "linux/amd64",
                "386": "linux/386",
                "arm64": "linux/arm64",
                "arm": "linux/arm/v7",
            }
            platform = platform_map.get(active_arch, "")
        if platform and action in ("run", "create"):
            command.extend(["--platform", platform])
        return command

    def _docker_pull_if_needed(self, image: str) -> Tuple[bool, str]:
        if not self.config.get("docker_auto_pull", True):
            return True, ""

        pulled = getattr(self, "_pulled_images", None)
        if pulled is None:
            pulled = set()
            setattr(self, "_pulled_images", pulled)
        if image in pulled:
            return True, ""

        self._log_progress(f"Pulling Docker image: {image}")
        command = self._docker_command_base() + ["pull", image]
        result = self._run_command(command, stream_output=True, output_prefix="pull> ")
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "docker pull failed").strip()
            return False, message
        pulled.add(image)
        self._log_progress(f"Pulled Docker image: {image}")
        return True, ""

    def _build_isf_with_go_fallback(
        self, elf_path: str, map_path: Optional[str], output_path: str
    ) -> Tuple[bool, str]:
        if not self._command_available("docker"):
            return False, "docker command not found"

        go_image = (self.config.get("dwarf2json_go_fallback_image") or "").strip()
        if not go_image:
            return False, "dwarf2json_go_fallback_image is empty"

        pulled_ok, pull_message = self._docker_pull_if_needed(go_image)
        if not pulled_ok:
            return False, f"Go fallback image pull failed: {pull_message}"

        self._log_progress(
            f"Using Go fallback to build dwarf2json in container image: {go_image}"
        )

        with tempfile.TemporaryDirectory(prefix="vol3-dwarf2json-go-") as work_dir:
            in_elf = os.path.join(work_dir, "vmlinux")
            shutil.copy2(elf_path, in_elf)

            in_map = ""
            if map_path:
                in_map = os.path.join(work_dir, "System.map")
                shutil.copy2(map_path, in_map)

            out_json = os.path.join(work_dir, "isf.json")
            script_lines = [
                "set -e",
                "export PATH=\"/usr/local/go/bin:${PATH}\"",
                "export CGO_ENABLED=0",
                "if [ ! -x /tmp/dwarf2json ]; then",
                "  echo 'Building dwarf2json from source...';",
                "  GOBIN=/tmp go install github.com/volatilityfoundation/dwarf2json@latest;",
                "fi",
                "echo 'Running dwarf2json linux conversion...';",
                "if [ -f /work/System.map ]; then",
                "  /tmp/dwarf2json linux --elf /work/vmlinux --system-map /work/System.map > /work/isf.json;",
                "else",
                "  /tmp/dwarf2json linux --elf /work/vmlinux > /work/isf.json;",
                "fi",
            ]
            run_script = "\n".join(script_lines)

            command = self._docker_with_platform(self._docker_command_base(), "run")
            command.extend(
                [
                    "--rm",
                    "-v",
                    f"{work_dir}:/work",
                    go_image,
                    "sh",
                    "-lc",
                    run_script,
                ]
            )

            result = self._run_command(
                command,
                stream_output=True,
                output_prefix="go-fallback> ",
            )
            if result.returncode != 0:
                message = (
                    result.stderr
                    or result.stdout
                    or "Go fallback dwarf2json execution failed"
                ).strip()
                return False, self._shorten_message(message)

            if not os.path.exists(out_json) or os.path.getsize(out_json) == 0:
                return False, "Go fallback produced empty ISF output"

            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            shutil.copy2(out_json, output_path)
            return True, output_path

    def _docker_find_kernel_paths(
        self, container_id: str
    ) -> Tuple[List[str], List[str], Optional[str]]:
        script = (
            "find_system_map_for(){ "
            "  krel=\"$1\"; "
            "  for p in /boot/System.map-$krel /lib/modules/$krel/System.map /lib/modules/$krel/build/System.map; do "
            "    [ -e \"$p\" ] && { printf '%s' \"$p\"; return 0; }; "
            "  done; "
            "  printf ''; return 0; "
            "}; "
            "for p in "
            "/usr/lib/debug/boot/vmlinux* "
            "/usr/lib/debug/lib/modules/*/vmlinux "
            "/boot/vmlinux* "
            "/lib/modules/*/vmlinux; "
            "do "
            "  [ -e \"$p\" ] || continue; "
            "  printf 'ELF:%s\\n' \"$p\"; "
            "  b=$(basename \"$p\"); "
            "  krel=${b#vmlinux-}; "
            "  if [ \"$krel\" != \"$b\" ]; then "
            "    sm=$(find_system_map_for \"$krel\"); [ -n \"$sm\" ] && printf 'MAP:%s\\n' \"$sm\"; "
            "  fi; "
            "done; "
            "for p in /boot/System.map* /lib/modules/*/build/System.map /lib/modules/*/System.map; "
            "do [ -e \"$p\" ] && printf 'MAP:%s\\n' \"$p\"; done; "
            "exit 0"
        )
        command = self._docker_command_base() + [
            "exec",
            container_id,
            "sh",
            "-lc",
            script,
        ]
        result = self._run_command(command)
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            return [], [], stderr or "docker exec failed"

        elf_paths = []
        map_paths = []
        for line in (result.stdout or "").splitlines():
            if line.startswith("ELF:"):
                elf_paths.append(line[4:])
            elif line.startswith("MAP:"):
                map_paths.append(line[4:])
        return elf_paths, map_paths, None

    def _docker_copy_path(
        self, container_id: str, container_path: str, destination_path: str
    ) -> Tuple[bool, Optional[str]]:
        copied = self._run_command(
            self._docker_command_base()
            + ["cp", f"{container_id}:{container_path}", destination_path]
        )
        if copied.returncode != 0:
            return False, (copied.stderr or "").strip() or "docker cp failed"
        return True, None

    def _docker_create_running_container(self, image: str) -> Tuple[bool, str, str]:
        pulled_ok, pull_message = self._docker_pull_if_needed(image)
        if not pulled_ok:
            return False, "", pull_message

        self._log_progress(f"Creating working container from image: {image}")
        create_cmd = self._docker_with_platform(self._docker_command_base(), "create")
        create_cmd.extend([image, "sh", "-lc", "while true; do sleep 3600; done"])
        created = self._run_command(create_cmd)
        if created.returncode != 0:
            error_output = (created.stderr or created.stdout or "").strip()
            # Retry once if the failure looks like a corrupted local layer
            if "failed to extract layer" in error_output or "content digest" in error_output:
                self._log_progress(
                    f"Docker layer corruption detected for {image}, removing and re-pulling"
                )
                self._run_command(self._docker_command_base() + ["rmi", "-f", image])
                # Clear the pull cache so _docker_pull_if_needed actually pulls again
                pulled = getattr(self, "_pulled_images", None)
                if pulled and image in pulled:
                    pulled.discard(image)
                re_pulled_ok, re_pull_msg = self._docker_pull_if_needed(image)
                if not re_pulled_ok:
                    return False, "", f"Re-pull after layer corruption failed: {re_pull_msg}"
                create_cmd = self._docker_with_platform(self._docker_command_base(), "create")
                create_cmd.extend([image, "sh", "-lc", "while true; do sleep 3600; done"])
                created = self._run_command(create_cmd)
                if created.returncode != 0:
                    message = (created.stderr or created.stdout or "docker create failed after re-pull").strip()
                    return False, "", message
            else:
                return False, "", error_output or "docker create failed"

        container_id = (created.stdout or "").strip()
        if not container_id:
            return False, "", "docker create did not return a container id"

        self._log_progress(f"Starting working container: {container_id[:12]}")
        started = self._run_command(self._docker_command_base() + ["start", container_id])
        if started.returncode != 0:
            message = (started.stderr or started.stdout or "docker start failed").strip()
            self._run_command(self._docker_command_base() + ["rm", "-f", container_id])
            return False, "", message

        return True, container_id, ""

    def _docker_remove_container(self, container_id: str) -> None:
        self._log_progress(f"Removing container: {container_id[:12]}")
        self._run_command(self._docker_command_base() + ["rm", "-f", container_id])

    def _docker_prepare_kernel_packages(
        self, container_id: str, distribution: str, kernel_release: str
    ) -> Optional[str]:
        if not self.config.get("docker_prepare_kernel_packages", True):
            return None

        safe_kernel = shlex.quote(kernel_release)

        self._log_progress(
            f"Preparing kernel packages in container {container_id[:12]} "
            f"for {distribution} {kernel_release}"
        )

        if distribution in ("ubuntu", "debian"):
            script = (
                "export DEBIAN_FRONTEND=noninteractive; "
                "export LC_ALL=C; "
                "try_extract_vmlinux(){ "
                "  src=\"$1\"; out=\"$2\"; "
                "  command -v zcat >/dev/null 2>&1 || return 1; "
                "  command -v cpio >/dev/null 2>&1 || return 1; "
                "  command -v xz >/dev/null 2>&1 || return 1; "
                "  rm -f \"$out\"; "
                "  tmpd=$(mktemp -d 2>/dev/null || mktemp -d -t vol3); "
                "  if zcat \"$src\" 2>/dev/null | (cd \"$tmpd\" && cpio -id --quiet) >/dev/null 2>&1; then "
                "    cand=$(find \"$tmpd\" -type f \\( -name vmlinux -o -name 'vmlinux-*' \\) 2>/dev/null | head -n 1); "
                "    if [ -n \"$cand\" ] && [ -f \"$cand\" ]; then "
                "      cp -f \"$cand\" \"$out\" 2>/dev/null || true; "
                "    fi; "
                "  fi; "
                "  rm -rf \"$tmpd\" >/dev/null 2>&1 || true; "
                "  [ -s \"$out\" ]; "
                "}; "
                "( while true; do "
                "  bytes=$(du -sb /var/cache/apt/archives 2>/dev/null | awk '{print $1}'); "
                "  [ -n \"$bytes\" ] && echo \"VOL3_DL_BYTES:${bytes}\"; "
                "  sleep 2; "
                "done ) & VOL3_MON_PID=$!; "
                "cleanup_mon(){ kill \"$VOL3_MON_PID\" >/dev/null 2>&1 || true; }; "
                "trap cleanup_mon EXIT; "
                "APT_OPTS='-o APT::Status-Fd=1 -o Dpkg::Progress-Fancy=0'; "
                "if ! command -v apt-get >/dev/null 2>&1; then exit 0; fi; "
                "apt-get $APT_OPTS update || true; "
                "apt-get $APT_OPTS install -y --no-install-recommends ca-certificates gnupg wget cpio xz-utils || true; "
                "if grep -qi ubuntu /etc/os-release 2>/dev/null; then "
                "  apt-get $APT_OPTS install -y --no-install-recommends ubuntu-dbgsym-keyring || true; "
                "  codename=$( . /etc/os-release 2>/dev/null; printf '%s' \"${VERSION_CODENAME}\" ); "
                "  if [ -n \"$codename\" ]; then "
                "    printf 'deb http://ddebs.ubuntu.com %s main restricted universe multiverse\\n' \"$codename\" > /etc/apt/sources.list.d/ddebs.list; "
                "    printf 'deb http://ddebs.ubuntu.com %s-updates main restricted universe multiverse\\n' \"$codename\" >> /etc/apt/sources.list.d/ddebs.list; "
                "    printf 'deb http://ddebs.ubuntu.com %s-proposed main restricted universe multiverse\\n' \"$codename\" >> /etc/apt/sources.list.d/ddebs.list; "
                "  fi; "
                "  apt-get $APT_OPTS update || true; "
                "fi; "
                f"krel={safe_kernel}; "
                "installed=0; "
                "for pkg in \"linux-image-unsigned-${krel}-dbgsym\" \"linux-image-${krel}-dbgsym\" \"linux-image-${krel}-dbg\" \"linux-image-${krel}\" \"linux-image-unsigned-${krel}\"; do "
                "  echo \"trying package: $pkg\"; "
                "  apt-get $APT_OPTS install -y --no-install-recommends \"$pkg\" && installed=1 && break || true; "
                "done; "
                "if [ $installed -eq 1 ]; then "
                "  if [ -L /boot/vmlinuz ]; then "
                "    tgt=$(readlink -f /boot/vmlinuz || true); "
                "    [ -n \"$tgt\" ] && cp -f \"$tgt\" /boot/vmlinux-$krel || true; "
                "    if [ ! -s /boot/vmlinux-$krel ] && [ -n \"$tgt\" ]; then "
                "      try_extract_vmlinux \"$tgt\" /boot/vmlinux-$krel && echo 'extracted uncompressed vmlinux from vmlinuz' || true; "
                "    fi; "
                "  fi; "
                "  if [ -f /usr/lib/debug/boot/vmlinux-$krel ]; then cp -f /usr/lib/debug/boot/vmlinux-$krel /boot/vmlinux-$krel || true; fi; "
                "fi; "
                "if [ $installed -eq 0 ]; then echo 'no kernel package installed'; fi; "
                "cleanup_mon; "
                "exit 0"
            )
        elif distribution == "archlinux":
            script = (
                "if ! command -v pacman >/dev/null 2>&1; then exit 0; fi; "
                "pacman -Sy --noconfirm || true; "
                "pacman -S --noconfirm linux linux-debug || true; "
                "exit 0"
            )
        else:
            return None

        result = self._run_command(
            self._docker_command_base() + ["exec", container_id, "sh", "-lc", script],
            stream_output=True,
            output_prefix="pkg> ",
        )
        if result.returncode != 0:
            return (result.stderr or result.stdout or "package preparation failed").strip()
        self._log_progress(f"Kernel package preparation finished: {container_id[:12]}")
        return None

    @staticmethod
    def _shorten_message(message: str, limit: int = 260) -> str:
        compact = " ".join((message or "").split())
        if len(compact) <= limit:
            return compact
        return compact[: limit - 3] + "..."

    @staticmethod
    def _safe_output_name(banner: str) -> str:
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        converted = []
        for char in banner:
            converted.append(char if char in allowed else "_")
        name = "".join(converted).strip("_")
        if not name:
            name = "linux_banner"
        return name[:160]

    @staticmethod
    def _normalize_banner_for_comparison(banner: str) -> str:
        """Extract structurally significant parts of a Linux banner for comparison.

        Ignores build date/time and build machine hostname, which don't affect
        kernel struct layouts.  What matters is kernel version, compiler version,
        build number, config flags, and package version.
        """
        # Remove trailing nulls/whitespace
        banner = banner.strip().rstrip("\x00").strip()

        # Extract components that actually affect struct layouts:
        # 1. Kernel version:  "Linux version 6.17.0-14-generic"
        # 2. GCC version:     "(x86_64-linux-gnu-gcc (Ubuntu 15.2.0-4ubuntu4) 15.2.0"
        # 3. Linker version:  "GNU ld (GNU Binutils for Ubuntu) 2.45)"
        # 4. Build number:    "#14" or "#14~24.04.1"
        # 5. Config flags:    "SMP PREEMPT_DYNAMIC"
        # 6. Package version: "(Ubuntu 6.17.0-14.14-generic 6.17.9)"

        parts = []

        # Kernel version
        m = re.search(r"Linux version\s+(\S+)", banner)
        if m:
            parts.append(f"kver={m.group(1)}")

        # GCC version (full compiler identification)
        m = re.search(r"\(([^)]*gcc[^)]*)\)\s+([0-9.]+)", banner)
        if m:
            parts.append(f"gcc={m.group(1).strip()}:{m.group(2)}")

        # Linker version
        m = re.search(r"GNU ld\s+\([^)]*\)\s+([0-9.]+)", banner)
        if m:
            parts.append(f"ld={m.group(1)}")

        # Build number and suffix (e.g., #14-Ubuntu or #14~24.04.1-Ubuntu)
        m = re.search(r"(#\S+)", banner)
        if m:
            parts.append(f"build={m.group(1)}")

        # Config flags (SMP, PREEMPT, PREEMPT_DYNAMIC, etc.)
        for flag in ("SMP", "PREEMPT_DYNAMIC", "PREEMPT_RT", "PREEMPT"):
            if flag in banner:
                parts.append(f"flag={flag}")

        # Package version at the end: (Ubuntu 6.17.0-14.14-generic 6.17.9)
        # Use [^)\s]+ instead of \S+ to avoid consuming stray ')' chars.
        # Take the LAST match — earlier "(Ubuntu ...)" groups are compiler
        # version strings (e.g. "Ubuntu 15.2.0-4ubuntu4"), not the package.
        pkg_matches = list(re.finditer(
            r"\(Ubuntu\s+([^)\s]+(?:\s+[^)\s]+)?)\)", banner
        ))
        if pkg_matches:
            parts.append(f"pkg={pkg_matches[-1].group(1)}")

        return "|".join(sorted(parts))

    @staticmethod
    def _verify_isf_banner(isf_path: str, expected_banner: str) -> Tuple[bool, str]:
        """Check that the ISF's embedded linux_banner matches the memory dump banner.

        Returns (match, message).  When match is False the ISF was built from a
        different kernel build and should be discarded.

        Uses a structural comparison that ignores build date/time and build
        machine hostname, since those don't affect kernel struct layouts.
        """
        try:
            with open(isf_path, "r") as fh:
                isf = json.load(fh)
        except Exception as exc:
            return False, f"Failed to read ISF for banner check: {exc}"

        constant_data = (
            isf.get("symbols", {}).get("linux_banner", {}).get("constant_data")
        )
        if not constant_data:
            return False, "ISF has no linux_banner constant_data"

        try:
            isf_banner_bytes = base64.b64decode(constant_data)
            isf_banner = isf_banner_bytes.decode("latin-1").strip().rstrip("\x00")
        except Exception as exc:
            return False, f"Failed to decode ISF linux_banner: {exc}"

        # Normalise: strip trailing whitespace / nulls from both sides
        norm_expected = expected_banner.strip().rstrip("\x00")
        norm_isf = isf_banner.strip().rstrip("\x00")

        # 1. Exact match
        if norm_expected == norm_isf:
            return True, "ISF banner matches memory dump banner (exact)"

        # 2. Structural match — ignore build date/hostname
        struct_expected = GiveMeLinuxISF._normalize_banner_for_comparison(norm_expected)
        struct_isf = GiveMeLinuxISF._normalize_banner_for_comparison(norm_isf)

        if struct_expected == struct_isf:
            vollog.info(
                f"[GiveMeLinuxISF] Banner structural match (date/host differ): "
                f"memory='{norm_expected}' isf='{norm_isf}'"
            )
            return True, "ISF banner matches memory dump banner (structural match, build date/host ignored)"

        # 3. Mismatch — log full banners for debugging
        vollog.info(
            f"[GiveMeLinuxISF] Banner mismatch detail:\n"
            f"  memory: {norm_expected}\n"
            f"  isf:    {norm_isf}\n"
            f"  struct_memory: {struct_expected}\n"
            f"  struct_isf:    {struct_isf}"
        )

        return False, (
            f"ISF banner mismatch:\n"
            f"  memory: {norm_expected}\n"
            f"  ISF:    {norm_isf}"
        )

    def _build_isf_with_dwarf2json_container(
        self, elf_path: str, map_path: Optional[str], output_path: str
    ) -> Tuple[bool, str]:
        if not self._command_available("docker"):
            return False, "docker command not found"

        self._log_progress("Using Docker-installed dwarf2json path (Go build in container)")
        built, message = self._build_isf_with_go_fallback(
            elf_path, map_path, output_path
        )
        if built:
            self._log_progress("Docker-installed dwarf2json produced a usable ISF")
            return True, message
        return False, message

    def _generate_via_docker(
        self,
        banner: str,
        symbols_path: str,
        image: str,
        kernel_release: str,
        distribution: str,
        architecture: str,
    ) -> Tuple[bool, str, str]:
        self._active_architecture = architecture
        created_ok, container_id, create_message = self._docker_create_running_container(
            image
        )
        if not created_ok:
            return False, "", self._shorten_message(create_message)

        try:
            self._log_progress(
                f"Searching kernel files in image {image} for banner kernel {kernel_release}"
            )
            prepare_message = self._docker_prepare_kernel_packages(
                container_id, distribution, kernel_release
            )
            elf_paths, map_paths, error = self._docker_find_kernel_paths(container_id)
            if error:
                return False, "", self._shorten_message(error)
            if not elf_paths:
                detail = "No vmlinux-like file found in container"
                if prepare_message:
                    detail = f"{detail}; prep: {prepare_message}"
                return False, "", self._shorten_message(detail)

            with tempfile.TemporaryDirectory(prefix="vol3-linux-kernel-") as temp_dir:
                selected_elf = elf_paths[0]
                self._log_progress(
                    f"Found vmlinux candidate: {selected_elf} (container {container_id[:12]})"
                )
                local_elf = os.path.join(
                    temp_dir, os.path.basename(selected_elf) or "vmlinux"
                )
                copied, copy_error = self._docker_copy_path(
                    container_id, selected_elf, local_elf
                )
                if not copied:
                    return False, "", self._shorten_message(
                        copy_error or "Failed to copy ELF from Docker"
                    )

                local_map = None
                if map_paths:
                    selected_map = map_paths[0]
                    self._log_progress(
                        f"Found System.map candidate: {selected_map}"
                    )
                    local_map = os.path.join(
                        temp_dir, os.path.basename(selected_map) or "System.map"
                    )
                    copied, copy_error = self._docker_copy_path(
                        container_id, selected_map, local_map
                    )
                    if not copied:
                        local_map = None

                kernel_fragment = kernel_release if kernel_release else "unknown_kernel"
                distro_fragment = distribution if distribution else "unknown_distro"
                arch_fragment = architecture if architecture else "unknown_arch"
                out_name = (
                    self._safe_output_name(
                        f"{distro_fragment}_{kernel_fragment}_{arch_fragment}_{banner}"
                    )
                    + ".json"
                )
                out_path = os.path.join(symbols_path, out_name)
                built, message = self._build_isf_with_dwarf2json_container(
                    local_elf, local_map, out_path
                )
                if not built:
                    return False, out_path, self._shorten_message(message)

                # Verify the ISF's embedded banner matches the memory dump
                banner_ok, banner_msg = self._verify_isf_banner(out_path, banner)
                if not banner_ok:
                    self._log_progress(
                        f"ISF banner verification failed for image {image}: {banner_msg}"
                    )
                    try:
                        os.remove(out_path)
                    except OSError:
                        pass
                    return False, "", self._shorten_message(
                        f"Banner mismatch from {image}: {banner_msg}"
                    )

                self._log_progress("ISF banner verification passed")
                return (
                    True,
                    out_path,
                    f"Generated ISF in Docker and copied ready JSON (image: {image})",
                )
        finally:
            self._docker_remove_container(container_id)

    def _select_docker_images(
        self, distribution: str, architecture: str, banner: str = ""
    ) -> List[str]:
        configured_single = (self.config.get("docker_image") or "").strip()
        configured_many = self._parse_csv_config(self.config.get("docker_images") or "")
        if configured_single:
            configured_many = [configured_single] + configured_many

        guessed = self._candidate_docker_images(distribution, architecture, banner)
        max_auto_images = int(self.config.get("max_auto_images", 3))
        if max_auto_images < 0:
            max_auto_images = 0
        guessed = guessed[:max_auto_images]

        ordered = configured_many + guessed
        output = []
        for image in ordered:
            if image not in output:
                output.append(image)
        return output

    def _try_build_for_banner(
        self,
        banner: str,
        symbols_path: str,
        kernel_release: str,
        distribution: str,
        architecture: str,
    ) -> Tuple[bool, str, str]:
        if not self._command_available("docker"):
            return False, "", "docker command not found"

        images = self._select_docker_images(distribution, architecture, banner)
        if not images:
            return False, "", "No Docker image configured or guessed"

        self._log_progress(
            f"Trying {len(images)} Docker image(s) for {distribution} {kernel_release} {architecture}"
        )
        messages = []
        for idx, image in enumerate(images, start=1):
            self._log_progress(f"[{idx}/{len(images)}] Trying image: {image}")
            generated_ok, generated_path, generated_message = self._generate_via_docker(
                banner=banner,
                symbols_path=symbols_path,
                image=image,
                kernel_release=kernel_release,
                distribution=distribution,
                architecture=architecture,
            )
            if generated_ok:
                return True, generated_path, generated_message
            messages.append(f"{image}: {self._shorten_message(generated_message)}")

        return False, "", " ; ".join(messages)

    def _validate_with_linux_psscan(self) -> Tuple[bool, str]:
        try:
            from volatility3.plugins.linux import psscan as linux_psscan

            psscan_plugin = linux_psscan.PsScan
        except Exception as excp:
            return False, f"Unable to import linux.psscan: {excp}"

        try:
            available_automagics = automagic.available(self.context)
            chosen_automagics = automagic.choose_automagic(available_automagics, psscan_plugin)
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
                return False, "linux.psscan returned 0 processes (symbols may not match this memory image)"
            return True, f"linux.psscan validation passed (rows={row_count})"
        except exceptions.UnsatisfiedException as excp:
            details = ", ".join(str(item) for item in excp.unsatisfied)
            return False, f"linux.psscan unsatisfied: {details}"
        except Exception as excp:
            return False, f"linux.psscan validation failed: {excp}"

    def _generator(self):
        symbols_path = self._ensure_directory(self.config.get("symbols_path"))
        layer_name = self._get_scan_layer_name()
        self._log_progress(f"Scanning Linux banners from layer: {layer_name}")
        linux_banners = self._collect_linux_banners(layer_name)

        self._log_progress(f"Found {len(linux_banners)} Linux banner candidate(s)")

        if not linux_banners:
            self._log_overall_progress(1, 1, "no Linux banners found")
            yield (
                0,
                (
                    format_hints.Hex(0),
                    "",
                    "",
                    "unknown",
                    "unknown",
                    "none",
                    "",
                    "failed",
                    "No Linux banner found in memory layer",
                ),
            )
            return

        local_identifiers = self._load_local_linux_identifiers()
        total_banners = len(linux_banners)
        processed = 0
        self._log_overall_progress(0, total_banners, "start")

        for idx, (offset, banner) in enumerate(linux_banners, start=1):
            kernel_release = self._infer_kernel_release(banner)
            distribution = self._infer_distribution(banner)
            architecture = self._infer_architecture(banner, kernel_release)

            self._log_progress(
                f"[{idx}/{len(linux_banners)}] Processing banner: "
                f"kernel={kernel_release or 'unknown'} distro={distribution} arch={architecture}"
            )

            local_symbol = self._find_local_symbol(local_identifiers, banner)
            if local_symbol:
                self._log_progress(f"Local symbol already available: {local_symbol}")
                yield (
                    0,
                    (
                        offset,
                        banner,
                        kernel_release,
                        distribution,
                        architecture,
                        "local",
                        local_symbol,
                        "ready",
                        "Matching local symbol file found",
                    ),
                )
                processed += 1
                self._log_overall_progress(
                    processed,
                    total_banners,
                    f"banner {idx}/{total_banners}: local symbol",
                )
                continue

            if self.config.get("auto_build", True):
                try:
                    generated_ok, generated_path, generated_message = self._try_build_for_banner(
                        banner=banner,
                        symbols_path=symbols_path,
                        kernel_release=kernel_release,
                        distribution=distribution,
                        architecture=architecture,
                    )
                except Exception as excp:
                    generated_ok = False
                    generated_path = ""
                    generated_message = f"Unexpected build error: {excp}"
                if generated_ok:
                    self._log_progress(f"ISF generation succeeded: {generated_path}")
                    local_identifiers = self._load_local_linux_identifiers()
                    local_symbol = self._find_local_symbol(local_identifiers, banner)
                    symbol_path = local_symbol or generated_path
                    validation_status = "generated"
                    validation_message = generated_message
                    if self.config.get("validate_psscan", True):
                        self._log_progress("Validating generated symbols with linux.psscan")
                        valid_ok, valid_message = self._validate_with_linux_psscan()
                        if valid_ok:
                            validation_status = "validated"
                            validation_message = f"{generated_message}; {valid_message}"
                            self._log_progress(
                                "linux.psscan validation passed, stopping further banner downloads"
                            )
                            yield (
                                0,
                                (
                                    offset,
                                    banner,
                                    kernel_release,
                                    distribution,
                                    architecture,
                                    "docker",
                                    symbol_path,
                                    validation_status,
                                    validation_message,
                                ),
                            )
                            processed += 1
                            self._log_overall_progress(
                                processed,
                                total_banners,
                                f"banner {idx}/{total_banners}: validated",
                            )
                            return

                        self._log_progress(
                            f"linux.psscan validation failed, continuing: {valid_message}"
                        )
                        validation_status = "failed"
                        validation_message = (
                            f"{generated_message}; psscan validation failed: {valid_message}"
                        )
                    yield (
                        0,
                        (
                            offset,
                            banner,
                            kernel_release,
                            distribution,
                            architecture,
                            "docker",
                            symbol_path,
                            validation_status,
                            validation_message,
                        ),
                    )
                    processed += 1
                    self._log_overall_progress(
                        processed,
                        total_banners,
                        f"banner {idx}/{total_banners}: generated",
                    )
                    continue
                failure_message = generated_message
            else:
                failure_message = "auto_build disabled"

            self._log_progress(
                f"ISF generation failed for banner {idx}/{len(linux_banners)}: {failure_message}"
            )

            yield (
                0,
                (
                    offset,
                    banner,
                    kernel_release,
                    distribution,
                    architecture,
                    "docker",
                    "",
                    "failed",
                    self._shorten_message(failure_message),
                ),
            )
            processed += 1
            self._log_overall_progress(
                processed,
                total_banners,
                f"banner {idx}/{total_banners}: failed",
            )

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Banner", str),
                ("Kernel Release", str),
                ("Distribution", str),
                ("Architecture", str),
                ("Source", str),
                ("Symbol File", str),
                ("Status", str),
                ("Message", str),
            ],
            self._generator(),
        )
