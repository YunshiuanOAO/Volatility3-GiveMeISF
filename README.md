# GiveMeISF

Volatility 3 plugins that automatically obtain matching ISF symbol tables for a
memory image — so you don't have to hunt down a kernel/PDB by hand before you
can run `linux.psscan` or `windows.psscan`.

| Plugin | Target | How it gets symbols |
| --- | --- | --- |
| `GiveMeLinuxISF` | Linux memory image | Scans `Linux version …` banner → spins up a matching distro Docker container → installs `linux-image[-dbgsym]` → extracts `vmlinux` + `System.map` → builds ISF in-container with `dwarf2json` (Go) |
| `GiveMeWindowsISF` | Windows memory image | Scans for kernel `RSDS` records → calls Volatility 3's built-in `PDBUtility.download_pdb_isf` to fetch the PDB from the Microsoft Symbol Server and convert to ISF |


## Demo

Linux :

<video src="assets/Linuxdemo.mp4" controls width="720">
  Your viewer doesn't support inline video — see
  <a href="assets/Linuxdemo.mp4">assets/Linuxdemo.mp4</a>.
</video>


Both plugins also (optionally) verify the resulting ISF by running the platform's
`psscan` plugin in-process.

## Requirements

Common:
- Volatility 3 ≥ 2.0.0 installed and importable (`vol.py` on `$PATH` or `volatility3` on `$PYTHONPATH`).

`GiveMeLinuxISF`:
- Working `docker` CLI with permission to pull images and run containers.
- Network access for the chosen distro mirrors and `golang:1.24` (default Go
  fallback used to build `dwarf2json` inside the container).

`GiveMeWindowsISF`:
- Network access to `msdl.microsoft.com` (or your override).
- Nothing else — PDB download and ISF conversion both run in pure Python via
  `volatility3.framework.symbols.windows.pdbconv`.

## Install

Drop the plugins into Volatility 3's plugin search path:

```bash

# copy into the corresponding category directory
cp "$(pwd)/GiveMeLinuxISF.py"   /path/to/volatility3/volatility3/framework/plugins/linux/

ln -s "$(pwd)/GiveMeWindowsISF.py" /path/to/volatility3/volatility3/framework/plugins/windows/

# symlink into the corresponding category directory
ln -s "$(pwd)/GiveMeLinuxISF.py"   /path/to/volatility3/volatility3/framework/plugins/linux/
ln -s "$(pwd)/GiveMeWindowsISF.py" /path/to/volatility3/volatility3/framework/plugins/windows/

# or load them ad-hoc
vol.py -p "$(pwd)" ...
```

After install they show up as:

- `linux.GiveMeLinuxISF.GiveMeLinuxISF`
- `windows.GiveMeWindowsISF.GiveMeWindowsISF`

## Usage

### Linux

```bash
vol.py -f memory.lime linux.GiveMeLinuxISF.GiveMeLinuxISF
```

Common config overrides (prefix with `--giveMeLinuxISF.<name>`):

| Option | Default | Notes |
| --- | --- | --- |
| `auto_build` | `True` | Set `False` to only check local symbol cache, no Docker work |
| `symbols_path` | `<vol3 symbols>/linux` | Where the generated ISF JSON is written |
| `docker_image` | — | Single image override |
| `docker_images` | — | CSV of images to try in order |
| `docker_platform` | auto from banner arch | e.g. `linux/amd64` |
| `dwarf2json_go_fallback_image` | `golang:1.24` | Image used to build `dwarf2json` |
| `docker_prepare_kernel_packages` | `True` | Run `apt`/`pacman` inside container to install matching `linux-image[-dbgsym]` |
| `max_auto_images` | `3` | Cap on guessed image candidates per banner |
| `validate_psscan` | `True` | Run `linux.psscan` after building to confirm the ISF actually works |

Output columns: `Offset | Banner | Kernel Release | Distribution | Architecture | Source | Symbol File | Status | Message`.

`Status` values: `ready` (already cached locally), `generated` (built via Docker), `validated` (built and `linux.psscan` passed), `failed`.

The plugin returns early as soon as one banner produces a `validated` ISF.

### Windows

```bash
vol.py -f memory.dmp windows.GiveMeWindowsISF.GiveMeWindowsISF
```

Config overrides (prefix with `--giveMeWindowsISF.<name>`):

| Option | Default | Notes |
| --- | --- | --- |
| `auto_build` | `True` | Set `False` to only consult local cache |
| `symbols_path` | `<vol3 symbols>/windows` | Informational; PDBUtility writes under `volatility3.symbols.__path__` |
| `symbol_server_url` | Microsoft MSDL | Override e.g. with an internal mirror |
| `validate_psscan` | `True` | Run `windows.psscan` after download |
| `kernel_pdb_names` | `ntkrnlmp,ntkrnlpa,ntkrpamp,ntoskrnl` | Override the list of kernel PDB names scanned for |

Output columns: `Offset | PDB Name | GUID | Age | MZ Offset | Source | Symbol File | Status | Message`.

`Status` values: `ready` (cached), `downloaded` (fetched from MSDL but psscan
validation skipped or failed), `validated` (downloaded and `windows.psscan`
passed), `failed`.

Because the Windows PDB↔ISF correspondence is exact (matched by GUID+age),
`Status: downloaded` with a populated `Symbol File` is still a successful
result. A failed `windows.psscan` validation usually points to the dump itself
(unsupported format, broken layer stacking) rather than the ISF.

## How it works (one-liner each)

`GiveMeLinuxISF`:
1. Memory scan for `Linux version …` banner → infer distro / kernel release / arch.
2. Pick Docker image (configured > guessed-from-banner).
3. In container: `apt-get install linux-image-${krel}[-dbgsym]` (or pacman equivalent), then locate `/boot/vmlinux-*` and `System.map-*`.
4. `docker cp` ELF + map out, run `dwarf2json linux` in `golang:1.24` container, write JSON to `symbols_path`.
5. Re-read symbol cache, optionally run `linux.psscan` to validate.

`GiveMeWindowsISF`:
1. `PDBUtility.pdbname_scan` for `ntkrnlmp.pdb` / `ntkrnlpa.pdb` / `ntkrpamp.pdb` / `ntoskrnl.pdb` RSDS records → `(GUID, age, pdb_name)`.
2. Cache lookup via `WindowsIdentifier.generate(pdb_name, GUID, age)`.
3. On miss, `PDBUtility.download_pdb_isf` fetches the PDB from MSDL and converts to `.json.xz` under `volatility3/symbols/windows/`.
4. Optionally run `windows.psscan` to validate.

## License

[MIT](LICENSE).

Note: Volatility 3 itself is licensed under VSL-v1.0. These plugins
`import volatility3.*` and so are arguably derivative works. MIT is fine for
personal/standalone use; if you want to upstream into Volatility 3 you'll
need to relicense to VSL-v1.0 to match the project.
