# Third-party notices

OpenVPN Dash Client uses the components below. The project's own license does
not replace their licenses. Copyright, license, attribution and NOTICE files
provided by the runtime wheels are retained with those packages in the Windows
installation. CPython's license is included with the embedded Python runtime.

The Windows distribution uses CPython 3.12.10, Pynsist 2.8 and NSIS. NSIS and
Pynsist are build tools; their use does not make this an official OpenVPN,
Python, NSIS or Pynsist distribution. OpenVPN Community and its driver/service
are installed separately and are not bundled.

## Runtime packages

Versions below correspond to the locked Windows dependencies for version 0.1.0.
Full license texts and any bundled component notices take precedence over this
summary.

| Package | Version | License |
| --- | --- | --- |
| aiohappyeyeballs | 2.7.1 | PSF-2.0 |
| aiohttp | 3.14.4 | Apache-2.0 and MIT (including llhttp) |
| aiosignal | 1.4.0 | Apache-2.0 |
| annotated-doc | 0.0.5 | MIT |
| anyio | 4.15.1 | MIT |
| attrs | 26.1.0 | MIT |
| certifi | 2026.7.22 | MPL-2.0 |
| cmd2 | 4.2.4 | MIT |
| colorama | 0.4.6 | BSD-3-Clause |
| frozenlist | 1.8.0 | Apache-2.0 |
| h11 | 0.16.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| httpx | 0.28.1 | BSD-3-Clause |
| idna | 3.20 | BSD-3-Clause |
| linkify-it-py | 2.2.0 | MIT |
| markdown-it-py | 4.2.0 | MIT, including upstream markdown-it notices |
| mdit-py-plugins | 0.6.1 | MIT, with individual plugin notices |
| mdurl | 0.1.2 | MIT |
| multidict | 6.9.1 | Apache-2.0 |
| platformdirs | 4.12.4 | MIT |
| prompt_toolkit | 3.0.53 | BSD-3-Clause |
| propcache | 0.5.4 | Apache-2.0 |
| psutil | 7.2.2 | BSD-3-Clause |
| pycountry | 26.2.16 | LGPL-2.1; see below |
| Pygments | 2.21.0 | BSD-2-Clause |
| pyperclip | 1.11.0 | BSD-3-Clause |
| python-dotenv | 1.2.4 | BSD-3-Clause |
| pywin32 | 312 | PSF and component-specific licenses |
| rich | 15.0.0 | MIT |
| rich-argparse | 1.8.0 | MIT |
| shellingham | 1.5.4 | ISC |
| textual | 8.2.8 | MIT |
| typer | 0.27.3 | MIT, including vendored Click BSD-3-Clause |
| typing_extensions | 4.16.0 | PSF-2.0 |
| wcwidth | 0.9.2 | MIT |
| yarl | 1.25.1 | Apache-2.0 |

## pycountry and corresponding source

This application uses the unmodified pycountry library at runtime. Its package
metadata declares LGPL-2.1-only. The library's original COPYRIGHT.txt also
contains its contributor acknowledgements and the notice for data and
translations from Debian iso-codes under LGPL 2.1. These notices and the license
are retained. See [pycountry 26.2.16](https://pypi.org/project/pycountry/26.2.16/)
and the [upstream source](https://github.com/pycountry/pycountry/tree/26.2.16).

The installed library remains a separate Python package. You may modify or
replace it with an interface-compatible version, and debug such modifications.
The source for this application, dependency lockfile and build script are
available in this repository; these terms do not restrict rights granted by the
library's license.

The Release provides the locked upstream source distribution and corresponding
build/data sources beside the installer. Copies are also placed in
`licenses/dependency-sources` in the installation. Source archives are provided
as received from upstream; they are not relicensed under this project's license.

| Upstream source archive | SHA-256 |
| --- | --- |
| pycountry-26.2.16.tar.gz | `5b6027d453fcd6060112b951dd010f01f168b51b4bf8a1f1fc8c95c8d94a0801` |
| certifi-2026.7.22.tar.gz | `741e2c3b351ddf169a738da9f2c048608ff7f2c5cc02f1ebc6b118bb090d5d55` |
| pycountry-26.2.16-git-source.tar.gz | `db064d7c4656deb38279755c67f9eeed759705c711c2ed362e9f0cf336518bb0` |
| iso-codes_4.20.1.orig.tar.xz | `5d551f3ddb32548c4321e9011720fd97751af0107592f79ebffc939bd32f2268` |

The pycountry build source corresponds to upstream commit
`4ba3951667c2ed98363a3640c9022cf1b7a59300`. Its generator pins iso-codes v4.20.1.
The accompanying Debian source archive supplies the ISO JSON and editable PO
translation files used by that generator. These are included because the PyPI
source distribution contains generated MO translation files.

## certifi source

certifi and its Mozilla CA bundle are distributed under MPL 2.0. The unmodified
source archive listed above is included beside the installer and in the
installation's source directory. The upstream project is
[certifi/python-certifi](https://github.com/certifi/python-certifi), and its
[license](https://www.mozilla.org/en-US/MPL/2.0/) continues to apply.

## Rebuilding

The build script uses `uv.lock` for runtime versions and verifies the hashes of
dependency source archives. When updating dependencies, review their actual
wheel license files, preserve copyright and NOTICE files, and update this list
and the accompanying source archives together.
