# Zeus Banking Trojan (2013) — Static, Dynamic, & Network-Based Analysis

<p align="center">
  <img src="https://img.shields.io/badge/Sample-Zeus_Banking_Trojan_2013-critical?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Static-IDA_Pro_%2B_Cutter_%2B_FLOSS_%2B_Pestudio-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Dynamic-Procmon_%2B_Procdot_%2B_Wireshark_%2B_FakeNet--NG-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Framework-MITRE_ATT%26CK_%2B_MAEC-red?style=for-the-badge" />
</p>

> **⚠️ WARNING:** This repository analyzes a live malware sample. The sample itself is not stored here. If you intend to replicate this analysis, use only isolated virtual machines with no network connectivity to production systems. See the sample source below.

---

## Overview

This repository documents a complete technical analysis of a 2013 variant of the Zeus Banking Trojan — one of the most historically significant pieces of financial malware ever created, and the direct ancestor of TrickBot, Dridex, and QakBot.

The analysis spans three phases: static examination of the binary using PE analysis tools and disassemblers, dynamic execution monitoring in a controlled Windows 10 environment, and network traffic analysis via packet capture and DNS emulation. The goal was to characterize what this sample does, how it evades detection, and what indicators it leaves behind — grounded in evidence at every step.

**Sample:** `invoice_2318362983713_823931342io.pdf.exe`
**Source:** [theZoo Malware Repository](https://github.com/ytisf/theZoo/tree/master/malware/Binaries/ZeusBankingVersion_26Nov2013) (password: `infected`)
**Compilation timestamp:** 2013-11-25 10:32:03 UTC
**Analysis date:** December 2025

---

## Sample Identification

| Attribute | Value |
|---|---|
| **Filename** | `invoice_2318362983713_823931342io.pdf.exe` |
| **File type** | PE32 executable (GUI), Intel 80386, Windows |
| **Size** | 252,928 bytes (~247 KB) |
| **MD5** | `ea039a854d20d7734c5add48f1a51c34` |
| **SHA1** | `9615dca4c0e46b8a39de5428af7db060399230b2` |
| **SHA256** | `69e966e730557fde8fd84317cdef1ece00a8bb3470c0b58f3231e170168af169` |
| **Compiler** | MSVC 16.0 (Visual Studio 2010) |
| **Entropy** | 6.982 (unpacked — no packer confirmed) |
| **Signing status** | Unsigned — no valid code-signing certificate |
| **PE sections** | 6 (.text, .data, .rsrc + others) |

**Initial vector:** Double-extension masquerading — the filename embeds `.pdf` before `.exe`. On Windows systems with "hide known file extensions" enabled (the default), this file displays as a PDF document.

---

## Methodology

Analysis was structured across four phases:

**Phase 1 — Identification:** File properties, MAC timestamps, cryptographic hashes, packer/compiler detection, PE signing status, OSINT correlation across threat intelligence platforms.

**Phase 2 — Capability Assessment:** Capability characterization using the MAEC framework, cross-referenced to MITRE ATT&CK techniques. Informed by static import analysis and OSINT behavioral sandbox data.

**Phase 3 — Static Analysis:** Two-tier approach — automated tooling (FLOSS string extraction, CAPA behavioral detection, PE structure analysis) followed by manual disassembly in IDA Pro with cross-validation in Cutter where IDA encountered recognition limitations.

**Phase 4 — Dynamic Analysis:** Controlled execution in an isolated Windows 10 VM. Procmon and Procdot for file/registry/process monitoring, Wireshark and FakeNet-NG for network traffic capture, Regshot for registry delta comparison. No live network connectivity.

---

## Key Findings

### Social Engineering & Initial Execution
The malware presents a fabricated UAC elevation prompt displaying "Adobe Flash Player" with a spoofed verified publisher field ("Adobe Systems Incorporated"). Upon elevation, it displays a fake installer error dialog — a decoy while the payload executes silently in the background. When run with explicit admin privileges, Windows surfaces the actual filename and "Unknown" publisher, confirming the spoofing applies only to standard UAC behavior.

### File System Operations
Immediately post-execution, the original binary self-deletes without creating a Recycle Bin entry. A 87.1 KB copy is dropped to `%LOCALAPPDATA%\Temp\InstallFlashPlayer.exe` with the Hidden attribute enabled and fabricated Adobe version information. An 18-minute gap between creation and modification timestamps indicates additional writes after the initial drop — likely configuration or state data.

### Registry Behavior
The malware modifies four Internet Explorer ZoneMap registry keys (`ProxyBypass`, `IntranetName`, `UNCAsIntranet`, `AutoDetect`) under `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap`, reducing browser security posture to facilitate future credential interception. Extensive reconnaissance activity was observed — thousands of `RegQueryValue` and `RegOpenKey` operations targeting cryptography stores, Winsock parameters, session manager configuration, and debugger settings.

### Network Activity
- DNS query to `j.maxmind.com` via Google's public resolver (8.8.8.8:53) — confirming geolocation fingerprinting of the infected host
- HTTP GET to `j.maxmind.com/app/geoip.js` — active geolocation data retrieval
- HTTP GET to `fpdownload.macromedia.com` with `User-Agent: Flash Player Seed/3.0` — the dropped binary maintaining the Adobe installer cover story
- Malformed DNS traffic to `85.114.128.127:53` — likely obfuscated C2 probing or sandbox-detection behavior
- No DNS queries to `corect.com` (the hardcoded C2 domain from static analysis) — the original C2 infrastructure is defunct

### Static Analysis
FLOSS extracted 826 strings from the binary. A consistent pattern of randomized character sequences immediately preceding legitimate Windows API names was identified — a code-level obfuscation technique where each imported function is aliased to a nonsensical stub name (`RamilmiaputtHastJobs` → `KERNEL32.FindNextFileW`, `Vavsrubepodsjadebrooli` → `USER32.GetMonitorInfoW`). This complicates both manual analysis and signature generation.

IDA Pro identified 57 functions in the `.text` section. A key finding: function boundaries are deliberately disrupted through irregular prologues, extensive arithmetic blocks interwoven with functional code, and indirect API invocation via global function pointers. Cutter identified additional function boundaries that IDA collapsed into `loc_` blocks — the discrepancy confirms deliberate anti-analysis obfuscation rather than unusual compilation.

CAPA confirmed VM detection capability (anti-VMware string references, T1497.001) and PE export parsing for dynamic API resolution at two offsets (0x4094B1 and 0x40A3B6).

The embedded domain `corect.com` was investigated via Wayback Machine — circa 2013 it hosted a Romanian news website, consistent with either a compromised legitimate site or deliberately chosen benign-looking infrastructure. Currently redirects to an unrelated casino domain.

### Why Advanced Behaviors Didn't Activate
Persistence installation, browser injection, and credential exfiltration were not observed. This is expected: Zeus variants are designed to gate these behaviors behind successful C2 communication. Without a live C2 server to deliver configuration, the sample advances through reconnaissance and environmental profiling but never receives the trigger to activate its primary payload. This is consistent with the malware's known architecture — the absence of these behaviors reflects infrastructure age, not capability absence.

---

## Capability Assessment (MITRE ATT&CK)

| Capability | MITRE Technique | Evidence |
|---|---|---|
| Keylogging & input capture | T1056 | `GetAsyncKeyState`, `VkKeyScanA` imports; OSINT |
| Clipboard monitoring | T1115 | `EnumClipboardFormats`, `GetClipboardData` imports |
| File operations & credential logging | T1005, T1074 | `WriteFile`, `FindNextFileA`, file system APIs |
| Process injection (shared-memory) | T1055 | `CreateFileMappingA`, `VirtualQueryEx` imports |
| VM/sandbox evasion | T1497, T1497.001 | CAPA detection; anti-VMware strings |
| Code obfuscation | T1027 | Stub name mangling; opaque arithmetic blocks |
| Registry persistence | T1547.001 | OSINT: HKCU Run key modification |
| Network C2 communication | T1071 | OSINT HTTP/DNS data; dynamic API resolution |
| System reconnaissance | T1082, T1083 | Environment variable queries; drive enumeration |
| Geolocation fingerprinting | T1016 | `j.maxmind.com` DNS/HTTP observed |
| Social engineering / UAC bypass | T1548.002 | Spoofed Adobe Flash installer; fake UAC prompt |

---

## Indicators of Compromise

### File Indicators

**Primary sample:**
```
Filename : invoice_2318362983713_823931342io.pdf.exe
MD5      : ea039a854d20d7734c5add48f1a51c34
SHA1     : 9615dca4c0e46b8a39de5428af7db060399230b2
SHA256   : 69e966e730557fde8fd84317cdef1ece00a8bb3470c0b58f3231e170168af169
Size     : 252,928 bytes
Type     : PE32 executable (GUI), Intel 80386
Compiled : 2013-11-25 10:32:03 UTC
```

**Dropped file:**
```
Filename  : InstallFlashPlayer.exe
Path      : C:\Users\<USER>\AppData\Local\Temp\InstallFlashPlayer.exe
Size      : 89,248 bytes (87.1 KB)
Attributes: Hidden
Version   : Adobe® Flash® Player Installer/Uninstaller 11.0 r1
OrigName  : FlashUtil.exe
```

### Network Indicators
```
Domains:
  corect.com            — embedded C2 domain (static); no DNS observed during analysis
  j.maxmind.com         — geolocation fingerprinting (observed)
  fpdownload.macromedia.com — Flash update host contacted by dropped binary (observed)

HTTP Requests (observed):
  GET /app/geoip.js HTTP/1.0
  Host: j.maxmind.com

  GET /get/flashplayer/update/current/install/install_all_win_cab_64_ax_sgn.z
  Host: fpdownload.macromedia.com
  User-Agent: Flash Player Seed/3.0
```

### Registry Indicators (observed)
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProxyBypass
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\IntranetName
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\UNCAsIntranet
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\AutoDetect
```

### Process Indicators
```
Process name : InstallFlashPlayer.exe
Working set  : ~3.5 MB
Children     : cmd.exe + conhost.exe
Thread behavior: Includes a dedicated "KILL OWN PROCESS" worker thread
UAC display  : "Adobe® Flash® Player Installer..." (standard privileges)
              "invoice_2318362983713_823931342io.pdf.exe" (admin privileges)
```

---

## YARA Detection Rule

```yara
rule Zeus_BankingTrojan_26Nov2013_Sample {
    meta:
        description    = "Detects Zeus Banking Trojan sample from November 2013"
        author         = "Alister A. Rodrigues"
        date           = "2025-12-08"
        reference      = "MD5: ea039a854d20d7734c5add48f1a51c34"
        severity       = "high"
        malware_family = "Zeus"

    strings:
        $domain         = "corect.com" ascii wide
        $geo            = "j.maxmind.com" ascii wide
        $fake_desc      = "Adobe Flash Player Installer" ascii wide
        $fake_copyright = "1996-2011 Adobe, Inc." ascii wide
        $original_name  = "FlashUtil.exe" ascii wide

        $api1 = "GetAsyncKeyState" ascii
        $api2 = "CreateFileMappingA" ascii
        $api3 = "GetClipboardData" ascii
        $api4 = "VirtualQueryEx" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            ($domain and $geo) or
            ($fake_desc and $fake_copyright and $original_name) or
            (3 of ($api*))
        )
}
```

---

## Toolchain

| Tool | Purpose |
|---|---|
| **PEiD** | Packer/compiler signature detection |
| **Detect It Easy (DIE)** | Compiler identification, entropy analysis |
| **PE-bear** | PE header inspection, import table, string analysis |
| **Pestudio** | Import analysis, entropy per section, suspicious indicator flagging |
| **FLOSS** | String extraction (plaintext + obfuscated) |
| **CAPA** | Automated behavioral capability detection |
| **IDA Pro** | Primary disassembly and decompilation |
| **Cutter** | Cross-validation disassembly (supplementary) |
| **Sysinternals sigcheck** | Code-signing certificate verification |
| **Windows certutil** | SHA-256 / SHA-1 / MD5 hash computation |
| **Process Monitor (Procmon)** | File, registry, and process event monitoring |
| **Procdot** | Process activity visualization and graph analysis |
| **Wireshark** | Packet capture and traffic analysis |
| **FakeNet-NG** | Network emulation and DNS/HTTP interception |
| **Regshot** | Registry snapshot delta comparison |
| **VirusTotal** | OSINT hash correlation, sandbox behavioral data |
| **Wayback Machine** | Historical domain investigation (corect.com) |

---

## Why This Sample Still Matters

Zeus itself is defunct. Its C2 infrastructure has been dead for years, and the specific 2013 variant analyzed here cannot exfiltrate credentials to any live server. But the techniques it pioneered are not defunct — they're the blueprint for the entire modern banking malware ecosystem.

Every behavior documented in this analysis has a direct descendant in current threats:

- The **double-extension social engineering** (`invoice.pdf.exe`) is still the primary delivery vector for commodity malware in 2025
- The **shared-memory process injection** technique (`CreateFileMappingA` + `VirtualQueryEx`) appears in TrickBot's browser hooking module
- The **geolocation fingerprinting** via MaxMind is used verbatim by QakBot for victim profiling
- The **IE ZoneMap modification** for reducing browser security posture is reproduced in Dridex
- The **stub-name obfuscation** pattern — aliasing API imports to randomized strings — is a direct precursor to modern string encryption techniques used by virtually every major malware family today

Understanding Zeus is prerequisite to understanding its successors. The analysis here is intended as a complete reference for that lineage.

---

## Full Report

> **[→ Full Technical Analysis Report (PDF)](./report/)**

Covers complete static analysis findings (PE structure, disassembly, obfuscation patterns), dynamic execution monitoring, network traffic analysis, full IOC table, YARA rule, and defensive recommendations.

---

*Analysis by Alister A. Rodrigues. All analysis conducted in an isolated virtual machine environment with no production network connectivity. The malware sample is not stored in this repository.*
