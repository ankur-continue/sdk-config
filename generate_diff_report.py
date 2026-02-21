#!/usr/bin/env python3
"""Generate enriched diff_report.html with risk annotations from v2 analysis."""
import re
import html
from pathlib import Path
from collections import OrderedDict

DIR = Path(__file__).parent

# ─── Risk annotations from v2 deep analysis ─────────────────────────────────

# Application configs risk map
APP_RISK = {
    # CRITICAL (13)
    "CONFIG_BT_GATT_DYNAMIC_DB": ("critical", "Production RCA: SMP DFU switched from dynamic to static GATT, shifting ALL ATT handles", ["bt","rca","select-depends"]),
    "CONFIG_BT_SMP_SC_PAIR_ONLY": ("critical", "SDK default n\u2192y; legacy BLE pairing (4.0/4.1) completely disabled", ["bt","sdk-default"]),
    "CONFIG_BT_SMP_MIN_ENC_KEY_SIZE": ("critical", "SDK default 7\u219216; peers with <16-byte keys rejected", ["bt","sdk-default"]),
    "CONFIG_TIMESLICE_SIZE": ("critical", "SDK default 0\u219220ms; equal-priority threads now preempted, may expose races", ["kernel","sdk-default"]),
    "CONFIG_MCUBOOT_BOOTLOADER_MODE_SWAP_WITHOUT_SCRATCH": ("critical", "Deprecated rename to SWAP_USING_MOVE; if neither set OTA fails", ["mcuboot"]),
    "CONFIG_MCUMGR_TRANSPORT_BT_PERM_RW": ("critical", "Unauthenticated BLE DFU; anyone in range can initiate firmware update", ["bt","mcuboot"]),
    "CONFIG_MCUMGR_TRANSPORT_BT_DYNAMIC_SVC_REGISTRATION": ("critical", "Production RCA: select\u2192depends on; SMP moved to static registration", ["bt","rca","select-depends"]),
    "CONFIG_MCUMGR_TRANSPORT_BT_AUTHEN": ("critical", "Old prj.conf setting silently ignored; replaced by PERM_RW choice", ["bt","select-depends"]),
    "CONFIG_BT_BUF_ACL_RX_COUNT": ("critical", "Was 6, config removed; internal formula yields 2-3, packet drops under DFU load", ["bt"]),
    "CONFIG_BT_CTLR": ("critical", "Replaced by hidden HAS_BT_CTLR; old prj.conf CONFIG_BT_CTLR=y silently ignored", ["bt","select-depends"]),
    "CONFIG_BT_BUF_ACL_RX_SIZE": ("critical", "Halved 502\u2192251; peers sending >251-byte PDUs rejected, DFU throughput \u221250%", ["bt"]),
    "CONFIG_BT_L2CAP_TX_MTU": ("critical", "L2CAP TX MTU halved 498\u2192247; DFU time doubles", ["bt"]),
    "CONFIG_COMMON_LIBC_MALLOC_ARENA_SIZE": ("critical", "Picolibc default -1 (ALL SRAM); must explicitly set limit", ["kernel","sdk-default"]),

    # HIGH (16)
    "CONFIG_BT_CONN_TX_USER_DATA_SIZE": ("high", "TX handling refactored (struct tx_meta \u2192 struct closure); wrong size = corruption", ["bt","sdk-default"]),
    "CONFIG_MCUBOOT_SIGNATURE_KEY_FILE": ("high", "Signing key path in Kconfig; verify key not in VCS", ["mcuboot"]),
    "CONFIG_ROM_END_OFFSET": ("high", "Reserves 8342 bytes for MCUboot trailer; must match trailer size exactly", ["mcuboot"]),
    "CONFIG_ARM_MPU_REGION_MIN_ALIGN_AND_SIZE": ("high", "New default 128 when FPU_SHARING+MPU_STACK_GUARD; wastes RAM on alignment", ["kernel","sdk-default"]),
    "CONFIG_MCUMGR_GRP_IMG_ALLOW_CONFIRM_NON_ACTIVE_SLOT": ("high", "New default y; allows confirming non-active slot images", ["mcuboot","sdk-default"]),
    "CONFIG_MCUBOOT_BOOTLOADER_MODE_SWAP_USING_MOVE": ("high", "Replaces SWAP_WITHOUT_SCRATCH; verify app #ifdefs updated", ["mcuboot"]),
    "CONFIG_PSA_CRYPTO": ("high", "Master switch for PSA Crypto API; all BLE crypto depends on this", ["crypto"]),
    "CONFIG_NRF_SECURITY_ENABLER": ("high", "Auto-enables nrf_security when BLE requires crypto", ["crypto"]),
    "CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM": ("high", "Nordic nrf_security (Oberon+CC310) as PSA provider", ["crypto"]),
    "CONFIG_PSA_CRYPTO_SYS_INIT": ("high", "Auto-calls psa_crypto_init() at boot; CC310 HW fail \u2192 k_oops()", ["crypto"]),
    "CONFIG_PSA_NEED_CC3XX_CTR_DRBG_DRIVER": ("high", "CC310 hardware RNG; critical for BLE pairing", ["crypto"]),
    "CONFIG_PM_DEVICE_SYSTEM_MANAGED": ("high", "System auto-suspends devices before sleep; verify drivers handle suspend", ["pm"]),
    "CONFIG_FLASH_HAS_EXPLICIT_ERASE": ("high", "nRF52840 NOR flash requires explicit erase; drives NVS vs ZMS choice", ["storage"]),
    "CONFIG_NVS": ("high", "NVS changed select\u2192depends on FLASH_PAGE_LAYOUT; same class as ATT handle bug", ["storage","select-depends"]),
    "CONFIG_MPSL_HFCLK_LATENCY": ("high", "HFXO ramp-up 1400us; too low causes BLE timing issues", ["hw"]),
    "CONFIG_BOARD_ENABLE_DCDC": ("high", "DCDC migrated to devicetree; without DT regulator \u2192 2-3x higher current", ["hw"]),
    "CONFIG_BT_TINYCRYPT_ECC": ("high", "BLE ECC rewritten from TinyCrypt to PSA Crypto; different code paths", ["bt","crypto"]),
    "CONFIG_BT_GATT_CACHING": ("high", "GATT caching hash moved from TinyCrypt AES to PSA", ["bt","crypto"]),

    # MEDIUM (20)
    "CONFIG_BT_BUF_ACL_TX_COUNT": ("medium", "ACL TX buffers 32\u21928; may reduce peak throughput", ["bt"]),
    "CONFIG_BT_BUF_CMD_TX_COUNT": ("medium", "HCI command TX buffers 32\u21924; SDK default dropped", ["bt","sdk-default"]),
    "CONFIG_BT_CTLR_PRIVACY": ("medium", "Controller RPA resolution moved to host-side", ["bt"]),
    "CONFIG_PLATFORM_SPECIFIC_INIT": ("medium", "Deprecated: z_arm_platform_init() \u2192 soc_reset_hook()", ["kernel"]),
    "CONFIG_PSA_NEED_OBERON_ECDH_SECP_R1_256": ("medium", "Oberon software ECDH for P-256 BLE SC pairing", ["crypto"]),
    "CONFIG_MBEDTLS_THREADING_C": ("medium", "Thread-safe PSA crypto via k_mutex", ["crypto"]),
    "CONFIG_MBEDTLS_PSA_STATIC_KEY_SLOTS": ("medium", "PSA key storage heap 512 bytes; monitor for OOM", ["crypto"]),
    "CONFIG_PINCTRL_KEEP_SLEEP_STATE": ("medium", "Pins set to low-leakage states during sleep", ["pm"]),
    "CONFIG_PM_DEVICE_POWER_DOMAIN": ("medium", "Hierarchical power management enabled", ["pm"]),
    "CONFIG_STREAM_FLASH_POST_WRITE_CALLBACK": ("medium", "Post-write callback for MCUmgr OTA DFU", ["storage"]),
    "CONFIG_BT_SETTINGS_CCC_STORE_MAX": ("medium", "Max persisted CCC descriptors = 48", ["bt"]),
    "CONFIG_BT_CTLR_ENTROPY": ("medium", "New entropy driver replacing ENTROPY_BT_HCI path", ["bt"]),
    "CONFIG_SOC_FLASH_NRF_RADIO_SYNC_MPSL_NORMAL_PRIORITY_TIMEOUT_US": ("medium", "Flash/BLE radio sync timeout 10ms", ["hw"]),
    "CONFIG_POSIX_TIMERS": ("medium", "POSIX timers pulled by picolibc", ["kernel"]),
    "CONFIG_LOG_RATELIMIT": ("medium", "New log rate-limiting (5s interval)", ["kernel"]),
    "CONFIG_SEGGER_RTT_INIT_MODE_STRONG_CHECK": ("medium", "RTT init preserves control block across boot", ["kernel"]),
    "CONFIG_MEMFAULT_NCS_DEVICE_INFO_CUSTOM": ("medium", "Custom memfault device info; if function missing \u2192 linker error", ["memfault"]),
    "CONFIG_BT_BAP_UNICAST_SERVER": ("medium", "BT Audio profiles: select\u2192depends on BT_GATT_DYNAMIC_DB", ["bt","select-depends"]),
    "CONFIG_BT_CAP_ACCEPTOR": ("medium", "BT Audio profiles: select\u2192depends on BT_GATT_DYNAMIC_DB", ["bt","select-depends"]),
    "CONFIG_BT_HAS": ("medium", "BT Audio profiles: select\u2192depends on BT_GATT_DYNAMIC_DB", ["bt","select-depends"]),

    # LOW (20)
    "CONFIG_BT_ATT_PREPARE_COUNT": ("low", "ATT prepare write buffers added (0\u21922)", ["bt"]),
    "CONFIG_BT_CTLR_SDC_TX_PACKET_COUNT": ("low", "LL TX packets 3\u21928; aligned with ACL_TX_COUNT", ["bt"]),
    "CONFIG_BT_LONG_WQ_STACK_SIZE": ("low", "BT long workqueue stack 1300\u21921800; PSA needs more", ["bt"]),
    "CONFIG_BT_MAX_PAIRED": ("low", "Max bonded devices 20\u21928; saves NVS storage", ["bt"]),
    "CONFIG_MBEDTLS_CIPHER_C": ("low", "Legacy mbedTLS cipher API disabled; PSA is primary", ["crypto"]),
    "CONFIG_MBEDTLS_ENABLE_HEAP": ("low", "Global heap for PSA crypto enabled (512 bytes)", ["crypto"]),
    "CONFIG_MBEDTLS_MPI_MAX_SIZE": ("low", "Max MPI 256\u2192384 for RSA-3072 support", ["crypto"]),
    "CONFIG_ENTROPY_DEVICE_RANDOM_GENERATOR": ("low", "Hardware RNG replaces Xoshiro PRNG", ["crypto"]),
    "CONFIG_XOSHIRO_RANDOM_GENERATOR": ("low", "Xoshiro PRNG replaced by hardware entropy", ["crypto"]),
    "CONFIG_MCUBOOT_UPDATE_FOOTER_SIZE": ("low", "8KB reserved for MCUboot trailer", ["mcuboot"]),
    "CONFIG_MCUMGR_GRP_IMG_ALLOW_ERASE_PENDING": ("low", "Allows erasing secondary slot with pending swap", ["mcuboot"]),
    "CONFIG_MCUMGR_GRP_IMG_UPLOAD_CHECK_HOOK": ("low", "Upload validation hook enabled", ["mcuboot"]),
    "CONFIG_CONSOLE": ("low", "Console drivers disabled for production", ["kernel"]),
    "CONFIG_SHELL": ("low", "Interactive shell disabled; saves ~10-20KB", ["kernel"]),
    "CONFIG_RUNTIME_NMI": ("low", "Runtime NMI handler disabled", ["kernel"]),
    "CONFIG_MEMFAULT_CDR_ENABLE": ("low", "Memfault CDR SDK default flipped n\u2192y", ["memfault"]),
    "CONFIG_NRFX_SAADC": ("low", "ADC driver enabled for battery/analog", ["hw"]),
    "CONFIG_NRFX_TWI1": ("low", "TWI1 disabled; switched to TWIM (DMA-capable)", ["hw"]),
    "CONFIG_I2C_NRFX_TWI": ("low", "Non-DMA I2C removed; DT uses TWIM", ["hw"]),
    "CONFIG_ENTROPY_BT_HCI": ("low", "BT HCI entropy replaced by hardware RNG", ["crypto"]),
    "CONFIG_SB_VALIDATION_STRUCT_HAS_HASH": ("low", "FW validation struct includes hash", ["crypto"]),
}

# MCUboot configs risk map
MCUBOOT_RISK = {
    # CRITICAL (4)
    "CONFIG_BOOT_PREFER_SWAP_MOVE": ("critical", "Lost 'default y if SOC_FAMILY_NORDIC_NRF'; new SWAP_OFFSET defaults y instead", ["boot","sdk-default","new-algo"]),
    "CONFIG_MCUBOOT_BOOTLOADER_MODE_SWAP_WITHOUT_SCRATCH": ("critical", "Deprecated rename to SWAP_USING_MOVE; old symbol ignored", ["boot"]),
    "CONFIG_PICOLIBC": ("critical", "C library changed MINIMAL_LIBC\u2192picolibc with IO_MINIMAL; %02x loses padding", ["libc"]),
    "CONFIG_COMMON_LIBC_MALLOC_ARENA_SIZE": ("critical", "Picolibc default -1 (ALL SRAM); v64 sets =0 but fragile in 48KB partition", ["libc","sdk-default"]),

    # HIGH (5)
    "CONFIG_BOOT_PREFER_SWAP_OFFSET": ("high", "New swap algorithm; places firmware at sector+1 in secondary slot", ["boot","new-algo"]),
    "CONFIG_BOOT_IMG_HASH_ALG_SHA256": ("high", "Formal hash algorithm choice introduced; SHA256 was implicit before", ["boot","crypto"]),
    "CONFIG_CBPRINTF_LIBC_SUBSTS": ("high", "cbprintf no longer substitutes libc printf; snprintk \u2192 picolibc snprintf", ["libc"]),
    "CONFIG_BOOT_SIGNATURE_KEY_FILE": ("high", "Signing key path changed to project-specific private key", ["crypto"]),
    "CONFIG_BOARD_ENABLE_DCDC": ("high", "DCDC migrated to devicetree; SOC_DCDC_NRF52X deprecated", ["hw"]),

    # MEDIUM (8)
    "CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST": ("medium", "New TLV validation; images with unexpected TLV types rejected", ["boot","security"]),
    "CONFIG_MCUBOOT_STORAGE_WITH_ERASE": ("medium", "Explicit erase support for RRAM/MRAM; no behavioral change on nRF52840", ["boot","flash"]),
    "CONFIG_FORTIFY_SOURCE_COMPILE_TIME": ("medium", "-D_FORTIFY_SOURCE=1 enabled; picolibc allows it", ["security"]),
    "CONFIG_MCUBOOT_CLEANUP_RAM": ("medium", "New: zeros ALL RAM before jumping to app; not enabled by default", ["security"]),
    "CONFIG_MBEDTLS_CFG_FILE": ("medium", "Unconditional default removed; now conditional on TinyCrypt/mbedTLS only", ["crypto"]),
    "CONFIG_BOOT_BYPASS_KEY_MATCH": ("medium", "Skips TLV key hash matching; must remain =n in production", ["security"]),
    "CONFIG_NCS_MCUBOOT_IMG_VALIDATE_ATTEMPT_COUNT": ("medium", "count=1: single failed validation erases image", ["boot"]),
    "CONFIG_NCS_MCUBOOT_IN_BUILD": ("medium", "child-image flag replaced by SB_CONFIG_BOOTLOADER_MCUBOOT=y in sysbuild", ["build"]),

    # LOW (10)
    "CONFIG_BOOT_WATCHDOG_FEED_NRFX_WDT": ("low", "Refactored watchdog feeding; functionally equivalent", ["boot","hw"]),
    "CONFIG_BOOT_MAX_IMG_SECTORS_AUTO": ("low", "Auto-calculates max sectors; off when PM is used", ["boot"]),
    "CONFIG_SIGN_IMAGES": ("low", "Explicit toggle removed; signing implicit in sysbuild", ["build"]),
    "CONFIG_COMPILER_FREESTANDING": ("low", "-ffreestanding no longer needed with picolibc", ["libc"]),
    "CONFIG_THREAD_LOCAL_STORAGE": ("low", "TLS enabled by picolibc; MCUboot single-threaded, minimal bloat", ["libc"]),
    "CONFIG_BOOT_ECDSA_CC310": ("low", "CC310 BL crypto path identical in both versions", ["crypto"]),
    "CONFIG_BOOT_KEYS_REVOCATION": ("low", "KMU-based key rotation; only for nRF54L/54H, not nRF52840", ["security"]),
    "CONFIG_NRF_SECURITY_ENABLER": ("low", "App-level auto-enabler; no effect on MCUboot crypto path", ["crypto"]),
    "CONFIG_PLATFORM_SPECIFIC_INIT": ("low", "Deprecated: z_arm_platform_init() \u2192 soc_reset_hook()", ["kernel"]),
    "CONFIG_SCHED_DUMB": ("low", "Rename to SCHED_SIMPLE; MCUboot single-threaded", ["kernel"]),
    "CONFIG_DEVICE_DEINIT_SUPPORT": ("low", "Adds deinit ptr per device (+4B); consider =n for 48KB partition", ["kernel"]),
    "CONFIG_PINCTRL_KEEP_SLEEP_STATE": ("low", "Retains pin sleep states; small RAM cost", ["hw"]),
    "CONFIG_SEGGER_RTT_SECTION": ("low", "RTT buffers in explicit section for MCUboot\u2192app transition", ["kernel"]),
}

# ─── Parse .config files ────────────────────────────────────────────────────

def parse_config(path):
    """Parse a Kconfig .config file into {name: value} dict."""
    configs = OrderedDict()
    with open(path) as f:
        for line in f:
            line = line.strip()
            m = re.match(r'^(CONFIG_\w+)=(.+)$', line)
            if m:
                configs[m.group(1)] = m.group(2)
            elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
                name = line.split()[1]
                configs[name] = 'n'
    return configs

def compute_diff(old, new):
    """Compare two config dicts. Returns (changed, added, removed) lists."""
    all_keys = set(old) | set(new)
    changed, added, removed = [], [], []
    for k in sorted(all_keys):
        in_old = k in old
        in_new = k in new
        if in_old and in_new:
            if old[k] != new[k]:
                changed.append((k, old[k], new[k]))
        elif in_new:
            added.append((k, new[k]))
        else:
            removed.append((k, old[k]))
    return changed, added, removed

# ─── Category assignment ────────────────────────────────────────────────────

CATEGORY_RULES = [
    (r'BT_CTLR|SDC_', 'BLE Controller'),
    (r'BT_|MCUMGR_TRANSPORT_BT', 'Bluetooth'),
    (r'MCUMGR_|IMG_MANAGER', 'MCUmgr / DFU'),
    (r'MCUBOOT_|BOOT_PREFER|BOOT_SWAP|BOOT_IMG|BOOT_SIGNATURE|BOOT_ECDSA|BOOT_VALIDATE|BOOT_WATCHDOG|BOOT_MAX_IMG|BOOT_BYPASS|BOOT_KEYS|SIGN_IMAGES|UPDATEABLE_IMAGE', 'MCUboot'),
    (r'FLASH_|STREAM_FLASH|SOC_FLASH', 'Flash'),
    (r'NVS|SETTINGS_NVS', 'NVS'),
    (r'PSA_|OBERON_|CC3XX_|CRACEN_', 'PSA Crypto'),
    (r'MBEDTLS_', 'mbedTLS'),
    (r'NRF_SECURITY|ENTROPY_|XOSHIRO|TINYCRYPT', 'Crypto'),
    (r'PICOLIBC|CBPRINTF|COMMON_LIBC|MINIMAL_LIBC', 'C Library'),
    (r'MEMFAULT_', 'Memfault'),
    (r'MPSL_', 'MPSL'),
    (r'LOG_|LOGGING', 'Logging'),
    (r'RTT_|SEGGER_', 'Segger RTT'),
    (r'SHELL_', 'Shell'),
    (r'NRFX_|NRFC_', 'nrfx Drivers'),
    (r'I2C_|TWIM_|TWI_', 'I2C'),
    (r'GPIO_|NRFX_GPIOTE', 'GPIO'),
    (r'PM_|POWEROFF', 'Power Mgmt'),
    (r'ARM_|FP_|FPU_', 'ARM / FPU'),
    (r'MPU_', 'MPU'),
    (r'THREAD_|MULTITHREADING|SCHED_|WAITQ_|TIMESLICE', 'Scheduler'),
    (r'SENSOR_|ADC_|SAADC', 'Sensors / ADC'),
    (r'PINCTRL_', 'Pin Control'),
    (r'DCDC|REGULATOR|BOARD_ENABLE', 'Power HW'),
    (r'POSIX_', 'POSIX'),
    (r'SB_|NCS_|BUILD_OUTPUT|SECURE_BOOT', 'Build / NCS'),
    (r'PLATFORM_SPECIFIC|SOC_RESET|SOC_DCDC|SOC_NRF', 'SoC'),
    (r'FORTIFY_|STACK_CANARIES|STACK_SENTINEL', 'Security'),
    (r'DEVICE_|INIT_STACKS|ISR_STACK|MAIN_STACK|HEAP_MEM|KERNEL_|KOBJECT', 'Kernel'),
]

def categorize(name):
    bare = name.replace('CONFIG_', '', 1)
    for pattern, cat in CATEGORY_RULES:
        if re.search(pattern, bare):
            return cat
    return 'Other'

# ─── HTML generation ────────────────────────────────────────────────────────

def val_html(v):
    if v == 'y':
        return '<span class="val-y">y</span>'
    if v == 'n':
        return '<span class="val-n">n</span>'
    if v.startswith('"'):
        display = html.escape(v if len(v) < 60 else v[:57] + '..."')
        return f'<span class="val-str">{display}</span>'
    return f'<span class="val-num">{html.escape(v)}</span>'

def risk_badge(level):
    if level == 'none':
        return ''
    return f'<span class="badge {level}">{level.upper()}</span>'

def tag_html(tags):
    return ''.join(f'<span class="tag {t}">{t.upper()}</span>' for t in tags)

def risk_order(level):
    return {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'none': 4}.get(level, 5)

def make_rows(entries, risk_map, mode):
    """Generate table rows. mode: 'changed', 'added', 'removed'."""
    rows = []
    for entry in entries:
        if mode == 'changed':
            name, old_v, new_v = entry
        elif mode == 'added':
            name, new_v = entry
            old_v = None
        else:
            name, old_v = entry
            new_v = None

        info = risk_map.get(name)
        level = info[0] if info else 'none'
        why = info[1] if info else ''
        tags = info[2] if info else []
        cat = categorize(name)
        active = (mode == 'changed') or (mode == 'added' and new_v != 'n') or (mode == 'removed' and old_v != 'n')

        old_cell = val_html(old_v) if old_v is not None else '<span class="val-n">\u2014</span>'
        new_cell = val_html(new_v) if new_v is not None else '<span class="val-n">\u2014</span>'

        why_cell = ''
        if why:
            why_cell = f'<div class="why">{html.escape(why)}</div>'
        tag_cell = tag_html(tags) if tags else ''

        search_text = f"{name} {cat} {level} {why} {' '.join(tags)}".lower()

        rows.append((level, active, name, f'''<tr class="row" data-risk="{level}" data-active="{1 if active else 0}" data-text="{html.escape(search_text)}">
<td class="key">{html.escape(name)}</td>
<td class="cat">{html.escape(cat)}</td>
<td class="risk-cell">{risk_badge(level)}{tag_cell}</td>
<td>{old_cell}</td>
<td>{new_cell}</td>
<td class="why-cell">{why_cell}</td>
</tr>'''))
    # Sort by risk level (critical first), then name
    rows.sort(key=lambda r: (risk_order(r[0]), r[2]))
    return rows

def count_risks(rows):
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'none': 0}
    for level, active, name, html_str in rows:
        counts[level] += 1
    return counts

def make_section_table(rows, section_id, title, color, open_default=False):
    active_rows = [r for r in rows if r[1]]
    inactive_rows = [r for r in rows if not r[1]]

    risk_counts = count_risks(active_rows)
    risk_summary = []
    for level in ['critical', 'high', 'medium', 'low']:
        if risk_counts[level] > 0:
            risk_summary.append(f'<span class="risk-count {level}">{risk_counts[level]} {level}</span>')

    out = []
    # Active section
    active_open = ' open' if open_default else ''
    out.append(f'<details{active_open}><summary style="color:{color}">{title} ({len(active_rows)} active) {" ".join(risk_summary)}</summary>')
    out.append('<table><thead><tr><th>Config</th><th>Category</th><th>Risk</th><th>v61</th><th>v64</th><th>Analysis</th></tr></thead><tbody>')
    for _, _, _, row_html in active_rows:
        out.append(row_html)
    out.append('</tbody></table></details>')

    # Inactive section (=n configs)
    if inactive_rows:
        out.append(f'<details><summary style="color:var(--muted)">{title} \u2014 inactive/=n ({len(inactive_rows)})</summary>')
        out.append('<table><thead><tr><th>Config</th><th>Category</th><th>Risk</th><th>v61</th><th>v64</th><th>Analysis</th></tr></thead><tbody>')
        for _, _, _, row_html in inactive_rows:
            out.append(row_html)
        out.append('</tbody></table></details>')

    return '\n'.join(out)

def make_image_section(title, old_path, new_path, risk_map, old_label, new_label):
    old_cfg = parse_config(old_path)
    new_cfg = parse_config(new_path)
    changed, added, removed = compute_diff(old_cfg, new_cfg)

    changed_rows = make_rows(changed, risk_map, 'changed')
    added_rows = make_rows(added, risk_map, 'added')
    removed_rows = make_rows(removed, risk_map, 'removed')

    all_active_rows = [r for r in changed_rows + added_rows + removed_rows if r[1]]
    total_risks = count_risks(all_active_rows)

    # Stats
    active_added = sum(1 for r in added_rows if r[1])
    inactive_added = len(added_rows) - active_added
    active_removed = sum(1 for r in removed_rows if r[1])
    inactive_removed = len(removed_rows) - active_removed

    stats = f'''<div class="stats">
<span class="stat changed">{len(changed_rows)} changed</span>
<span class="stat added">{active_added} added (active)</span>
<span class="stat removed">{active_removed} removed (active)</span>
<span class="stat muted">{inactive_added} added =n &middot; {inactive_removed} removed =n</span>
<span class="stat muted">{len(old_cfg)} total in v61 &middot; {len(new_cfg)} total in v64</span>
</div>
<div class="stats risk-stats">'''
    for level in ['critical', 'high', 'medium', 'low']:
        if total_risks[level] > 0:
            stats += f'<span class="stat risk-{level}">{total_risks[level]} {level.upper()}</span>'
    stats += '</div>'

    tables = []
    tables.append(make_section_table(changed_rows, 'changed', '\u0394 Changed Values', 'var(--changed)', open_default=True))
    tables.append(make_section_table(added_rows, 'added', '+ Added', 'var(--added)', open_default=False))
    tables.append(make_section_table(removed_rows, 'removed', '\u2212 Removed', 'var(--removed)', open_default=False))

    return f'''<div class="section">
<h2>{title}</h2>
<p class="subtitle">{old_label} &rarr; {new_label}</p>
{stats}
{chr(10).join(tables)}
</div>'''


CSS = '''
:root {
    --bg: #0d1117; --fg: #c9d1d9; --border: #30363d;
    --added: #238636; --removed: #da3633; --changed: #d29922; --muted: #484f58;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace; background: var(--bg); color: var(--fg); padding: 24px; line-height: 1.5; font-size: 13px; }
h1 { font-size: 1.6em; margin-bottom: 4px; color: #f0f6fc; }
h1 small { font-size: 0.6em; color: var(--muted); font-weight: normal; }
h2 { font-size: 1.3em; color: #f0f6fc; margin-bottom: 4px; }
.subtitle { color: var(--muted); margin-bottom: 12px; font-size: 12px; }
.header-subtitle { color: var(--muted); margin-bottom: 16px; font-size: 13px; }
.section { background: #161b22; border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 24px; }
.stats { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 8px; }
.stat { padding: 3px 10px; border-radius: 14px; font-size: 0.82em; font-weight: 600; }
.stat.changed { background: rgba(210,153,34,0.15); color: var(--changed); }
.stat.added { background: rgba(35,134,54,0.15); color: var(--added); }
.stat.removed { background: rgba(218,54,51,0.15); color: var(--removed); }
.stat.muted { background: rgba(72,79,88,0.15); color: var(--muted); }
.stat.risk-critical { background: #f8514918; color: #f85149; }
.stat.risk-high { background: #d2992218; color: #d29922; }
.stat.risk-medium { background: #58a6ff18; color: #58a6ff; }
.stat.risk-low { background: #3fb95018; color: #3fb950; }
.risk-stats { margin-bottom: 16px; }

details { margin-bottom: 12px; }
summary { cursor: pointer; padding: 8px 12px; background: #0d1117; border: 1px solid var(--border); border-radius: 6px; font-weight: bold; font-size: 13px; user-select: none; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
summary:hover { border-color: #58a6ff; }
details[open] > summary { border-radius: 6px 6px 0 0; }

table { width: 100%; border-collapse: collapse; font-size: 12px; }
thead { position: sticky; top: 0; z-index: 1; }
th { background: #161b22; color: var(--muted); text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); font-size: 11px; text-transform: uppercase; letter-spacing: 0.3px; }
td { padding: 5px 10px; border-bottom: 1px solid #21262d; vertical-align: top; }
tr:hover { background: rgba(88,166,255,0.04); }
tr.hidden { display: none !important; }
.key { color: #f0f6fc; font-weight: 500; white-space: nowrap; }
.cat { color: var(--muted); font-size: 11px; white-space: nowrap; }
.risk-cell { white-space: nowrap; }
.why-cell { max-width: 300px; }
.why { color: #8b949e; font-size: 11px; line-height: 1.4; }

.val-y { color: #3fb950; font-weight: bold; }
.val-n { color: #f85149; }
.val-num { color: #d2a8ff; font-weight: bold; }
.val-str { color: #79c0ff; }

.badge { display: inline-block; padding: 1px 7px; border-radius: 10px; font-size: 9px; font-weight: bold; text-transform: uppercase; margin-right: 4px; vertical-align: middle; }
.badge.critical { background: #f8514922; color: #f85149; border: 1px solid #f8514944; }
.badge.high { background: #d2992222; color: #d29922; border: 1px solid #d2992244; }
.badge.medium { background: #58a6ff22; color: #58a6ff; border: 1px solid #58a6ff44; }
.badge.low { background: #3fb95022; color: #3fb950; border: 1px solid #3fb95044; }

.tag { display: inline-block; padding: 0 5px; border-radius: 3px; font-size: 9px; margin-right: 2px; vertical-align: middle; }
.tag.bt, .tag.bluetooth { background: #1f3d5c; color: #58a6ff; }
.tag.crypto { background: #3d1f5c; color: #d2a8ff; }
.tag.mcuboot, .tag.boot { background: #5c3d1f; color: #d29922; }
.tag.kernel, .tag.libc { background: #1f5c3d; color: #3fb950; }
.tag.hw { background: #5c1f3d; color: #f778ba; }
.tag.build { background: #2d2d2d; color: #c9d1d9; }
.tag.memfault { background: #3d5c1f; color: #7ee787; }
.tag.pm { background: #1f5c5c; color: #56d4dd; }
.tag.storage, .tag.flash { background: #5c5c1f; color: #e3b341; }
.tag.rca { background: #f8514933; color: #f85149; border: 1px solid #f8514955; }
.tag.sdk-default { background: #d2992233; color: #d29922; border: 1px solid #d2992255; }
.tag.select-depends { background: #f8514933; color: #ff7b72; border: 1px solid #f8514955; }
.tag.new-algo { background: #d2a8ff33; color: #d2a8ff; border: 1px solid #d2a8ff55; }
.tag.security { background: #3d1f5c; color: #d2a8ff; }

.risk-count { font-size: 11px; font-weight: bold; margin-left: 4px; }
.risk-count.critical { color: #f85149; }
.risk-count.high { color: #d29922; }
.risk-count.medium { color: #58a6ff; }
.risk-count.low { color: #3fb950; }

/* Controls */
.controls { background: #161b22; border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; margin-bottom: 20px; display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
.controls input { flex: 1; min-width: 200px; padding: 7px 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--fg); font-family: inherit; font-size: 13px; }
.controls input:focus { outline: none; border-color: #58a6ff; }
.filter-bar { display: flex; gap: 6px; flex-wrap: wrap; }
.filter-btn { padding: 4px 10px; border-radius: 14px; border: 1px solid var(--border); background: var(--bg); color: var(--muted); cursor: pointer; font-size: 11px; font-family: inherit; }
.filter-btn:hover { border-color: #58a6ff; color: #58a6ff; }
.filter-btn.active { background: #58a6ff22; border-color: #58a6ff; color: #58a6ff; }

.cross-link { font-size: 11px; color: #58a6ff; text-decoration: none; margin-top: 8px; display: inline-block; }
.cross-link:hover { text-decoration: underline; }

footer { margin-top: 32px; padding-top: 12px; border-top: 1px solid #21262d; color: #484f58; font-size: 11px; }
'''

JS = '''
let currentRisk = 'all';
let currentSection = 'all';

function filterAll() {
    const q = document.getElementById('search').value.toLowerCase();
    document.querySelectorAll('tr.row').forEach(tr => {
        const text = (tr.getAttribute('data-text') || '') + ' ' + tr.textContent.toLowerCase();
        const risk = tr.getAttribute('data-risk') || 'none';
        const matchQ = !q || text.includes(q);
        const matchR = currentRisk === 'all' || risk === currentRisk;
        tr.classList.toggle('hidden', !(matchQ && matchR));
    });
    // Auto-expand details with visible rows
    document.querySelectorAll('details').forEach(d => {
        const hasVisible = d.querySelector('tr.row:not(.hidden)');
        if (q || currentRisk !== 'all') {
            if (hasVisible) d.open = true;
        }
    });
}

function setRisk(level, btn) {
    currentRisk = level;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    filterAll();
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('search').addEventListener('input', filterAll);
});
'''

def generate():
    app_section = make_image_section(
        'Application Config',
        DIR / 'application_v61_ncs270.config',
        DIR / 'application_v64_ncs322.config',
        APP_RISK,
        'build/zephyr/.config (v61/NCS2.7.0)',
        'build/app/zephyr/.config (v64/NCS3.2.2)'
    )
    mcuboot_section = make_image_section(
        'MCUboot Config',
        DIR / 'mcuboot_v61_ncs270.config',
        DIR / 'mcuboot_v64_ncs322.config',
        MCUBOOT_RISK,
        'build/mcuboot/zephyr/.config (v61)',
        'build/mcuboot/zephyr/.config (v64)'
    )

    page = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Config Diff v2: v61/NCS2.7.0 &rarr; v64/NCS3.2.2 &mdash; Risk Annotated</title>
<style>{CSS}</style>
</head>
<body>

<h1>Config Diff v2 <small>Risk-Annotated</small></h1>
<p class="header-subtitle">v61 (NCS 2.7.0) &rarr; v64 (NCS 3.2.2) &mdash; custom_board (nRF52840) &mdash; Generated 2026-02-22</p>

<div class="controls">
<input type="text" id="search" placeholder="Filter configs... (e.g. BT_SMP, MCUBOOT, FLASH, critical, select-depends)">
<div class="filter-bar">
<button class="filter-btn active" onclick="setRisk('all', this)">All</button>
<button class="filter-btn" onclick="setRisk('critical', this)">Critical</button>
<button class="filter-btn" onclick="setRisk('high', this)">High</button>
<button class="filter-btn" onclick="setRisk('medium', this)">Medium</button>
<button class="filter-btn" onclick="setRisk('low', this)">Low</button>
<button class="filter-btn" onclick="setRisk('none', this)">None</button>
</div>
</div>

<p style="margin-bottom:16px;font-size:12px;color:#8b949e;">
Every config cross-referenced against Kconfig source in NCS 2.7.0 and 3.2.2.
Risk annotations from <a class="cross-link" href="application_analysis_v2.html">Application Analysis v2</a>
and <a class="cross-link" href="mcuboot_analysis_v2.html">MCUboot Analysis v2</a>.
</p>

{app_section}

{mcuboot_section}

<footer>
Generated 2026-02-22 &middot; custom_board &middot; NCS 2.7.0 &rarr; 3.2.2 &middot;
<a class="cross-link" href="application_analysis_v2.html">App Analysis v2</a> &middot;
<a class="cross-link" href="mcuboot_analysis_v2.html">MCUboot Analysis v2</a>
</footer>

<script>{JS}</script>
</body>
</html>'''

    out = DIR / 'diff_report.html'
    with open(out, 'w') as f:
        f.write(page)
    print(f'Written {out} ({len(page):,} bytes)')

if __name__ == '__main__':
    generate()
