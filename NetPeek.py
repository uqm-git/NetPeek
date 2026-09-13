import psutil
import os
import shutil
import json
import time
import sys
import urllib.request
from datetime import datetime
from collections import Counter, defaultdict

if os.name == "nt":
    os.system("")

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    PURPLE      = "\033[38;5;141m"
    PURPLE_DARK = "\033[38;5;99m"
    PURPLE_LT   = "\033[38;5;183m"
    VIOLET      = "\033[38;5;135m"
    ORCHID      = "\033[38;5;170m"
    LAVENDER    = "\033[38;5;189m"
    PINK        = "\033[38;5;213m"
    LIME        = "\033[38;5;154m"
    ORANGE      = "\033[38;5;208m"
    HIDE_CURSOR = "\033[?25l"
    SHOW_CURSOR = "\033[?25h"

ICON_P2P    = "◉"
ICON_EXT    = "●"
ICON_LOCAL  = "○"
ICON_LISTEN = "◆"

W_PID    = 7
W_PROC   = 28
W_PROTO  = 6
W_LOCAL  = 25
W_REMOTE = 25
W_STAT   = 14
W_INFO   = 36

TOTAL_W = (W_PID + W_PROC + W_PROTO + W_LOCAL + W_REMOTE
           + W_STAT + W_INFO + 12)

GITHUB = "github.com/uqm-git"

_GEO_CACHE = {}
_GEO_LAST = 0.0
_GEO_MIN_GAP = 1.4

SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

TRAFFIC_WINDOW = 30
TRAFFIC_INTERVAL = 1.0
TRAFFIC_HIGH_PORT_MIN = 49152
TRAFFIC_MIN_BYTES = 4096
TRAFFIC_MIN_PACKETS = 20


def term_width():
    try:
        w = shutil.get_terminal_size().columns
    except Exception:
        w = 80
    return max(60, w - 2)


def cursor_hide():
    sys.stdout.write(C.HIDE_CURSOR)
    sys.stdout.flush()


def cursor_show():
    sys.stdout.write(C.SHOW_CURSOR)
    sys.stdout.flush()


def spinner_load(text="Loading", duration=0.9):
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        frame = SPINNER_FRAMES[i % len(SPINNER_FRAMES)]
        sys.stdout.write(f"\r  {C.PURPLE_LT}{frame}{C.RESET} {C.GRAY}{text}...{C.RESET}")
        sys.stdout.flush()
        time.sleep(0.07)
        i += 1
    sys.stdout.write("\r" + " " * (len(text) + 12) + "\r")
    sys.stdout.flush()


def pulse_print(text, color=C.PURPLE_LT, cycles=2, delay=0.08):
    for _ in range(cycles):
        sys.stdout.write("\r" + C.BOLD + color + text + C.RESET)
        sys.stdout.flush()
        time.sleep(delay)
        sys.stdout.write("\r" + C.DIM + color + text + C.RESET)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\r" + C.BOLD + color + text + C.RESET + "\n")
    sys.stdout.flush()


def geo_lookup(ip, timeout=3):
    global _GEO_LAST
    if not ip or ip in _GEO_CACHE:
        return _GEO_CACHE.get(ip, "")

    gap = time.monotonic() - _GEO_LAST
    if gap < _GEO_MIN_GAP:
        time.sleep(_GEO_MIN_GAP - gap)

    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,status"
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        _GEO_LAST = time.monotonic()
        if data.get("status") == "success":
            country = data.get("country", "") or data.get("countryCode", "")
            _GEO_CACHE[ip] = country
            return country
    except Exception:
        pass

    _GEO_CACHE[ip] = ""
    return ""


def get_process_info(pid):
    if not pid:
        return ("System", "")
    try:
        p = psutil.Process(pid)
        name = p.name()
        try:
            exe = p.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            exe = ""
        return (name, exe)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return ("?", "")


def is_external(ip):
    if not ip:
        return False
    if ip.startswith("127.") or ip.startswith("10.") \
       or ip.startswith("192.168.") or ip == "::1" \
       or ip.startswith("fe80:"):
        return False
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return False
        except (ValueError, IndexError):
            pass
    return True


def short_path(path, maxlen=W_INFO):
    if not path:
        return ""
    if len(path) <= maxlen:
        return path
    parts = path.replace("\\", "/").split("/")
    if len(parts) >= 2:
        return "…/" + "/".join(parts[-2:])
    return "…" + path[-(maxlen - 1):]


def classify(conn):
    listen = conn.status in ("LISTEN", "NONE") and not conn.raddr
    ext = bool(conn.raddr) and is_external(conn.raddr.ip)
    return {
        "is_listen": listen,
        "is_external": ext,
    }


def collect(filter_pids=None):
    rows = []
    for conn in psutil.net_connections(kind="inet"):
        if filter_pids is not None and (conn.pid or 0) not in filter_pids:
            continue

        name, exe = get_process_info(conn.pid)
        kind = classify(conn)

        local  = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
        remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"

        status = conn.status
        if not conn.raddr and status == "NONE":
            status = "LISTEN" if conn.type.name == "SOCK_STREAM" else "NONE"

        rows.append({
            "pid": conn.pid or 0,
            "program": name,
            "proto": "TCP" if conn.type.name == "SOCK_STREAM" else "UDP",
            "local": local,
            "remote": remote,
            "status": status,
            "path": exe,
            "is_listen": kind["is_listen"],
            "is_external": kind["is_external"],
        })

    def sort_key(r):
        if r["is_external"]: return (0, r["program"].lower(), r["remote"])
        if r["is_listen"]:   return (1, r["program"].lower(), r["local"])
        return (2, r["program"].lower(), r["local"])

    rows.sort(key=sort_key)
    return rows


def get_process_list():
    procs = {}
    for p in psutil.process_iter(["pid", "name", "exe"]):
        try:
            info = p.info
            name = info["name"] or "?"
            exe = info["exe"] or ""
            key = name.lower()
            if key not in procs:
                procs[key] = {"name": name, "exe": exe, "pids": set()}
            procs[key]["pids"].add(info["pid"])
            if exe and not procs[key]["exe"]:
                procs[key]["exe"] = exe
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procs


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def box_top(width, color=None):
    color = color or C.PURPLE
    print(color + "╔" + "═" * width + "╗" + C.RESET)


def box_bottom(width, color=None):
    color = color or C.PURPLE
    print(color + "╚" + "═" * width + "╝" + C.RESET)


def box_sep(width, color=None):
    color = color or C.PURPLE
    print(color + "╟" + "─" * width + "╢" + C.RESET)


def box_line(text, width, color=None, text_color="", align="center"):
    color = color or C.PURPLE
    if align == "center":
        pad = max(0, (width - len(text)) // 2)
        left = " " * pad
        right = " " * max(0, width - pad - len(text))
    elif align == "left":
        left = "  "
        right = " " * max(0, width - len(left) - len(text))
    else:
        left = " " * max(0, width - len(text) - 2)
        right = "  "
    print(color + "║" + C.RESET
          + left + text_color + text + C.RESET + right
          + color + "║" + C.RESET)


def menu_row(key, label, width, key_color=None, label_color=None):
    key_color = key_color or C.LAVENDER
    label_color = label_color or C.WHITE
    left  = "   "
    mid   = "  "
    text  = f"[{key}]"
    visible_len = len(left) + len(text) + len(mid) + len(label)
    pad = max(0, width - visible_len)
    print(C.PURPLE + "║" + C.RESET
          + left
          + key_color + C.BOLD + text + C.RESET
          + mid
          + label_color + label + C.RESET
          + " " * pad
          + C.PURPLE + "║" + C.RESET)


ASCII_LOGO = [
    "  ███╗   ██╗███████╗████████╗██████╗ ███████╗███████╗██╗  ██╗",
    "  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██║ ██╔╝",
    "  ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  █████╗  █████╔╝ ",
    "  ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██╔══╝  ██╔══╝  ██╔═██╗ ",
    "  ██║ ╚████║███████╗   ██║   ██║     ███████╗███████╗██║  ██╗",
    "  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝",
]

LOGO_COLORS = [C.VIOLET, C.PURPLE, C.PURPLE_LT, C.ORCHID, C.PURPLE_LT, C.VIOLET]


def animate_logo(width):
    for step in range(len(ASCII_LOGO[0]) // 8 + 1):
        clear()
        print()
        print(C.PURPLE_DARK + "╔" + "═" * width + "╗" + C.RESET)
        print(C.PURPLE_DARK + "║" + C.RESET + " " * width + C.PURPLE_DARK + "║" + C.RESET)
        for i, line in enumerate(ASCII_LOGO):
            shown = line[:min(len(line), step * 8)]
            pad = max(0, (width - len(line)) // 2)
            col = LOGO_COLORS[i % len(LOGO_COLORS)]
            print(C.PURPLE_DARK + "║" + C.RESET
                  + " " * pad
                  + C.BOLD + col + shown + C.RESET
                  + " " * max(0, width - pad - len(line))
                  + C.PURPLE_DARK + "║" + C.RESET)
        time.sleep(0.04)


def startup_animation():
    width = term_width()
    animate_logo(width)
    time.sleep(0.1)
    clear()
    print()
    print(C.PURPLE_DARK + "╔" + "═" * width + "╗" + C.RESET)
    print(C.PURPLE_DARK + "║" + C.RESET + " " * width + C.PURPLE_DARK + "║" + C.RESET)
    for i, line in enumerate(ASCII_LOGO):
        pad = max(0, (width - len(line)) // 2)
        col = LOGO_COLORS[i % len(LOGO_COLORS)]
        print(C.PURPLE_DARK + "║" + C.RESET
              + " " * pad
              + C.BOLD + col + line + C.RESET
              + " " * max(0, width - pad - len(line))
              + C.PURPLE_DARK + "║" + C.RESET)
    print(C.PURPLE_DARK + "║" + C.RESET + " " * width + C.PURPLE_DARK + "║" + C.RESET)
    print(C.PURPLE_DARK + "╚" + "═" * width + "╝" + C.RESET)
    print()
    cursor_hide()
    spinner_load("Initializing NetPeek", 1.1)
    cursor_show()
    print()


def show_main_menu():
    clear()
    width = term_width()

    print()
    print(C.PURPLE_DARK + "╔" + "═" * width + "╗" + C.RESET)
    print(C.PURPLE_DARK + "║" + C.RESET + " " * width + C.PURPLE_DARK + "║" + C.RESET)

    for i, line in enumerate(ASCII_LOGO):
        pad = max(0, (width - len(line)) // 2)
        col = LOGO_COLORS[i % len(LOGO_COLORS)]
        print(C.PURPLE_DARK + "║" + C.RESET
              + " " * pad
              + C.BOLD + col + line + C.RESET
              + " " * max(0, width - pad - len(line))
              + C.PURPLE_DARK + "║" + C.RESET)

    print(C.PURPLE_DARK + "║" + C.RESET + " " * width + C.PURPLE_DARK + "║" + C.RESET)

    subtitle = "✦  PORT  MONITOR  ✦"
    pad = max(0, (width - len(subtitle)) // 2)
    print(C.PURPLE_DARK + "║" + C.RESET
          + " " * pad
          + C.BOLD + C.ORCHID + subtitle + C.RESET
          + " " * max(0, width - pad - len(subtitle))
          + C.PURPLE_DARK + "║" + C.RESET)

    ts = datetime.now().strftime("%A, %d.%m.%Y  •  %H:%M:%S")
    pad = max(0, (width - len(ts)) // 2)
    print(C.PURPLE_DARK + "║" + C.RESET
          + " " * pad
          + C.GRAY + ts + C.RESET
          + " " * max(0, width - pad - len(ts))
          + C.PURPLE_DARK + "║" + C.RESET)

    print(C.PURPLE_DARK + "╟" + "─" * width + "╢" + C.RESET)
    print(C.PURPLE_DARK + "║" + C.RESET + " " * width + C.PURPLE_DARK + "║" + C.RESET)

    prompt = "Please choose an option:"
    pad = max(0, (width - len(prompt)) // 2)
    print(C.PURPLE_DARK + "║" + C.RESET
          + " " * pad
          + C.WHITE + prompt + C.RESET
          + " " * max(0, width - pad - len(prompt))
          + C.PURPLE_DARK + "║" + C.RESET)

    print(C.PURPLE_DARK + "║" + C.RESET + " " * width + C.PURPLE_DARK + "║" + C.RESET)

    menu_row("1", "  Show all connections", width, key_color=C.PURPLE_LT)
    menu_row("2", "  Filter by EXE / process", width, key_color=C.PURPLE_LT)
    menu_row("3", "  Traffic analysis  [BETA]", width, key_color=C.PURPLE_LT)
    menu_row("4", "  Exit", width, key_color=C.ORCHID)

    print(C.PURPLE_DARK + "║" + C.RESET + " " * width + C.PURPLE_DARK + "║" + C.RESET)
    print(C.PURPLE_DARK + "╟" + "─" * width + "╢" + C.RESET)

    gh_pad = max(0, (width - len(GITHUB) - 4) // 2)
    print(C.PURPLE_DARK + "║" + C.RESET
          + " " * gh_pad
          + C.GRAY + "⌥ " + C.RESET
          + C.LAVENDER + C.BOLD + GITHUB + C.RESET
          + " " * max(0, width - gh_pad - len(GITHUB) - 4)
          + C.PURPLE_DARK + "║" + C.RESET)

    print(C.PURPLE_DARK + "╚" + "═" * width + "╝" + C.RESET)
    print()


def show_process_menu(procs):
    sorted_procs = sorted(procs.values(), key=lambda x: x["name"].lower())

    page_size = 22
    total = len(sorted_procs)
    pages = (total + page_size - 1) // page_size
    page = 0

    while True:
        clear()
        width = term_width()
        print()
        box_top(width)
        box_line("SELECT A PROCESS", width,
                 text_color=C.BOLD + C.WHITE)
        box_line(f"Page {page + 1} / {pages}   •   {total} processes",
                 width, text_color=C.GRAY)
        box_sep(width)
        box_line("", width)

        start = page * page_size
        end = min(start + page_size, total)
        for i, proc in enumerate(sorted_procs[start:end], start=start):
            num = f"[{i + 1:>3}]"
            name = proc["name"][:32]
            pids = ",".join(str(p) for p in sorted(proc["pids"])[:4])
            if len(proc["pids"]) > 4:
                pids += "…"
            visible = f"   {num}  {name:<32}  PID: {pids}"
            pad = max(0, width - len(visible))
            print(C.PURPLE + "║" + C.RESET
                  + "   " + C.LAVENDER + num + C.RESET
                  + "  " + C.WHITE + f"{name:<32}" + C.RESET
                  + "  " + C.GRAY + f"PID: {pids}" + C.RESET
                  + " " * pad
                  + C.PURPLE + "║" + C.RESET)

        box_line("", width)
        box_sep(width)
        box_line("[N] Next   [P] Previous   [S] Search   [Q] Cancel",
                 width, text_color=C.ORCHID)
        box_line("Enter a number to select",
                 width, text_color=C.PURPLE_LT)
        box_bottom(width)
        print()

        try:
            choice = input(f"  {C.BOLD}{C.PURPLE_LT}➤ {C.RESET}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return None

        if choice in ("q", ""):
            return None
        elif choice == "n":
            if page < pages - 1:
                page += 1
        elif choice == "p":
            if page > 0:
                page -= 1
        elif choice == "s":
            query = input(f"  {C.PURPLE}Search: {C.RESET}").strip().lower()
            if query:
                matches = [p for p in sorted_procs
                           if query in p["name"].lower()
                           or query in p["exe"].lower()]
                if matches:
                    sorted_procs = matches
                    total = len(sorted_procs)
                    pages = (total + page_size - 1) // page_size
                    page = 0
                else:
                    print(f"  {C.RED}No matches.{C.RESET}")
                    input(f"  {C.GRAY}ENTER...{C.RESET}")
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < total:
                    return sorted_procs[idx]["pids"]
            except ValueError:
                pass


def print_header(subtitle="", animate=False):
    width = term_width()
    title = "✦  N E T P E E K  ✦"
    pad = max(0, (width - len(title)) // 2)
    print()
    print(C.PURPLE_DARK + "╔" + "═" * width + "╗" + C.RESET)

    if animate:
        cursor_hide()
        sys.stdout.write(C.PURPLE_DARK + "║" + C.RESET + " " * pad)
        sys.stdout.flush()
        for ch in title:
            sys.stdout.write(C.BOLD + C.PURPLE_LT + ch + C.RESET)
            sys.stdout.flush()
            time.sleep(0.02)
        sys.stdout.write(" " * max(0, width - pad - len(title))
                         + C.PURPLE_DARK + "║" + C.RESET + "\n")
        cursor_show()
    else:
        print(C.PURPLE_DARK + "║" + C.RESET
              + " " * pad + C.BOLD + C.PURPLE_LT + title + C.RESET
              + " " * max(0, width - pad - len(title))
              + C.PURPLE_DARK + "║" + C.RESET)

    if subtitle:
        pad_s = max(0, (width - len(subtitle)) // 2)
        print(C.PURPLE_DARK + "║" + C.RESET
              + " " * pad_s + C.ORCHID + subtitle + C.RESET
              + " " * max(0, width - pad_s - len(subtitle))
              + C.PURPLE_DARK + "║" + C.RESET)
    ts = datetime.now().strftime("%A, %d.%m.%Y  •  %H:%M:%S")
    pad2 = max(0, (width - len(ts)) // 2)
    print(C.PURPLE_DARK + "║" + C.RESET
          + " " * pad2 + C.GRAY + ts + C.RESET
          + " " * max(0, width - pad2 - len(ts))
          + C.PURPLE_DARK + "║" + C.RESET)
    gh_pad = max(0, (width - len(GITHUB) - 4) // 2)
    print(C.PURPLE_DARK + "║" + C.RESET
          + " " * gh_pad
          + C.GRAY + "⌥ " + C.RESET
          + C.LAVENDER + GITHUB + C.RESET
          + " " * max(0, width - gh_pad - len(GITHUB) - 4)
          + C.PURPLE_DARK + "║" + C.RESET)
    print(C.PURPLE_DARK + "╚" + "═" * width + "╝" + C.RESET)
    print()


def print_legend():
    print(f"  {C.PURPLE_LT}{ICON_EXT} External{C.RESET}    "
          f"{C.YELLOW}{ICON_LISTEN} Listen{C.RESET}    "
          f"{C.GREEN}{ICON_LOCAL} Local{C.RESET}")
    print()


def print_table(rows, animate=False):
    width = term_width()
    print("  "
          + f"{C.BOLD}{C.WHITE}"
          f"{'PID':<{W_PID}} "
          f"{'PROGRAM':<{W_PROC}} "
          f"{'PROTO':<{W_PROTO}} "
          f"{'LOCAL':<{W_LOCAL}} "
          f"{'REMOTE':<{W_REMOTE}} "
          f"{'STATUS':<{W_STAT}} "
          f"{'INFO'}"
          f"{C.RESET}")
    print(C.PURPLE_DARK + "─" * width + C.RESET)

    if not rows:
        print(f"  {C.YELLOW}No connections found.{C.RESET}")
        print(C.PURPLE_DARK + "─" * width + C.RESET)
        return

    for r in rows:
        if r["is_external"]:
            icon, col = ICON_EXT, C.PURPLE_LT
        elif r["is_listen"]:
            icon, col = ICON_LISTEN, C.YELLOW
        else:
            icon, col = ICON_LOCAL, C.GREEN

        info_plain = short_path(r["path"])
        info_col = C.GRAY

        proc_disp   = r["program"][:W_PROC - 1]
        local_disp  = r["local"][:W_LOCAL - 1]
        remote_disp = r["remote"][:W_REMOTE - 1]
        status_disp = r["status"][:W_STAT - 1]
        pid_disp    = str(r["pid"])[:W_PID - 1]

        if r["status"] == "ESTABLISHED":
            stat_col = C.YELLOW
        elif r["status"] in ("LISTEN", "NONE"):
            stat_col = C.ORCHID
        elif r["status"] in ("TIME_WAIT", "CLOSE_WAIT"):
            stat_col = C.DIM
        else:
            stat_col = C.GRAY

        line = (
            f"  {col}{icon}{C.RESET} "
            f"{C.GRAY}{pid_disp:<{W_PID}}{C.RESET}"
            f"{col}{proc_disp:<{W_PROC}}{C.RESET}"
            f"{C.MAGENTA}{r['proto']:<{W_PROTO}}{C.RESET}"
            f"{C.WHITE}{local_disp:<{W_LOCAL}}{C.RESET}"
            f"{col}{remote_disp:<{W_REMOTE}}{C.RESET}"
            f"{stat_col}{status_disp:<{W_STAT}}{C.RESET}"
            f"{info_col}{info_plain[:W_INFO]}{C.RESET}"
        )
        print(line)
        if animate:
            time.sleep(0.006)

    print(C.PURPLE_DARK + "─" * width + C.RESET)


def print_statistics(rows, animate=False):
    if not rows:
        return
    procs = Counter(r["program"] for r in rows)
    top = procs.most_common(8)

    width = min(60, term_width())
    print()
    print(f"  {C.BOLD}{C.WHITE}STATISTICS{C.RESET}")
    print(f"  {C.PURPLE_DARK}{'─' * width}{C.RESET}")
    max_count = top[0][1] if top else 1
    for name, count in top:
        bar_len = int(count / max_count * 30)
        bar = "█" * bar_len
        print(f"  {C.PURPLE_LT}{name[:28]:<28}{C.RESET} "
              f"{C.VIOLET}{bar:<30}{C.RESET} {C.BOLD}{count:>3}{C.RESET}")
        if animate:
            time.sleep(0.05)
    print()


def wait_for_enter(msg="Back to menu"):
    print()
    print(f"  {C.GRAY}Press {C.BOLD}{C.WHITE}ENTER{C.RESET}{C.GRAY} {msg}...{C.RESET}")
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass


def run_view(filter_pids=None, subtitle=""):
    clear()
    print_header(subtitle, animate=True)
    print_legend()
    cursor_hide()
    spinner_load("Scanning connections", 0.8)
    cursor_show()
    rows = collect(filter_pids)
    print_table(rows, animate=True)
    print_statistics(rows, animate=True)
    wait_for_enter("to return to the menu")


def snapshot_io():
    data = {}
    for conn in psutil.net_connections(kind="inet"):
        if not conn.raddr:
            continue
        key = (
            conn.pid or 0,
            conn.laddr.ip if conn.laddr else "",
            conn.laddr.port if conn.laddr else 0,
            conn.raddr.ip,
            conn.raddr.port,
        )
        try:
            p = psutil.Process(conn.pid) if conn.pid else None
            if p is None:
                continue
            io = p.io_counters()
            data[key] = (io.read_bytes, io.write_bytes, time.monotonic())
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            continue
    return data


def analyze_traffic(duration=TRAFFIC_WINDOW, interval=TRAFFIC_INTERVAL,
                    update_cb=None):
    samples = defaultdict(list)
    start = time.monotonic()
    last = snapshot_io()
    step = 0
    total_steps = int(duration / interval)

    while time.monotonic() - start < duration:
        time.sleep(interval)
        step += 1
        now_snap = snapshot_io()
        now = time.monotonic()

        for key, (rb, wb, _t) in now_snap.items():
            if key in last:
                prb, pwb, pt = last[key]
                dt = max(now - pt, 1e-6)
                rx = max(0, rb - prb) / dt
                tx = max(0, wb - pwb) / dt
                samples[key].append((rx, tx))

        last = now_snap
        if update_cb:
            update_cb(step, total_steps, samples)

    results = []
    for key, vals in samples.items():
        if not vals:
            continue
        pid, lip, lport, rip, rport = key
        avg_rx = sum(v[0] for v in vals) / len(vals)
        avg_tx = sum(v[1] for v in vals) / len(vals)
        peak_rx = max(v[0] for v in vals)
        peak_tx = max(v[1] for v in vals)
        total_rx = sum(v[0] for v in vals) * interval
        total_tx = sum(v[1] for v in vals) * interval
        results.append({
            "pid": pid,
            "lip": lip,
            "lport": lport,
            "rip": rip,
            "rport": rport,
            "avg_rx": avg_rx,
            "avg_tx": avg_tx,
            "peak_rx": peak_rx,
            "peak_tx": peak_tx,
            "total_rx": total_rx,
            "total_tx": total_tx,
            "samples": len(vals),
        })

    return results


def score_p2p(entry):
    score = 0
    reasons = []
    lport = entry["lport"]
    rport = entry["rport"]

    if lport >= TRAFFIC_HIGH_PORT_MIN:
        score += 2
        reasons.append(f"L:{lport}")
    if rport >= TRAFFIC_HIGH_PORT_MIN:
        score += 2
        reasons.append(f"R:{rport}")

    total_bytes = entry["total_rx"] + entry["total_tx"]
    if total_bytes >= TRAFFIC_MIN_BYTES:
        score += 1
        reasons.append(f"{int(total_bytes/1024)}KB")

    if entry["samples"] >= TRAFFIC_MIN_PACKETS:
        score += 1
        reasons.append(f"{entry['samples']}s")

    if entry["avg_rx"] > 1024 or entry["avg_tx"] > 1024:
        score += 1
        reasons.append("flow")

    if entry["peak_rx"] > 8192 or entry["peak_tx"] > 8192:
        score += 1
        reasons.append("burst")

    return score, reasons


def live_progress(step, total, samples):
    bar_len = 30
    filled = int(step / total * bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)
    sys.stdout.write(
        f"\r  {C.PURPLE_LT}Analyzing{C.RESET} "
        f"{C.VIOLET}{bar}{C.RESET} "
        f"{C.GRAY}{step}/{total}s  •  "
        f"{len(samples)} flows tracked{C.RESET}"
    )
    sys.stdout.flush()


def run_traffic_analysis():
    clear()
    width = term_width()
    print()
    print(f"  {C.BOLD}{C.PURPLE_LT}✦  N E T P E E K  —  TRAFFIC ANALYSIS  "
          f"{C.ORCHID}[BETA]{C.RESET}{C.BOLD}{C.PURPLE_LT}  ✦{C.RESET}")
    print(f"  {C.GRAY}{datetime.now().strftime('%A, %d.%m.%Y  •  %H:%M:%S')}{C.RESET}")
    print(f"  {C.GRAY}Window: {TRAFFIC_WINDOW}s   Interval: "
          f"{TRAFFIC_INTERVAL}s{C.RESET}")
    print(f"  {C.PURPLE_DARK}{'─' * width}{C.RESET}")
    print()

    cursor_hide()
    results = analyze_traffic(update_cb=live_progress)
    sys.stdout.write("\r" + " " * (width) + "\r")
    cursor_show()

    scored = []
    for entry in results:
        if not is_external(entry["rip"]):
            continue
        score, reasons = score_p2p(entry)
        if score >= 3:
            scored.append((score, reasons, entry))

    scored.sort(key=lambda x: (-x[0], -(x[2]["total_rx"] + x[2]["total_tx"])))

    clear()
    width = term_width()
    print()
    print(f"  {C.BOLD}{C.PURPLE_LT}✦  N E T P E E K  —  TRAFFIC ANALYSIS  "
          f"{C.ORCHID}[BETA]{C.RESET}{C.BOLD}{C.PURPLE_LT}  ✦{C.RESET}")
    print(f"  {C.GRAY}{datetime.now().strftime('%A, %d.%m.%Y  •  %H:%M:%S')}{C.RESET}")
    print(f"  {C.PURPLE_DARK}{'─' * width}{C.RESET}")
    print()

    if not scored:
        print(f"  {C.YELLOW}No suspicious P2P-like traffic detected "
              f"in the last {TRAFFIC_WINDOW}s.{C.RESET}")
    else:
        header = (f"  {C.BOLD}{C.WHITE}"
                  f"{'SCORE':<7} {'PID':<7} {'PROCESS':<22} "
                  f"{'LOCAL':<22} {'REMOTE':<22} "
                  f"{'RX/s':<10} {'TX/s':<10} {'TOTAL':<10} REASON"
                  f"{C.RESET}")
        print(header)
        print(f"  {C.PURPLE_DARK}{'─' * width}{C.RESET}")

        for score, reasons, e in scored:
            name, _exe = get_process_info(e["pid"])
            local = f"{e['lip']}:{e['lport']}"
            remote = f"{e['rip']}:{e['rport']}"
            total = e["total_rx"] + e["total_tx"]

            if score >= 5:
                scol = C.RED
            elif score >= 4:
                scol = C.ORANGE
            else:
                scol = C.YELLOW

            print(
                f"  {scol}{score:<7}{C.RESET} "
                f"{C.GRAY}{e['pid']:<7}{C.RESET} "
                f"{C.WHITE}{name[:21]:<22}{C.RESET} "
                f"{C.PURPLE_LT}{local[:21]:<22}{C.RESET} "
                f"{C.PURPLE_LT}{remote[:21]:<22}{C.RESET} "
                f"{C.LIME}{e['avg_rx']:<10.0f}{C.RESET} "
                f"{C.PINK}{e['avg_tx']:<10.0f}{C.RESET} "
                f"{C.LAVENDER}{total:<10.0f}{C.RESET} "
                f"{C.ORCHID}{','.join(reasons[:4])}{C.RESET}"
            )
            time.sleep(0.01)

        print(f"  {C.PURPLE_DARK}{'─' * width}{C.RESET}")
        print(f"  {C.GRAY}Flows analyzed: {C.BOLD}{C.WHITE}{len(results)}"
              f"{C.RESET}  •  "
              f"{C.GRAY}Suspicious: {C.BOLD}{C.WHITE}{len(scored)}{C.RESET}")

    print()
    print(f"  {C.GRAY}[R] Re-run   [ENTER] Back to menu{C.RESET}")
    print(f"  {C.GRAY}⌥ {C.LAVENDER}{GITHUB}{C.RESET}")
    try:
        choice = input(f"  {C.PURPLE_LT}➤ {C.RESET}").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return
    if choice == "r":
        run_traffic_analysis()


def main():
    try:
        startup_animation()
    except (KeyboardInterrupt, EOFError):
        cursor_show()
        return

    while True:
        show_main_menu()
        try:
            choice = input(f"  {C.BOLD}{C.PURPLE_LT}➤ {C.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if choice == "1":
            run_view(None, "ALL CONNECTIONS")

        elif choice == "2":
            cursor_hide()
            spinner_load("Reading processes", 0.7)
            cursor_show()
            procs = get_process_list()
            if not procs:
                print(f"  {C.RED}No processes found.{C.RESET}")
                input(f"  {C.GRAY}ENTER...{C.RESET}")
                continue

            selected_pids = show_process_menu(procs)
            if selected_pids:
                name = "?"
                for p in procs.values():
                    if p["pids"] & selected_pids:
                        name = p["name"]
                        break
                run_view(selected_pids, f"FILTER: {name}")

        elif choice == "3":
            run_traffic_analysis()

        elif choice == "4" or choice.lower() in ("q", "exit"):
            clear()
            print()
            try:
                pulse_print("  Bye!", C.PURPLE_LT, cycles=2, delay=0.1)
            except (KeyboardInterrupt, EOFError):
                pass
            print(f"  {C.GRAY}⌥ {C.LAVENDER}{GITHUB}{C.RESET}\n")
            break
        else:
            print(f"  {C.RED}Invalid choice.{C.RESET}")
            input(f"  {C.GRAY}ENTER...{C.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cursor_show()
        print(f"\n\n  {C.PURPLE_LT}Cancelled.{C.RESET}\n")