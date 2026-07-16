import argparse
import os
import time
import frida

SOURCE = "dexdump.js"
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

def on_message(message, data):
    if message["type"] == "send":
        payload = message.get("payload")
        print(f"[*] {payload}")
    elif message["type"] == "error":
        print(f"[!] {message.get('description') or message}")
        if message.get("stack"):
            print(message["stack"])
    else:
        print(message)

def on_detached(reason, crash):
    print(f"[!] Session detached: {reason}")
    if crash:
        print(crash)

def compile_script():
    print("[*] Compiling script...")
    compiler = frida.Compiler()
    compiler.on("diagnostics", lambda diag: print(f"[compiler] {diag}"))
    bundle = compiler.build(SOURCE, project_root=PROJECT_ROOT)
    print("[*] Compiled OK")
    return bundle

def main():
    parser = argparse.ArgumentParser(description="Dump DEX files on-device with Frida 17")
    parser.add_argument("-P", "--package", default="com.example.app", help="Target package name (default: com.example.app)")
    parser.add_argument("-H", "--host", default="192.168.1.2:27042", help="Remote frida-server host:port (omit with --usb)")
    parser.add_argument("-U", "--usb", action="store_true", help="Use USB device")
    parser.add_argument("-s", "--spawn", action="store_true", default=True, help="Spawn the target (default)")
    parser.add_argument("-a", "--attach", action="store_true", help="Attach to a running process instead of spawn")
    parser.add_argument("-d", "--deep-search", action="store_true", help="Enable deep search for broken-header DEX")
    parser.add_argument("-o", "--output", default=None, help="On-device output dir (default: /data/data/<pkg>/files/dexes)")
    parser.add_argument("--sleep", type=float, default=5.0, help="Seconds to wait after resume before dump (default: 5)")
    
    args = parser.parse_args()
    bundle = compile_script()
    spawn_mode = not args.attach
    pid = None

    if args.usb:
        device = frida.get_usb_device()
    else:
        device = frida.get_device_manager().add_remote_device(address=args.host)

    print(f"[*] Device: {device}")

    if spawn_mode:
        try:
            pid = device.spawn(args.package)
            print(f"[*] Spawned {args.package} (pid {pid})")
        except frida.ExecutableNotFoundError:
            print(f"[*] Error spawning {args.package}: executable not found")
            return
        session = device.attach(pid)
    else:
        session = device.attach(args.package)
        print(f"[*] Attached to {args.package}")

    session.on("detached", on_detached)
    script = session.create_script(bundle)
    script.on("message", on_message)
    script.load()

    if spawn_mode and pid is not None:
        device.resume(pid)
        print("[*] Process resumed")

    if args.sleep > 0:
        print(f"[*] Waiting {args.sleep}s...")
        time.sleep(args.sleep)

    print("[*] Dumping DEX on device...")
    result = script.exports_sync.dump(args.deep_search, args.output)

    print(f"[*] Package : {result.get('package')}")
    print(f"[*] Output  : {result.get('outputDir')}")
    print(f"[*] Found   : {result.get('found')}")
    print(f"[*] Saved   : {len(result.get('saved') or [])}")

    for item in result.get("saved") or []:
        print(f"    {item['path']}  ({hex(item['size'])} @ {item['addr']})")

    try:
        session.detach()
    except Exception:
        pass

if __name__ == "__main__":
    main()
