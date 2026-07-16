# frida-dexdump (Frida 17)

Dump in-memory DEX files from Android apps using **Frida 17**.

DEX search & dump logic is based on [hluwa/frida-dexdump](https://github.com/hluwa/frida-dexdump). This repo updates it for Frida 17 and writes dumps **on-device** under the app’s files directory.

## Features

- Frida 17 compatible (`frida.Compiler`, modern Gum APIs, `exports_sync`)
- Magic-header scan + optional deep search for broken/missing headers
- Saves DEX on the Android filesystem (no host pull required during dump)
- Progress logs while scanning memory ranges

## Requirements

- Python 3.8+
- [Frida](https://frida.re/) **17+** (`pip install frida frida-tools`)
- Matching `frida-server` (or Gadget) on the device

## Usage

```bash
# USB
python3 dexdump.py -n com.example.app -U -d

# Remote frida-server
python3 dexdump.py -n com.example.app -H 192.168.1.2:27042 -d
```

`dexdump.py` compiles `dexdump.js` with Frida’s compiler, spawns/attaches the target, then calls `dump()`.

### Options

| Flag | Description |
|------|-------------|
| `-P` / `--package` | Target package name |
| `-H` / `--host` | Remote `host:port` (default: `192.168.1.2:27042`) |
| `-U` / `--usb` | Use USB device |
| `-a` / `--attach` | Attach instead of spawn |
| `-d` / `--deep-search` | Deep search (broken / headerless DEX) |
| `-o` / `--output` | Custom on-device output directory |
| `--sleep N` | Wait N seconds after resume before dump (default: `5`) |

### Output path

By default, dumps are written to:

```text
/data/data/<package>/files/dexes/classes.dex
/data/data/<package>/files/dexes/classes2.dex
...
```

Pull them later if needed:

```bash
adb pull /data/data/<package>/files/dexes
```

## Files

| File | Role |
|------|------|
| `dexdump.py` | Host runner — compile, spawn/attach, trigger dump |
| `dexdump.js` | Frida agent — search memory & write DEX on device |

## Credits

DEX dumping approach and core search logic come from:

- **[hluwa/frida-dexdump](https://github.com/hluwa/frida-dexdump)** by [hluwa](https://github.com/hluwa)

Please star / credit the original project if this is useful.

Internals write-up (original author):

- [《深入 FRIDA-DEXDump 中的矛与盾》](https://mp.weixin.qq.com/s/n2XHGhshTmvt2FhxyFfoMA)

## License

Same spirit as the upstream project — see [LICENSE](LICENSE) (GPLv3).
