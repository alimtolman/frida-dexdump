import Java from "frida-java-bridge";

function verifyByMaps(dexptr, mapsptr) {
    const mapsOffset = dexptr.add(0x34).readUInt();
    const mapsSize = mapsptr.readUInt();

    for (let i = 0; i < mapsSize; i++) {
        const itemType = mapsptr.add(4 + i * 0xC).readU16();

        if (itemType === 4096) {
            const mapOffset = mapsptr.add(4 + i * 0xC + 8).readUInt();

            if (mapsOffset === mapOffset)
                return true;
        }
    }
    return false;
}

function getMapsAddress(dexptr, rangeBase, rangeEnd) {
    const mapsOffset = dexptr.add(0x34).readUInt();

    if (mapsOffset === 0)
        return null;

    const mapsAddress = dexptr.add(mapsOffset);

    if (mapsAddress < rangeBase || mapsAddress > rangeEnd)
        return null;

    return mapsAddress;
}

function getMapsEnd(maps, rangeBase, rangeEnd) {
    const mapsSize = maps.readUInt();

    if (mapsSize < 2 || mapsSize > 50)
        return null;

    const mapsEnd = maps.add(mapsSize * 0xC + 4);

    if (mapsEnd < rangeBase || mapsEnd > rangeEnd)
        return null;

    return mapsEnd;
}

function getDexRealSize(dexptr, rangeBase, rangeEnd) {
    const dexSize = dexptr.add(0x20).readUInt();
    const mapsAddress = getMapsAddress(dexptr, rangeBase, rangeEnd);

    if (!mapsAddress)
        return dexSize;

    const mapsEnd = getMapsEnd(mapsAddress, rangeBase, rangeEnd);

    if (!mapsEnd)
        return dexSize;

    return mapsEnd.sub(dexptr).toInt32();
}

function verify(dexptr, range, enableVerifyMaps) {
    if (range == null)
        return false;

    const rangeEnd = range.base.add(range.size);

    if (dexptr.add(0x70) > rangeEnd)
        return false;

    if (enableVerifyMaps) {
        const mapsAddress = getMapsAddress(dexptr, range.base, rangeEnd);

        if (!mapsAddress)
            return false;

        const mapsEnd = getMapsEnd(mapsAddress, range.base, rangeEnd);

        if (!mapsEnd)
            return false;

        return verifyByMaps(dexptr, mapsAddress);
    }

    return dexptr.add(0x3C).readUInt() === 0x70;
}

function verifyIdsOff(dexptr, dexSize) {
    const stringIdsOff = dexptr.add(0x3C).readUInt();
    const typeIdsOff = dexptr.add(0x44).readUInt();
    const protoIdsOff = dexptr.add(0x4C).readUInt();
    const fieldIdsOff = dexptr.add(0x54).readUInt();
    const methodIdsOff = dexptr.add(0x5C).readUInt();

    return stringIdsOff < dexSize && stringIdsOff >= 0x70
        && typeIdsOff < dexSize && typeIdsOff >= 0x70
        && protoIdsOff < dexSize && protoIdsOff >= 0x70
        && fieldIdsOff < dexSize && fieldIdsOff >= 0x70
        && methodIdsOff < dexSize && methodIdsOff >= 0x70;
}

function searchDex(deepSearch) {
    const result = [];
    const ranges = Process.enumerateRanges("r--");
    const total = ranges.length;
    const logEvery = Math.max(1, Math.floor(total / 20));

    send({
        type: "status",
        message: "Scanning " + total + " readable range(s)" + (deepSearch ? " [deep]" : "")
    });

    for (let i = 0; i < total; i++) {
        const range = ranges[i];

        if (i === 0 || i === total - 1 || (i + 1) % logEvery === 0) {
            const pct = Math.floor(((i + 1) / total) * 100);

            send({
                type: "progress",
                message: "Search " + (i + 1) + "/" + total + " (" + pct + "%) — found " + result.length
                    + " @ " + range.base + " +" + range.size
            });
        }

        try {
            Memory.scanSync(range.base, range.size, "64 65 78 0a 30 ?? ?? 00").forEach(function(match) {
                if (range.file && range.file.path
                    && (range.file.path.indexOf("/data/dalvik-cache/") === 0
                        || range.file.path.indexOf("/system/") === 0)) {
                    return;
                }

                if (verify(match.address, range, false)) {
                    const dexSize = getDexRealSize(match.address, range.base, range.base.add(range.size));

                    result.push({ addr: match.address, size: dexSize });
                    send({
                        type: "found",
                        message: "DEX magic @ " + match.address + " size=" + dexSize
                    });

                    const maxSize = range.size - match.address.sub(range.base).toInt32();

                    if (deepSearch && maxSize !== dexSize)
                        result.push({ addr: match.address, size: maxSize });
                }
            });

            if (deepSearch) {
                Memory.scanSync(range.base, range.size, "70 00 00 00").forEach(function(match) {
                    const dexBase = match.address.sub(0x3C);
                    
                    if (dexBase < range.base)
                        return;

                    if (dexBase.readCString(4) !== "dex\n" && verify(dexBase, range, true)) {
                        const realDexSize = getDexRealSize(dexBase, range.base, range.base.add(range.size));

                        if (!verifyIdsOff(dexBase, realDexSize))
                            return;

                        result.push({ addr: dexBase, size: realDexSize });
                        send({
                            type: "found",
                            message: "DEX (deep) @ " + dexBase + " size=" + realDexSize
                        });

                        const maxSize = range.size - dexBase.sub(range.base).toInt32();

                        if (maxSize !== realDexSize)
                            result.push({ addr: dexBase, size: maxSize });
                    }
                });
            } else if (range.base.readCString(4) !== "dex\n" && verify(range.base, range, true)) {
                const realDexSize = getDexRealSize(range.base, range.base, range.base.add(range.size));

                result.push({ addr: range.base, size: realDexSize });
                send({
                    type: "found",
                    message: "DEX (headerless) @ " + range.base + " size=" + realDexSize
                });
            }
        } catch (e) {
            // ignore unreadable ranges
        }
    }

    send({
        type: "status",
        message: "Search done — " + result.length + " candidate(s)"
    });

    return result;
}

function setReadPermission(base, size) {
    const end = base.add(size);

    Process.enumerateRanges("---").forEach(function (range) {
        const rangeEnd = range.base.add(range.size);

        if (range.base < base || rangeEnd > end)
            return;

        if (!range.protection.startsWith("r"))
            Memory.protect(range.base, range.size, "r" + range.protection.substring(1, 3));
    });
}

function getPackageName() {
    try {
        const raw = new Uint8Array(File.readAllBytes("/proc/self/cmdline"));
        let end = raw.indexOf(0);

        if (end < 0)
            end = raw.length;

        const name = String.fromCharCode.apply(null, Array.prototype.slice.call(raw, 0, end)).trim();

        if (name)
            return name;
    } catch (e) {
    }
    return "unknown";
}

function ensureDir(path) {
    const mkdirPtr = Module.findGlobalExportByName("mkdir");

    if (mkdirPtr === null)
        throw new Error("mkdir not found");

    const mkdir = new NativeFunction(mkdirPtr, "int", ["pointer", "int"]);
    const parts = path.split("/");
    let cur = "";

    for (let i = 0; i < parts.length; i++) {
        if (!parts[i])
            continue;

        cur += "/" + parts[i];
        mkdir(Memory.allocUtf8String(cur), 0o755);
    }
}

function fingerprint(buf) {
    return Checksum.compute("md5", buf);
}

function fixHeader(buf) {
    const bytes = new Uint8Array(buf.slice(0));
    const size = bytes.length;

    if (bytes[0] !== 0x64 || bytes[1] !== 0x65 || bytes[2] !== 0x78 || bytes[3] !== 0x0a) {
        bytes[0] = 0x64; // d
        bytes[1] = 0x65; // e
        bytes[2] = 0x78; // x
        bytes[3] = 0x0a; // \n
        bytes[4] = 0x30; // 0
        bytes[5] = 0x33; // 3
        bytes[6] = 0x35; // 5
        bytes[7] = 0x00;
    }

    function writeU32(off, value) {
        bytes[off] = value & 0xff;
        bytes[off + 1] = (value >> 8) & 0xff;
        bytes[off + 2] = (value >> 16) & 0xff;
        bytes[off + 3] = (value >> 24) & 0xff;
    }

    if (size >= 0x24)
        writeU32(0x20, size);

    if (size >= 0x28)
        writeU32(0x24, 0x70);

    if (size >= 0x2C) {
        const le = bytes[0x28] === 0x78 && bytes[0x29] === 0x56 && bytes[0x2A] === 0x34 && bytes[0x2B] === 0x12;
        const be = bytes[0x28] === 0x12 && bytes[0x29] === 0x34 && bytes[0x2A] === 0x56 && bytes[0x2B] === 0x78;

        if (!le && !be) {
            bytes[0x28] = 0x78;
            bytes[0x29] = 0x56;
            bytes[0x2A] = 0x34;
            bytes[0x2B] = 0x12;
        }
    }

    return bytes.buffer;
}

function dumpToDevice(deepSearch, outputDir) {
    const pkg = getPackageName();
    const outDir = outputDir || ("/data/data/" + pkg + "/files/dexes");

    ensureDir(outDir);

    send({ type: "status", message: "Searching DEX in " + pkg });
    
    const found = searchDex(!!deepSearch);
    
    send({ type: "status", message: "Found " + found.length + " candidate(s)" });

    const seen = {};
    const saved = [];
    let idx = 1;

    for (let i = 0; i < found.length; i++) {
        const item = found[i];
    
        try {
            const base = ptr(item.addr);
            const size = item.size;

            setReadPermission(base, size);

            let buf = base.readByteArray(size);

            if (buf === null)
                continue;

            buf = fixHeader(buf);
            const fp = fingerprint(buf);

            if (seen[fp])
                continue;

            seen[fp] = true;

            const name = idx === 1 ? "classes.dex" : ("classes" + idx + ".dex");
            const path = outDir + "/" + name;

            File.writeAllBytes(path, buf);
            saved.push({
                path: path,
                addr: base.toString(),
                size: size
            });
            send({
                type: "saved",
                path: path,
                addr: base.toString(),
                size: size
            });

            idx++;
        } catch (e) {
            send({ type: "error", message: e.toString(), addr: String(item.addr) });
        }
    }

    return {
        package: pkg,
        outputDir: outDir,
        found: found.length,
        saved: saved
    };
}

rpc.exports = {
    dump: function (deepSearch, outputDir) {
        return dumpToDevice(deepSearch, outputDir);
    },
    searchdex: function (deepSearch) {
        return searchDex(!!deepSearch).map(function (item) {
            return { addr: item.addr.toString(), size: item.size };
        });
    }
};

send({ type: "ready", package: getPackageName() });
