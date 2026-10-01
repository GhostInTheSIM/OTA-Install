#!/usr/bin/env python3

"""Frida host that injects the SMS-DELIVER PDUs produced by
smpp-ota-install-applet.py (--pdus-file) into an Android phone's telephony
stack, and decodes the Proof-of-Receipt (PoR) each one returns.

It attaches to com.android.phone by name, loads frida-ota-agent.js, and hands
it the list of PDUs read from the JSON file. The agent injects them one at a
time (each after the previous PoR), and reports every PoR back here for
decoding with the same pySim OTA code the install script uses.

Requires the 'frida' Python package (installed with frida-tools) and, for PoR
decoding, PYTHONPATH pointing to the pySim checkout:

    PYTHONPATH=/path/to/pysim ./frida-ota-inject.py --pdus-file pdus.json \\
        --kic <KIC> --kid <KID>
"""

import argparse
import json
import sys
import threading
from pathlib import Path

import frida

option_parser = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
)
option_parser.add_argument(
    "--pdus-file",
    required=True,
    help="JSON file written by smpp-ota-install-applet.py --pdus-file",
)
option_parser.add_argument(
    "-p",
    "--process",
    default="com.android.phone",
    help="Target process (name or PID) to attach to",
)
option_parser.add_argument(
    "--slot", type=int, default=0, help="SIM slot (0 = slot 1, 1 = slot 2)"
)
option_parser.add_argument(
    "--device-id", default=None, help="Frida device ID; default is the first USB device"
)

# OTA options for decoding the PoR (must match the ones used to generate the PDUs).
dec_group = option_parser.add_argument_group("PoR Decoding Options")
dec_group.add_argument(
    "--kic", default=None, help="OTA key (KIC), for decoding the PoR"
)
dec_group.add_argument(
    "--kid", default=None, help="OTA key (KID), for decoding the PoR"
)
dec_group.add_argument("--kic-idx", type=int, default=1)
dec_group.add_argument("--kid-idx", type=int, default=1)
dec_group.add_argument("--algo-crypt", default="triple_des_cbc2")
dec_group.add_argument("--algo-auth", default="triple_des_cbc2")
dec_group.add_argument("--cntr", type=int, default=0)
dec_group.add_argument("--por-rc-cc-ds", default="cc")
dec_group.add_argument("--por-no-ciphering", action="store_true", default=False)


class PorDecoder:
    """Decodes PoR payloads using pySim, mirroring the install script's handler."""

    def __init__(self, opts):
        from pySim.ota import OtaKeyset, OtaDialectSms, OtaCheckError, CompactRemoteResp
        from pySim.sms import UserDataHeader
        from pySim.utils import h2b

        self._h2b = h2b
        self._retry_errors = (ValueError, OtaCheckError)
        self._CompactRemoteResp = CompactRemoteResp
        self._UserDataHeader = UserDataHeader
        self.dialect = OtaDialectSms()
        self.keyset = None
        if opts.kic and opts.kid:
            self.keyset = OtaKeyset(
                algo_crypt=opts.algo_crypt,
                kic_idx=opts.kic_idx,
                kic=h2b(opts.kic),
                algo_auth=opts.algo_auth,
                kid_idx=opts.kid_idx,
                kid=h2b(opts.kid),
                cntr=opts.cntr,
            )
        self.spi = {
            "por_shall_be_ciphered": not opts.por_no_ciphering,
            "por_rc_cc_ds": opts.por_rc_cc_ds,
        }

    def _decode_unverified(self, data):
        """Parse an unciphered PoR without verifying its checksum (needs no keys)."""
        if data[0] != 0x02:
            raise ValueError("Unexpected UDL=0x%02x" % data[0])
        udhd, remainder = self._UserDataHeader.from_bytes(data)
        if not udhd.has_ie(0x71):
            raise ValueError("RPI 0x71 not found in UDH")
        por = self.dialect.SmsResponsePacket.parse(remainder)
        remote = None
        if por["response_status"] == "por_ok" and len(por["secured_data"]):
            remote = self._CompactRemoteResp.parse(por["secured_data"])
        return por, remote

    def decode(self, payload_hex):
        data = self._h2b(payload_hex)
        if self.keyset is None:
            por, remote = self._decode_unverified(data)
            status = str(por["response_status"])
            if remote is not None:
                return (
                    status,
                    str(remote["last_status_word"]),
                    str(remote["last_response_data"]),
                )
            return status, None, None
        try:
            por, remote = self.dialect.decode_resp(self.keyset, self.spi, data)
        except self._retry_errors:
            spi = self.spi.copy()
            spi["por_shall_be_ciphered"] = False
            spi["por_rc_cc_ds"] = "no_rc_cc_ds"
            por, remote = self.dialect.decode_resp(self.keyset, spi, data)
        status = str(por["response_status"])
        if remote is not None:
            return (
                status,
                str(remote["last_status_word"]),
                str(remote["last_response_data"]),
            )
        return status, None, None


def compile_agent():
    """Compile the agent into a single script bundle."""
    project_root = Path(__file__).resolve().parent
    if not (project_root / "node_modules" / "frida-java-bridge").exists():
        sys.exit(
            f"frida-java-bridge not found in {project_root / 'node_modules'}; "
            f"run 'npm install frida-java-bridge' in {project_root} first"
        )
    compiler = frida.Compiler()
    compiler.on("diagnostics", lambda diag: print(f"[-] agent compiler: {diag}"))
    return compiler.build("frida-ota-agent.js", project_root=str(project_root))


def main():
    opts = option_parser.parse_args()

    pdus_path = Path(opts.pdus_file)
    if not pdus_path.exists():
        sys.exit(f"PDU file does not exist: {pdus_path}")
    entries = json.loads(pdus_path.read_text())
    titles = [e.get("title", f"PDU {i + 1}") for i, e in enumerate(entries)]
    pdus_hex = [e["pdu"] for e in entries]
    print(f"[+] Loaded {len(pdus_hex)} PDU(s) from {pdus_path}")

    decoder = None
    if (opts.kic and opts.kid) or opts.por_no_ciphering:
        try:
            decoder = PorDecoder(opts)
        except ImportError as e:
            print(
                f"[!] pySim not importable ({e}); PoRs will be shown as raw hex. "
                f"Set PYTHONPATH to the pySim checkout to decode them."
            )
        else:
            if decoder.keyset is None:
                print(
                    "[!] --kic/--kid not given: PoRs are decoded but their checksum is NOT verified."
                )
    else:
        print(
            "[!] --kic/--kid not given and PoRs are ciphered: they will be shown as raw hex, "
            "not decoded (pass --kic/--kid, or --por-no-ciphering if the card sends them unciphered)."
        )

    finished = threading.Event()
    failure = {"msg": None}

    def report_por(payload):
        title = titles[report_por.idx] if report_por.idx < len(titles) else "?"
        report_por.idx += 1
        sw = f"{payload['sw1']:02x}{payload['sw2']:02x}"
        if decoder is None:
            print(f"    PoR (SW {sw}): {payload['hex']}")
            return
        try:
            status, last_sw, last_resp = decoder.decode(payload["hex"])
        except Exception as e:
            print(f"    PoR (SW {sw}): decode failed: {e}; raw {payload['hex']}")
            return
        line = f"    PoR: {status}"
        if last_sw is not None:
            line += f", R-APDU SW {last_sw}"
            if last_resp:
                line += f", data {last_resp}"
        print(line)
        if status != "por_ok":
            print(f"[!] [{title}] card reported PoR status '{status}'")

    report_por.idx = 0

    def on_message(message, data):
        if message["type"] == "error":
            print(f"[-] agent error: {message.get('description', message)}")
            failure["msg"] = "agent script error"
            finished.set()
            return
        payload = message.get("payload", {})
        kind = payload.get("type")
        if kind == "log":
            print(f"[+] {payload['message']}")
        elif kind == "error":
            print(f"[-] {payload['message']}")
            failure["msg"] = payload["message"]
            finished.set()
        elif kind == "inject":
            title = titles[payload["index"]] if payload["index"] < len(titles) else "?"
            print(f"[+] Injecting [{payload['index'] + 1}/{payload['total']}] {title}")
        elif kind == "por":
            report_por(payload)
        elif kind == "timeout":
            title = titles[payload["index"]] if payload["index"] < len(titles) else "?"
            print(
                f"[!] No PoR for [{payload['index'] + 1}] {title} within timeout; advancing"
            )
        elif kind == "done":
            print(f"[+] Done: {payload['count']} PDU(s) injected")
            finished.set()

    if opts.device_id:
        device = frida.get_device(opts.device_id)
    else:
        device = frida.get_usb_device(timeout=5)
    print(f"[+] Using device: {device.name}")

    target = int(opts.process) if opts.process.isdigit() else opts.process
    session = device.attach(target)
    print(f"[+] Attached to {opts.process}")

    script = session.create_script(compile_agent())
    script.on("message", on_message)
    script.load()

    script.exports_sync.inject(pdus_hex, opts.slot)

    if not finished.wait(timeout=len(pdus_hex) * 10 + 30):
        print("[!] Timed out waiting for the agent to finish")
        failure["msg"] = "host timeout"

    session.detach()
    sys.exit(1 if failure["msg"] else 0)


if __name__ == "__main__":
    main()
