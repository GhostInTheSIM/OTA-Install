#!/usr/bin/env python3

import argparse
import json
import logging
import time
import sys
import smpplib.client
import smpplib.consts
from pathlib import Path
from osmocom.utils import swap_nibbles
from osmocom.tlv import bertlv_encode_len
from pySim.global_platform.install_param import InstallParams
from pySim.ota import (
    OtaKeyset,
    OtaDialectSms,
    OtaAlgoCrypt,
    OtaAlgoAuth,
    OtaCheckError,
    CNTR_REQ,
    RC_CC_DS,
    POR_REQ,
)
from pySim.javacard import CapFile
from pySim.sms import SMS_DELIVER, AddressField
from pySim.utils import b2h, h2b, is_hexstr

logger = logging.getLogger(Path(__file__).stem)

option_parser = argparse.ArgumentParser(
    description="Tool to perform complete Java Card applet installation (.cap file) over SMPP via Secured OTA SMS",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)

# Input file
option_parser.add_argument(
    "cap_file",
    type=str,
    nargs="?",
    default=None,
    help="Path to the Java Card .cap file to install (optional with --delete-only and --loadfile-aid)",
)

# SMPP Connection parameters
smpp_group = option_parser.add_argument_group("SMPP Connection Options")
smpp_group.add_argument(
    "--host", help="Host/IP of the SMPP server", default="localhost"
)
smpp_group.add_argument(
    "--port", help="TCP port of the SMPP server", default=2775, type=int
)
smpp_group.add_argument(
    "--system-id", help="System ID to use to bind to the SMPP server", default="test"
)
smpp_group.add_argument(
    "--password", help="Password to use to bind to the SMPP server", default="test"
)
smpp_group.add_argument(
    "--src-addr", default="12", type=str, help="SMS source address (MSISDN)"
)
smpp_group.add_argument(
    "--dest-addr", default="23", type=str, help="SMS destination address (MSISDN)"
)
smpp_group.add_argument(
    "--timeout",
    default=10,
    type=int,
    help="Maximum response waiting time per SMS (seconds)",
)
smpp_group.add_argument(
    "--verbose", help="Enable verbose logging", action="store_true", default=False
)
smpp_group.add_argument(
    "--dry-run",
    help="Print APDUs and OTA packets without connecting to SMPP server",
    action="store_true",
    default=False,
)

# Output of the SMS-DELIVER PDUs
output_group = option_parser.add_argument_group("PDU Output Options")
output_group.add_argument(
    "--pdus-file",
    type=str,
    default=None,
    help="Write all generated/transmitted SMS-DELIVER PDUs to this file as JSON "
    '(a list of {"title", "pdu"} objects)',
)
output_group.add_argument(
    "--smsc-addr",
    type=str,
    default=None,
    help='SMSC address to prepend to each PDU written to --pdus-file (use a leading "+" '
    "for an international number, same rules as --src-addr), as expected by "
    'Android\'s injectSmsPdu() for the "3gpp" format',
)

# OTA Security parameters
ota_group = option_parser.add_argument_group("OTA Security Options")
algo_crypt_choices = [cls.enum_name for cls in OtaAlgoCrypt.__subclasses__()]
ota_group.add_argument(
    "--algo-crypt",
    choices=algo_crypt_choices,
    default="triple_des_cbc2",
    help="OTA crypt algorithm",
)
algo_auth_choices = [cls.enum_name for cls in OtaAlgoAuth.__subclasses__()]
ota_group.add_argument(
    "--algo-auth",
    choices=algo_auth_choices,
    default="triple_des_cbc2",
    help="OTA auth algorithm",
)
ota_group.add_argument("--kic", required=True, type=is_hexstr, help="OTA key (KIC)")
ota_group.add_argument("--kic-idx", default=1, type=int, help="OTA key index (KIC)")
ota_group.add_argument("--kid", required=True, type=is_hexstr, help="OTA key (KID)")
ota_group.add_argument("--kid-idx", default=1, type=int, help="OTA key index (KID)")
ota_group.add_argument("--cntr", default=0, type=int, help="replay protection counter")
ota_group.add_argument(
    "--tar",
    default="000000",
    type=is_hexstr,
    help="Toolkit Application Reference (TAR) for RAM",
)
ota_group.add_argument(
    "--cntr-req",
    choices=CNTR_REQ.decmapping.values(),
    default="no_counter",
    help="Counter requirement",
)
ota_group.add_argument(
    "--no-ciphering", action="store_true", default=False, help="Disable ciphering"
)
ota_group.add_argument(
    "--rc-cc-ds",
    choices=RC_CC_DS.decmapping.values(),
    default="cc",
    help="message check (rc/cc/ds)",
)
ota_group.add_argument(
    "--por-in-submit",
    action="store_true",
    default=False,
    help="require PoR to be sent via SMS-SUBMIT",
)
ota_group.add_argument(
    "--por-no-ciphering",
    action="store_true",
    default=False,
    help="Disable ciphering (PoR)",
)
ota_group.add_argument(
    "--por-rc-cc-ds",
    choices=RC_CC_DS.decmapping.values(),
    default="cc",
    help="PoR check (rc/cc/ds)",
)
ota_group.add_argument(
    "--por-req",
    choices=POR_REQ.decmapping.values(),
    default="por_required",
    help="Proof of Receipt requirements",
)

# Applet Installation parameters
gp_group = option_parser.add_argument_group(
    "GlobalPlatform / Applet Installation Options"
)
gp_group.add_argument(
    "--delete-existing",
    action="store_true",
    default=False,
    help="Attempt deleting existing package/applet before loading",
)
gp_group.add_argument(
    "--delete-only",
    action="store_true",
    default=False,
    help="Only delete the package (Executable Load File) and its applet instances, without installing; "
    "the AID is taken from --loadfile-aid or from the .cap file",
)
gp_group.add_argument(
    "--loadfile-aid",
    type=is_hexstr,
    help="Override Executable Load File (Package) AID (hex)",
)
gp_group.add_argument(
    "--sd-aid", type=is_hexstr, default="", help="Security Domain (ISD) AID (hex)"
)
gp_group.add_argument(
    "--module-aid", type=is_hexstr, help="Override Executable Module AID (hex)"
)
gp_group.add_argument(
    "--instance-aid", type=is_hexstr, help="Override Application Instance AID (hex)"
)
gp_group.add_argument(
    "--privileges",
    default="00",
    type=is_hexstr,
    help="Application privileges hex string",
)
gp_group.add_argument(
    "--max-block-size",
    type=int,
    default=96,
    help="Max payload block size in bytes per LOAD APDU",
)

# Load Parameters of INSTALL [for load]: either given as a whole or built from the distinct options
load_prm_group = option_parser.add_argument_group(
    "Load Parameters (INSTALL [for load])",
    "Unless --load-parameters is given, the parameters are built from the "
    "code size of the load file and the optional --load-parameters-* values",
)
load_prm_group.add_argument(
    "--load-parameters",
    type=is_hexstr,
    default=None,
    help='Load Parameters (GPC_SPE_034, section 11.5.2.3.7, table 11-49); pass "" to send none',
)
load_prm_group.add_argument(
    "--load-parameters-volatile-memory",
    type=int,
    default=None,
    help="Volatile data minimum memory requirement (GPC_SPE_034, table 11-49)",
)
load_prm_group.add_argument(
    "--load-parameters-non-volatile-memory",
    type=int,
    default=None,
    help="Non-volatile data minimum memory requirement (GPC_SPE_034, table 11-49)",
)

# Install Parameters of INSTALL [for install]: either given as a whole or built from the distinct options
inst_prm_group = option_parser.add_argument_group(
    "Install Parameters (INSTALL [for install])",
    "Unless --install-parameters is given, the parameters are built from "
    "--app-parameters, the optional --install-parameters-* values and the "
    "SIM Toolkit options",
)
inst_prm_group.add_argument(
    "--install-parameters",
    type=is_hexstr,
    default=None,
    help="Install Parameters (GPC_SPE_034, section 11.5.2.3.7, table 11-49)",
)
inst_prm_group.add_argument(
    "--app-parameters",
    type=is_hexstr,
    default=None,
    help="Application-specific parameters (hex), passed to the install() method of the applet",
)
inst_prm_group.add_argument(
    "--install-parameters-volatile-memory-quota",
    type=int,
    default=None,
    help="Volatile memory quota (GPC_SPE_034, section 11.5.2.3.7, table 11-49)",
)
inst_prm_group.add_argument(
    "--install-parameters-non-volatile-memory-quota",
    type=int,
    default=None,
    help="Non-volatile memory quota (GPC_SPE_034, section 11.5.2.3.7, table 11-49)",
)

# SIM Toolkit parameters (part of the Install Parameters)
stk_group = option_parser.add_argument_group(
    "SIM Toolkit Parameters (ETSI TS 102 226, section 8.2.1.3.2.1)"
)
stk_group.add_argument(
    "--enable-sim-toolkit",
    action="store_true",
    default=False,
    help="Include SIM Toolkit parameters in install command",
)
stk_group.add_argument(
    "--access-domain",
    default="ff",
    type=is_hexstr,
    help="SIM Toolkit access domain (hex)",
)
stk_group.add_argument(
    "--priority-level",
    default="01",
    type=is_hexstr,
    help="SIM Toolkit priority level (2 hex chars)",
)
stk_group.add_argument(
    "--max-timers", type=int, default=0, help="SIM Toolkit max timers count"
)
stk_group.add_argument(
    "--max-menu-entry-text",
    type=int,
    default=16,
    help="SIM Toolkit max menu entry text length",
)
stk_group.add_argument(
    "--max-menu-entries", type=int, default=0, help="SIM Toolkit max menu entries count"
)
stk_group.add_argument(
    "--max-channels", type=int, default=0, help="SIM Toolkit max channels count"
)
stk_group.add_argument(
    "--applet-tar",
    type=is_hexstr,
    default="",
    help="TAR value for the installed applet parameters (hex)",
)


def build_address_field(addr: str) -> AddressField:
    """Build an AddressField (TON/NPI + BCD digits) from an MSISDN; a leading '+' or more than
    10 digits select an international number."""
    digits = addr.lstrip("+")
    ton = "international" if addr.startswith("+") or len(digits) > 10 else "unknown"
    return AddressField(digits, ton, "isdn_e164")


def build_sms_deliver_tpdu(
    payload: bytes, src_addr: str, pid: int = 0x7F, dcs: int = 0xF6
) -> bytes:
    """Construct a full 3GPP TS 23.040 SMS-DELIVER TPDU."""
    # Service Centre Time Stamp in BCD, timezone offset +00 quarters
    scts = h2b(swap_nibbles(time.strftime("%y%m%d%H%M%S")) + "00")
    deliver = SMS_DELIVER(
        tp_udhi=True,
        tp_oa=build_address_field(src_addr),
        tp_pid=pid,
        tp_dcs=dcs,
        tp_scts=scts,
        tp_udl=len(payload),
        tp_ud=payload,
    )
    return bytes(deliver.to_bytes())


def encode_smsc_address(smsc_addr: str) -> bytes:
    """Encode an SMSC address as it precedes the TPDU in a PDU (3GPP TS 27.005, section 3.1 <pdu>; 3GPP TS 24.011,
    section 8.2.5.1): unlike the TP-OA, the length counts octets (TON/NPI + BCD digits), not digits.
    """
    # strip the TP-OA style length (number of digits) and replace it by the number of octets
    ton_npi_bcd = build_address_field(smsc_addr).to_bytes()[1:]
    return bytes([len(ton_npi_bcd)]) + ton_npi_bcd


def is_success_sw(sw: bytes) -> bool:
    return sw == b"\x90\x00" or len(sw) == 2 and sw[0] in [0x61, 0x62, 0x63, 0x6F]


class SmppHandler:
    """Handles SMPP communication and unwrapping of OTA responses received via SMS."""

    def __init__(
        self,
        host: str,
        port: int,
        system_id: str,
        password: str,
        src_addr: str,
        dest_addr: str,
        timeout: int,
        ota_dialect: OtaDialectSms,
        ota_keyset: OtaKeyset,
        spi: dict,
    ):
        self.client = None
        client = smpplib.client.Client(host, port, allow_unknown_opt_params=True)
        client.set_message_sent_handler(self.message_sent_handler)
        client.set_message_received_handler(self.message_received_handler)
        client.connect()
        client.bind_transceiver(system_id=system_id, password=password)
        self.client = client

        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.timeout = timeout
        self.ota_dialect = ota_dialect
        self.ota_keyset = ota_keyset
        self.spi = spi
        self.response = None

    def unbind(self):
        if self.client:
            try:
                self.client.unbind()
                self.client.disconnect()
            except Exception as e:
                logger.debug("Error during unbind/disconnect: %s", e)
            self.client = None

    def message_received_handler(self, pdu):
        if pdu.short_message:
            logger.debug("SMS-TPDU received: %s", b2h(pdu.short_message))
            try:
                dec = self.ota_dialect.decode_resp(
                    self.ota_keyset, self.spi, pdu.short_message
                )
            except (ValueError, OtaCheckError):
                # Retry decoding with ciphering and checksum verification disabled
                spi = self.spi.copy()
                spi["por_shall_be_ciphered"] = False
                spi["por_rc_cc_ds"] = "no_rc_cc_ds"
                dec = self.ota_dialect.decode_resp(
                    self.ota_keyset, spi, pdu.short_message
                )
            logger.debug("SMS-TPDU decoded: %s", dec)
            self.response = dec
        return None

    def message_sent_handler(self, pdu):
        logger.debug(
            "SMS-TPDU sent: sequence=%s message_id=%s", pdu.sequence, pdu.message_id
        )

    def transceive(self, payload: bytes) -> tuple[bytes, bytes]:
        """Send a secured OTA SMS payload and return (response data, status word) of the R-APDU."""
        logger.debug("SMS-TPDU sending: %s...", b2h(payload))

        self.client.send_message(
            source_addr_ton=smpplib.consts.SMPP_TON_INTL,
            source_addr=self.src_addr,
            dest_addr_ton=smpplib.consts.SMPP_TON_INTL,
            destination_addr=self.dest_addr,
            short_message=payload,
            data_coding=smpplib.consts.SMPP_ENCODING_BINARY,
            esm_class=smpplib.consts.SMPP_GSMFEAT_UDHI,
            protocol_id=0x7F,
        )

        timestamp_sent = int(time.time())
        self.response = None
        while self.response is None:
            self.client.poll()
            if int(time.time()) - timestamp_sent > self.timeout:
                raise ValueError("Timeout reached waiting for response SMS-TPDU!")

        por, remote_resp = self.response
        if por["response_status"] != "por_ok":
            raise ValueError(
                f"PoR indicates an error: {por['response_status']} (no R-APDU received)"
            )
        if remote_resp is None:
            raise ValueError("PoR does not contain a response (no R-APDU received)")

        resp_bytes = h2b(remote_resp["last_response_data"])
        sw_bytes = h2b(remote_resp["last_status_word"])
        logger.info(
            "Received R-APDU response: %s SW: %s", b2h(resp_bytes), b2h(sw_bytes)
        )

        return resp_bytes, sw_bytes


def build_delete_apdu(aid_hex: str) -> bytes:
    """Build GP DELETE APDU for a given AID."""
    aid_bytes = h2b(aid_hex)
    data = b"\x4f" + bytes([len(aid_bytes)]) + aid_bytes
    return b"\x80\xe4\x00\x80" + bytes([len(data)]) + data + b"\x00"


def build_load_parameters(
    code_size: int, volatile_memory: int | None, nonvolatile_memory: int | None
) -> bytes:
    """Build the Load Parameters field (GPC_SPE_034, table 11-49): EF containing the minimum memory
    requirements C6 (non-volatile code), C7 (volatile data, optional) and C8 (non-volatile data, optional).
    """
    sys_params = b"\xc6\x02" + code_size.to_bytes(2, byteorder="big")
    if volatile_memory is not None:
        sys_params += b"\xc7\x02" + volatile_memory.to_bytes(2, byteorder="big")
    if nonvolatile_memory is not None:
        sys_params += b"\xc8\x02" + nonvolatile_memory.to_bytes(2, byteorder="big")
    return b"\xef" + bytes([len(sys_params)]) + sys_params


def build_install_for_load_apdu(
    loadfile_aid_hex: str, sd_aid_hex: str, load_params: bytes
) -> bytes:
    """Build GP INSTALL [for load] APDU with explicit Security Domain AID."""
    data = b""
    for field in (h2b(loadfile_aid_hex), h2b(sd_aid_hex), b"", load_params, b""):
        # load file AID, security domain AID, load file hash, load parameters, load token
        data += bytes([len(field)]) + field
    return b"\x80\xe6\x02\x00" + bytes([len(data)]) + data + b"\x00"


def build_load_apdus(loadfile_bytes: bytes, max_block_size: int) -> list[bytes]:
    """Wrap loadfile into C4 BER-TLV container and split into LOAD APDUs."""
    c4_data = b"\xc4" + bertlv_encode_len(len(loadfile_bytes)) + loadfile_bytes

    apdus = []
    for block_nr, offset in enumerate(range(0, len(c4_data), max_block_size)):
        chunk = c4_data[offset : offset + max_block_size]
        is_last = offset + max_block_size >= len(c4_data)
        p1 = 0x80 if is_last else 0x00
        p2 = block_nr & 0xFF
        apdus.append(b"\x80\xe8" + bytes([p1, p2, len(chunk)]) + chunk + b"\x00")
    return apdus


def build_stk_parameter(
    access_domain_hex: str,
    priority_level_hex: str,
    max_timers: int,
    max_menu_entry_text: int,
    max_menu_entries: int,
    max_channels: int,
    applet_tar_hex: str,
) -> bytes:
    """Build the contents of the SIM Toolkit parameter (tag CA), see ETSI TS 102 226, section 8.2.1.3.2.1."""
    acc_dom = h2b(access_domain_hex)
    tar_bytes = h2b(applet_tar_hex)

    tk = bytes([len(acc_dom)]) + acc_dom
    tk += h2b(priority_level_hex) + bytes(
        [max_timers, max_menu_entry_text, max_menu_entries]
    )
    tk += b"\x00\x00" * max_menu_entries
    tk += bytes([max_channels])
    tk += b"\x00"
    tk += bytes([len(tar_bytes)]) + tar_bytes
    return tk


def build_install_parameters(
    app_parameters_hex: str | None,
    volatile_quota: int | None,
    nonvolatile_quota: int | None,
    stk_parameter: bytes | None,
) -> bytes:
    """Build the Install Parameters field (GPC_SPE_034, table 11-49): mandatory C9, followed by
    EF (system specific parameters) only if at least one of its members is given."""
    system_specific_params = []
    if volatile_quota is not None:
        system_specific_params.append({"volatile_memory_quota": volatile_quota})
    if nonvolatile_quota is not None:
        system_specific_params.append({"non_volatile_memory_quota": nonvolatile_quota})
    if stk_parameter is not None:
        system_specific_params.append({"stk_parameter": b2h(stk_parameter)})

    install_params_dict = [{"app_specific_params": app_parameters_hex}]
    if system_specific_params:
        install_params_dict.append({"system_specific_params": system_specific_params})

    install_params = InstallParams()
    install_params.from_dict(install_params_dict)
    return install_params.to_bytes()


def build_install_for_install_apdu(
    loadfile_aid_hex: str,
    module_aid_hex: str,
    instance_aid_hex: str,
    privileges_hex: str,
    install_params: bytes,
) -> bytes:
    """Build GP INSTALL [for install and make selectable] APDU."""
    data = b""
    for field in (
        h2b(loadfile_aid_hex),
        h2b(module_aid_hex),
        h2b(instance_aid_hex),
        h2b(privileges_hex),
        install_params,
    ):
        data += bytes([len(field)]) + field
    data += b"\x00"  # Install Token length

    return b"\x80\xe6\x0c\x00" + bytes([len(data)]) + data + b"\x00"


def build_all_apdus(
    opts, loadfile_bytes: bytes, loadfile_aid: str, module_aid: str, instance_aid: str
) -> list[tuple[str, bytes, bool]]:
    """Build the full sequence of (title, C-APDU, must_succeed) needed to install the applet."""
    apdus = []
    if opts.delete_existing:
        apdus.append(("DELETE", build_delete_apdu(loadfile_aid), False))

    if opts.load_parameters is not None:
        load_params = h2b(opts.load_parameters)
    else:
        load_params = build_load_parameters(
            len(loadfile_bytes),
            opts.load_parameters_volatile_memory,
            opts.load_parameters_non_volatile_memory,
        )
    logger.info("Load parameters   : %s", b2h(load_params))

    apdus.append(
        (
            "INSTALL [for load]",
            build_install_for_load_apdu(
                loadfile_aid, sd_aid_hex=opts.sd_aid, load_params=load_params
            ),
            True,
        )
    )

    load_apdus = build_load_apdus(loadfile_bytes, max_block_size=opts.max_block_size)
    for i, load_apdu in enumerate(load_apdus, start=1):
        apdus.append((f"LOAD block {i}/{len(load_apdus)}", load_apdu, True))

    if opts.install_parameters is not None:
        install_params = h2b(opts.install_parameters)
    else:
        stk_parameter = None
        if opts.enable_sim_toolkit:
            stk_parameter = build_stk_parameter(
                access_domain_hex=opts.access_domain,
                priority_level_hex=opts.priority_level,
                max_timers=opts.max_timers,
                max_menu_entry_text=opts.max_menu_entry_text,
                max_menu_entries=opts.max_menu_entries,
                max_channels=opts.max_channels,
                applet_tar_hex=opts.applet_tar,
            )
        install_params = build_install_parameters(
            opts.app_parameters,
            opts.install_parameters_volatile_memory_quota,
            opts.install_parameters_non_volatile_memory_quota,
            stk_parameter,
        )
    logger.info("Install parameters: %s", b2h(install_params))

    apdus.append(
        (
            "INSTALL [for install]",
            build_install_for_install_apdu(
                loadfile_aid_hex=loadfile_aid,
                module_aid_hex=module_aid,
                instance_aid_hex=instance_aid,
                privileges_hex=opts.privileges,
                install_params=install_params,
            ),
            True,
        )
    )
    return apdus


def main():
    opts = option_parser.parse_args()

    if opts.cap_file is None and not (opts.delete_only and opts.loadfile_aid):
        option_parser.error(
            "argument cap_file is required, unless --delete-only is used together with --loadfile-aid"
        )

    if opts.smsc_addr is not None and opts.pdus_file is None:
        option_parser.error("argument --smsc-addr requires --pdus-file")

    if opts.load_parameters is not None and any(
        p is not None
        for p in [
            opts.load_parameters_volatile_memory,
            opts.load_parameters_non_volatile_memory,
        ]
    ):
        option_parser.error(
            "arguments --load-parameters-* are not allowed with --load-parameters"
        )
    if opts.install_parameters is not None and (
        opts.enable_sim_toolkit
        or opts.app_parameters is not None
        or any(
            p is not None
            for p in [
                opts.install_parameters_volatile_memory_quota,
                opts.install_parameters_non_volatile_memory_quota,
            ]
        )
    ):
        option_parser.error(
            "arguments --install-parameters-*, --app-parameters and --enable-sim-toolkit "
            "are not allowed with --install-parameters"
        )

    logging.basicConfig(
        level=logging.DEBUG if opts.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    cap = None
    if opts.cap_file is not None:
        cap_file_path = Path(opts.cap_file)
        if not cap_file_path.exists():
            logger.error("Specified .cap file does not exist: %s", cap_file_path)
            sys.exit(1)
        logger.info("Reading CAP file: %s", cap_file_path)
        cap = CapFile(str(cap_file_path))

    loadfile_aid = opts.loadfile_aid or cap.get_loadfile_aid()
    logger.info("Loadfile AID  : %s", loadfile_aid)

    if opts.delete_only:
        # P2=0x80: the applet instances of the package are deleted as well
        apdus = [("DELETE", build_delete_apdu(loadfile_aid), True)]
    else:
        loadfile_bytes = cap.get_loadfile()
        module_aid = opts.module_aid or cap.get_applet_aid() or loadfile_aid
        instance_aid = opts.instance_aid or module_aid

        logger.info("Loadfile Size : %d bytes", len(loadfile_bytes))
        logger.info("ISD AID       : %s", opts.sd_aid)
        logger.info("Module AID    : %s", module_aid)
        logger.info("Instance AID  : %s", instance_aid)

        apdus = build_all_apdus(
            opts, loadfile_bytes, loadfile_aid, module_aid, instance_aid
        )

    ota_keyset = OtaKeyset(
        algo_crypt=opts.algo_crypt,
        kic_idx=opts.kic_idx,
        kic=h2b(opts.kic),
        algo_auth=opts.algo_auth,
        kid_idx=opts.kid_idx,
        kid=h2b(opts.kid),
        cntr=opts.cntr,
    )

    spi = {
        "counter": opts.cntr_req,
        "ciphering": not opts.no_ciphering,
        "rc_cc_ds": opts.rc_cc_ds,
        "por_in_submit": opts.por_in_submit,
        "por_shall_be_ciphered": not opts.por_no_ciphering,
        "por_rc_cc_ds": opts.por_rc_cc_ds,
        "por": opts.por_req,
    }

    ota_dialect = OtaDialectSms()
    tar_bytes = h2b(opts.tar)

    smpp_handler = None
    if opts.dry_run:
        logger.info("======================== DRY RUN MODE ========================")
    else:
        logger.info(
            "Connecting to SMPP server at %s:%d (System ID: %s)...",
            opts.host,
            opts.port,
            opts.system_id,
        )
        smpp_handler = SmppHandler(
            opts.host,
            opts.port,
            opts.system_id,
            opts.password,
            opts.src_addr,
            opts.dest_addr,
            opts.timeout,
            ota_dialect,
            ota_keyset,
            spi,
        )

    smsc_prefix = encode_smsc_address(opts.smsc_addr) if opts.smsc_addr else b""
    sms_deliver_pdus = []
    try:
        for title, apdu, must_succeed in apdus:
            logger.info("[%s] C-APDU: %s", title, b2h(apdu))
            payload = b"\x02\x70\x00" + ota_dialect.encode_cmd(
                ota_keyset, tar_bytes, spi, apdu=apdu
            )
            sms_deliver_pdus.append(
                (title, smsc_prefix + build_sms_deliver_tpdu(payload, opts.src_addr))
            )

            if smpp_handler is None:
                logger.info("[%s] SMS Payload: %s", title, b2h(payload))
                continue

            try:
                _resp, sw = smpp_handler.transceive(payload)
            except Exception as e:
                if must_succeed:
                    raise
                logger.warning("[%s] failed or item was not present: %s", title, e)
                continue

            if not is_success_sw(sw):
                if must_succeed:
                    raise RuntimeError(f"{title} failed with SW: {b2h(sw)}")
                logger.warning("[%s] failed with SW: %s", title, b2h(sw))
    finally:
        if smpp_handler:
            smpp_handler.unbind()

    logger.info("==============================================================")
    if opts.dry_run:
        logger.info("Dry run complete: %d APDUs / SMS packets generated.", len(apdus))
    else:
        logger.info(
            "SUCCESS: Applet OTA %s completed successfully!",
            "Deletion" if opts.delete_only else "Installation",
        )

    if opts.pdus_file is not None:
        with open(opts.pdus_file, "w") as f:
            json.dump(
                [{"title": title, "pdu": b2h(pdu)} for title, pdu in sms_deliver_pdus],
                f,
                indent=2,
            )
        logger.info(
            "Wrote %d SMS-DELIVER PDUs to %s", len(sms_deliver_pdus), opts.pdus_file
        )


if __name__ == "__main__":
    main()
