# OTA Applet Install: SMPP script + Frida injector

Tools to install (or delete) a Java Card applet on a SIM over the air (OTA), via secured SMS. They can
be used together or separately:

- **[`smpp-ota-install-applet.py`](smpp-ota-install-applet.py)**: builds the GlobalPlatform
  LOAD/INSTALL APDUs from a `.cap` file, wraps each one in a Secured OTA SMS and sends them over SMPP.
  With `--dry-run` nothing is sent and the APDUs and SMS are only printed. With `--pdus-file` the
  resulting SMS-DELIVER PDUs are also saved to a JSON file.
- **Frida injector**: injects the saved PDUs directly into the
  phone's telephony stack, so the applet can be installed on a real device without an SMSC. The host
  ([`frida-ota-inject.py`](frida-ota-inject.py)) runs on the PC, reads the PDU file and decodes the
  Proof of Receipt (PoR) of each PDU. The agent ([`frida-ota-agent.js`](frida-ota-agent.js)) is loaded
  by the host into `com.android.phone` and does the PDU injection on the device.

## Requirements

- [`pySim`](https://gitea.osmocom.org/sim-card/pysim) checked out, with its dependencies installed (`pip install -r requirements.txt`). Confirmed working on commit `3c437d41e0`.
- A programmable SIM card such as the sysmoISIM-SJA5, or a test eSIM such as the sysmoEUICC1-C2T.
- The OTA keyset (KIC/KID) of the Security Domain of the SIM/eSIM profile, and the TAR of the RAM application.
- For the Frida part: a rooted Android phone with `frida-server`
  running, and `frida-tools` (`pip install frida-tools`) and Node.js/`npm` installed on the PC.

## Part 1: `smpp-ota-install-applet.py`

Run it with `PYTHONPATH` pointing to the pySim checkout:

```sh
export PYTHONPATH=/path/to/pysim
PY=venv/bin/python3
SCRIPT=smpp-ota-install-applet.py
KEYS="--kic <KIC hex> --kid <KID hex>"   # add --kic-idx/--kid-idx if not 1
```

### Modes

- **Dry run**. Build the APDUs/SMS but send nothing:
  ```sh
  $PY $SCRIPT $KEYS --dry-run applet.cap
  ```
- **PDU file**. Also save the SMS-DELIVER PDUs to a JSON file:
  ```sh
  $PY $SCRIPT $KEYS --dry-run --pdus-file pdus.json --smsc-addr +<any number> applet.cap
  ```
- **Live, via [`pySim-smpp2sim.py`](https://gitea.osmocom.org/sim-card/pysim/src/branch/master/pySim-smpp2sim.py)**. A simulated SMSC that delivers the SMS to a
  card in a local PC/SC reader (defaults match: localhost:2775, system-id test, password test):
  ```sh
  # terminal 1
  $PY pySim-smpp2sim.py -p0
  # terminal 2
  $PY $SCRIPT $KEYS --delete-existing applet.cap
  ```
- **Live, against a real SMPP server**. Add `--host`/`--port`/`--system-id`/`--password`.
- **Delete only** (no install):
  ```sh
  $PY $SCRIPT $KEYS --delete-only --loadfile-aid <package AID>
  ```
  Or:
  ```sh
  $PY $SCRIPT $KEYS --delete-only applet.cap
  ```

### Useful options

| Option | Purpose |
|---|---|
| `--delete-existing` | Delete the package/applet first (failure is only a warning) |
| `--delete-only` | Only delete, don't install |
| `--enable-sim-toolkit --max-menu-entries N` | Register a toolkit applet (STK menu). `N` must be at least the number of menu entries the applet registers |
| `--max-timers N` | Toolkit applet: maximum number of timers it may allocate (default 0) |
| `--max-channels N` | Toolkit applet: maximum number of Bearer Independent Protocol (BIP) channels it may open, e.g. with OPEN CHANNEL (default 0) |
| `--por-no-ciphering` | Tell the card not to cipher the Proof of Receipt (PoR) it sends in response, so that its content (response data and status word) is readable in plain hex |
| `--applet-tar <TAR>` | TAR under which the applet itself can be addressed via OTA. Must be unique on the card |
| `--app-parameters <hex>` | Bytes passed to the applet's `install()` method |
| `--install-parameters` / `--load-parameters` | Override the built parameters with raw hex |
| `--pdus-file <path>` | Write the generated SMS-DELIVER PDUs to a JSON file (a list of `{"title", "pdu"}`) |
| `--smsc-addr <number>` | Prepend an SMSC address to each PDU written to `--pdus-file` (useful for Frida injection); use a leading `+` for an international number |

**Example invocation** (generate a PDU file for the Frida injector):

```sh
$PY $SCRIPT $KEYS --delete-existing --por-no-ciphering --enable-sim-toolkit --max-menu-entries 1 --max-channels 1 --max-timers 2 --applet-tar b00000 applet.cap --dry-run --pdus-file pdus.json --smsc-addr 1234567890
```

Run `$PY $SCRIPT --help` for the full list of arguments.

## Part 2: Frida injection (`frida-ota-inject.py` + `frida-ota-agent.js`)

Instead of a real/simulated SMSC, the Frida injector feeds the generated PDUs directly into the
Android telephony stack via `SmsDispatchersController.injectSmsPdu()`. Useful for testing on a real
phone, without setting up an SMPP connection and without a SIM card reader.

- [`frida-ota-inject.py`](frida-ota-inject.py): the host, runs on the PC. Reads the PDU JSON file,
  attaches to `com.android.phone`, hands the PDUs to the agent, and decodes each PoR the card returns
  (using the same pySim OTA code as the install script).
- [`frida-ota-agent.js`](frida-ota-agent.js): the agent, injected into the phone. Injects the PDUs
  one at a time (each only after the previous one's PoR) and reports every PoR back to the host.

The PDUs stay in a JSON file on the PC and
are sent over Frida's message channel.

### 1. Generate the PDU file

```sh
$PY $SCRIPT $KEYS --dry-run --pdus-file pdus.json --smsc-addr +<your SMSC or any number> applet.cap
```

The file is a JSON list of `{"title", "pdu"}` objects. `--smsc-addr` prepends the SMSC address that
`injectSmsPdu()` expects for the `"3gpp"` format.

### 2. Inject on the phone

The device needs `frida-server` running and reachable over USB; the PC needs the `frida` Python
package (installed with `frida-tools`). The agent imports `frida-java-bridge` (the Java bridge is no
longer part of the Frida runtime since Frida 17), and the host bundles it with the Frida compiler when
it starts. Install it once:

```sh
npm install frida-java-bridge
```

Then, with `PYTHONPATH` still pointing to pySim (to decode the PoRs):

```sh
$PY frida-ota-inject.py --pdus-file pdus.json $KEYS
```

- Attaches to `com.android.phone` by default. The target process can also be given explicitly (e.g., `-p com.android.phone`, `-p`/`--process` accepts a process name or a PID).
- If Frida complains with something like `unable to find process with name 'com.android.phone'`, find the
  PID on the device and pass it to `-p` instead:
  ```sh
  adb shell pidof com.android.phone
  $PY frida-ota-inject.py -p <pid> --pdus-file pdus.json $KEYS
  ```
- `--slot N` selects the SIM slot (0 = slot 1).
- `--device-id` picks a specific Frida device.
- Pass the same `$KEYS` (and any non-default `--algo-*` / `--por-*`) used to generate the PDUs, so the
  host can decode the PoRs and verify their checksum. With `--por-no-ciphering` the keys are optional. With neither, PoRs are printed as raw hex.
- Injection is PoR-driven: each PDU is sent only after the previous one's PoR is seen (timeout
  fallback), and every PoR is decoded and printed with its status and R-APDU SW.

### Known limitation

Installing/deleting a SIM Toolkit applet can make the card send proactive commands. If you're also
running `pySim-smpp2sim.py` in parallel, the latter may crash if it is unable to process a command.
This only affects the simulator, not a real phone or the Frida injector.

> The Frida injector cannot be used to reproduce the NAS OOB read: injected PDUs bypass the baseband and are delivered directly to the Android telephony stack, so the affected NAS parsing code path is never reached.
