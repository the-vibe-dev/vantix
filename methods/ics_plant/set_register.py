#!/usr/bin/env python3
import sys
from pymodbus.client.sync import ModbusTcpClient as ModbusClient

if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} <target_ip> <register> <value>")
    sys.exit(1)

ip = sys.argv[1]
reg = int(sys.argv[2])
val = int(sys.argv[3])

client = ModbusClient(ip, port=502)
if not client.connect():
    print("[-] Modbus connect failed")
    sys.exit(2)

client.write_register(reg, val)
print(f"[+] Wrote register {reg} = {val}")
