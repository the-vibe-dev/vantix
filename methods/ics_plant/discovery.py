#!/usr/bin/env python3
import sys
import time
from pymodbus.client.sync import ModbusTcpClient as ModbusClient

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <target_ip> [count]")
    sys.exit(1)

ip = sys.argv[1]
count = int(sys.argv[2]) if len(sys.argv) > 2 else 0

client = ModbusClient(ip, port=502)
if not client.connect():
    print("[-] Modbus connect failed")
    sys.exit(2)

print("[*] Reading holding registers 1..16")
print("[*] Map: 1=FEED_PUMP 2=TANK_LEVEL 3=OUTLET_VALVE 4=SEP_VALVE 6=OIL_SPILL 7=OIL_PROCESSED 8=WASTE_VALVE")

n = 0
while True:
    rr = client.read_holding_registers(1, 16)
    if not rr or not hasattr(rr, 'registers'):
        print("[-] Read failed")
    else:
        print(rr.registers)
    n += 1
    if count and n >= count:
        break
    time.sleep(1)
