#!/usr/bin/env python3
"""worldbox box init — PID 1 of one simulated VPS.

Plays the part of "Ubuntu 24.04 + cloud-init first boot" for the REAL
user-data the REAL provisioning code sent to the (fake) cloud API. It does
not know what Daal is: it mounts a private root-ish filesystem view,
executes the cloud-config modules the template uses (bootcmd, write_files,
runcmd) and then reaps children forever, like an init.

What is real here: every byte of user-data, the runcmd script, openssl,
python3, ip, and every binary the script downloads and verifies.
What is stubbed (see box/shims/): systemctl, ufw, sleep, chown, sshd.

Invoked as PID 1 of a fresh pid+mount namespace, inside the box's netns:
    init.py --box-dir D --user-data F --shims S [--ca PEM] [--hosts LINE]...
"""
import argparse, os, signal, subprocess, sys, time

import yaml


def sh(*argv):
    subprocess.run(argv, check=True)


def mounts(box, hosts_lines, write_dirs, binds, resolver):
    """Assemble the box's private root filesystem and chroot into it.

    <box>/rootfs is a small "base image" built from this laptop:

      /usr/<x>            symlink → /.host/usr/<x>   (read-only bind of the laptop's /usr)
      /bin /lib /sbin …   the laptop's own symlinks into /usr, copied
      /etc                overlay: the laptop's /etc underneath, <box>/etc-upper on top
      /usr/local /tmp /var /root /run(tmpfs)   plain directories — the box's own disk

    The last line is the point. Everything the box writes outside /etc
    sits on ONE mount, like a VPS's single disk, so rename(2) from /tmp
    to /usr/local/bin works (the verifier shim relies on it; FINDINGS.md
    F-001). A plain overlay of / would be simpler, but an unprivileged
    user namespace may not use a lower layer that has mounts under it.
    """
    root = os.path.join(box, "rootfs")
    up, work = os.path.join(box, "etc-upper"), os.path.join(box, "etc-work")
    for d in (up, work, os.path.join(box, "state")):
        os.makedirs(d, exist_ok=True)
    for d in ("etc", ".host/usr", "usr/local/bin", "usr/local/lib", "usr/local/sbin", "tmp", "root",
              "var/log", "var/lib", "run", "dev", "proc", "sys"):
        os.makedirs(os.path.join(root, d), exist_ok=True)
    os.chmod(os.path.join(root, "tmp"), 0o1777)
    for name in os.listdir("/usr"):
        if name != "local":
            os.symlink("/.host/usr/" + name, os.path.join(root, "usr", name))
    for name in os.listdir("/"):
        src = "/" + name
        if os.path.islink(src):  # merged-/usr symlinks: /bin → usr/bin, /lib64 → usr/lib64, …
            os.symlink(os.readlink(src), os.path.join(root, name))

    # /etc: directories that exist on this laptop are owned by the REAL
    # root, which a user namespace cannot write into even through an
    # overlay. A directory created in the upper layer first is ours and
    # merges over the laptop's, so pre-create each one the box writes in.
    etc_dirs = {d[len("etc/"):] for d in write_dirs if d.startswith("etc/")}
    for d in etc_dirs | {"ssh", "systemd/system/multi-user.target.wants"}:
        os.makedirs(os.path.join(up, d), exist_ok=True)
    # Files the Ubuntu image would have and this laptop may not.
    with open("/etc/hosts") as f:
        hosts = f.read()
    with open(os.path.join(up, "hosts"), "w") as f:
        f.write(hosts.rstrip("\n") + "\n" + "\n".join(hosts_lines) + "\n")
    if resolver:
        # A cloud image boots with the provider's resolvers configured.
        with open(os.path.join(up, "resolv.conf"), "w") as f:
            f.write(f"nameserver {resolver}\n")
    with open(os.path.join(up, "ssh/sshd_config"), "w") as f:
        f.write("#PermitRootLogin prohibit-password\n#PasswordAuthentication yes\n")

    sh("mount", "-t", "overlay", "overlay", "-o", f"lowerdir=/etc,upperdir={up},workdir={work}", root + "/etc")
    sh("mount", "--bind", "-o", "ro", "/usr", root + "/.host/usr")
    sh("mount", "--rbind", "/dev", root + "/dev")
    sh("mount", "--rbind", "/sys", root + "/sys")
    sh("mount", "-t", "proc", "proc", root + "/proc")
    sh("mount", "-t", "tmpfs", "tmpfs", root + "/run")
    # The rig's own files (shims, lab CA, this box's state dir) at the
    # same absolute paths as outside.
    for b in binds:
        os.makedirs(root + b, exist_ok=True)
        sh("mount", "--bind", b, root + b)
    os.chroot(root)
    os.chdir("/")
    os.makedirs("/run/wb-systemd", exist_ok=True)


def parents(path):
    out, d = [], os.path.dirname(path)
    while d not in ("", "/"):
        out.append(d.lstrip("/"))
        d = os.path.dirname(d)
    return out


def write_files(cfg):
    for wf in cfg.get("write_files") or []:
        path = wf["path"]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        content = wf.get("content", "")
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, int(str(wf.get("permissions", "0644")), 8))


def run_list(items, log, label):
    """cloud-init runs each list item as its own shell command."""
    for i, item in enumerate(items or []):
        argv = item if isinstance(item, list) else ["/bin/sh", "-c", item]
        log.write(f"--- {label}[{i}] ---\n".encode())
        log.flush()
        rc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL).returncode
        if rc != 0:
            log.write(f"--- {label}[{i}] exited {rc} ---\n".encode())
            log.flush()
            return rc
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--box-dir", required=True)
    ap.add_argument("--user-data", required=True)
    ap.add_argument("--shims", required=True)
    ap.add_argument("--ca", default="")
    ap.add_argument("--hosts", action="append", default=[])
    ap.add_argument("--timescale", default="20")
    ap.add_argument("--resolver", default="")
    a = ap.parse_args()

    box = os.path.abspath(a.box_dir)
    state = os.path.join(box, "state")
    with open(a.user_data) as f:
        raw = f.read()
    if not raw.startswith("#cloud-config"):
        sys.exit("user-data is not a #cloud-config document")
    cfg = yaml.safe_load(raw)

    write_dirs = [d for wf in cfg.get("write_files") or [] for d in parents(wf["path"])]
    binds = ([os.path.dirname(os.path.abspath(a.ca))] if a.ca else []) + [os.path.abspath(a.shims), state]
    mounts(box, a.hosts, write_dirs, binds, a.resolver)
    os.environ["PATH"] = a.shims + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    os.environ["HOME"] = "/root"
    os.environ["WB_BOX_STATE"] = state
    os.environ["WB_TIMESCALE"] = a.timescale
    if a.ca:
        # The box fetches its artefacts over TLS from the lab's stand-in
        # for the release mirror; this is the lab CA, and it is the ONLY
        # trust change — the sha256 + Ed25519 pins are checked by the
        # unmodified verifier shim against the real release key.
        os.environ["SSL_CERT_FILE"] = a.ca
    os.chdir("/")

    # PID 1: adopt and reap everything the "units" leave behind.
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))

    pid = os.fork()
    if pid == 0:
        os.setsid()
        log = open("/var/log/cloud-init-output.log", "ab", buffering=0)
        rc = run_list(cfg.get("bootcmd"), log, "bootcmd")
        if rc == 0:
            try:
                write_files(cfg)
            except Exception as e:  # noqa: BLE001
                log.write(f"write_files failed: {e}\n".encode())
                rc = 1
        if rc == 0:
            open(os.path.join(state, "write-files-done"), "w").close()
            rc = run_list(cfg.get("runcmd"), log, "runcmd")
        with open(os.path.join(state, "cloud-init.rc"), "w") as f:
            f.write(str(rc))
        os._exit(rc)

    while True:
        try:
            os.wait()
        except ChildProcessError:
            time.sleep(0.2)
        except InterruptedError:
            pass


if __name__ == "__main__":
    main()
