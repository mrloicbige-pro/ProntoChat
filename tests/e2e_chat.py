#!/usr/bin/env python3
import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_text(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def wait_for(path, needle, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if needle in read_text(path):
            return True
        time.sleep(0.1)
    return False


def append_config(config_dir, text):
    config_path = config_dir / "config.toml"
    with config_path.open("a", encoding="utf-8") as handle:
        handle.write(text)


class Harness:
    def __init__(self, build_dir, keep_logs):
        self.build_dir = build_dir
        self.keep_logs = keep_logs
        self.tmp = Path(tempfile.mkdtemp(prefix="prontochat-e2e-"))
        self.processes = []
        self.files = []

    def env_for(self, username):
        return {
            **os.environ,
            "CHAT_CONFIG_DIR": str(self.tmp / username),
            "CHAT_SOCKET_PATH": str(self.tmp / f"{username}.sock"),
        }

    def binary(self, name):
        return str(self.build_dir / name)

    def open_log(self, name):
        path = self.tmp / f"{name}.log"
        handle = path.open("w", encoding="utf-8")
        self.files.append(handle)
        return path, handle

    def run_checked(self, name, command, env):
        path, handle = self.open_log(name)
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        handle.flush()
        if completed.returncode != 0:
            raise RuntimeError(f"{name} failed with {completed.returncode}; see {path}")

    def start(self, name, command, env, stdin=None):
        path, handle = self.open_log(name)
        proc = subprocess.Popen(
            command,
            cwd=ROOT,
            env=env,
            stdin=stdin,
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self.processes.append((name, proc, path))
        return proc, path

    def start_chat(self, name, username, peer):
        path, handle = self.open_log(name)
        command = [
            "stdbuf",
            "-oL",
            "-eL",
            self.binary("chat"),
            peer,
        ]
        proc = subprocess.Popen(
            command,
            cwd=ROOT,
            env=self.env_for(username),
            stdin=subprocess.PIPE,
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self.processes.append((name, proc, path))
        return proc, path

    def cleanup(self, success):
        for _, proc, _ in reversed(self.processes):
            if proc.poll() is None:
                proc.terminate()

        deadline = time.monotonic() + 3.0
        for _, proc, _ in reversed(self.processes):
            remaining = max(0.0, deadline - time.monotonic())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                proc.kill()

        for handle in self.files:
            try:
                handle.close()
            except OSError:
                pass

        if success and not self.keep_logs:
            shutil.rmtree(self.tmp, ignore_errors=True)
        else:
            print(f"logs: {self.tmp}", file=sys.stderr)


def require_marker(path, marker, timeout, label):
    if not wait_for(path, marker, timeout):
        raise RuntimeError(f"timeout waiting for {label}: {marker!r} in {path}")


def write_line(proc, line):
    if proc.stdin is None:
        raise RuntimeError("process has no stdin")
    proc.stdin.write(line + "\n")
    proc.stdin.flush()


def close_stdin(proc):
    if proc.stdin is not None and not proc.stdin.closed:
        proc.stdin.close()


def wait_process(proc, timeout, label):
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"timeout waiting for {label} to exit") from exc


class IpcClient:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(160.0)
        self.sock.connect(str(path))
        self.buffer = b""

    def send_line(self, line):
        self.sock.sendall(line.encode("utf-8") + b"\n")

    def read_line(self, timeout):
        self.sock.settimeout(timeout)
        while b"\n" not in self.buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("IPC socket closed")
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        return line.decode("utf-8", errors="replace")

    def close(self):
        self.sock.close()


def main():
    parser = argparse.ArgumentParser(description="Run local ProntoChat end-to-end chat test.")
    parser.add_argument("--build-dir", default="build", type=Path)
    parser.add_argument("--keep-logs", action="store_true")
    parser.add_argument("--turn-server")
    parser.add_argument("--turn-port", default=3478, type=int)
    parser.add_argument("--turn-username")
    parser.add_argument("--turn-password")
    parser.add_argument("--force-relay", action="store_true")
    parser.add_argument("--expect-identity-mismatch", action="store_true")
    parser.add_argument("--disconnect-control", action="store_true")
    parser.add_argument("--expect-offline", action="store_true")
    args = parser.parse_args()

    turn_values = (args.turn_server, args.turn_username, args.turn_password)
    if any(turn_values) and not all(turn_values):
        parser.error("--turn-server, --turn-username, and --turn-password must be used together")
    if args.force_relay and not all(turn_values):
        parser.error("--force-relay requires a complete TURN configuration")
    if args.expect_identity_mismatch and any(turn_values):
        parser.error("--expect-identity-mismatch cannot be combined with TURN options")
    if args.expect_identity_mismatch and args.disconnect_control:
        parser.error("--expect-identity-mismatch cannot be combined with --disconnect-control")
    if args.expect_offline and (args.expect_identity_mismatch or args.disconnect_control or any(turn_values)):
        parser.error("--expect-offline cannot be combined with other scenario options")

    harness = Harness((ROOT / args.build_dir).resolve(), args.keep_logs)
    success = False
    try:
        (harness.tmp / "alex").mkdir()
        (harness.tmp / "nathan").mkdir()

        harness.run_checked(
            "alex-init",
            [harness.binary("chat"), "init", "alex"],
            harness.env_for("alex"),
        )
        harness.run_checked(
            "nathan-init",
            [harness.binary("chat"), "init", "nathan"],
            harness.env_for("nathan"),
        )
        for username in ("alex", "nathan"):
            harness.run_checked(
                f"{username}-config-server",
                [harness.binary("chat"), "config", "server", "ws://127.0.0.1:8787"],
                harness.env_for(username),
            )
        if args.expect_identity_mismatch:
            contacts_path = harness.tmp / "alex" / "contacts.db"
            contacts_path.write_text(f'nathan {bytes(32).hex()}\n', encoding="ascii")
            contacts_path.chmod(0o600)

        for username in ("alex", "nathan"):
            config_path = harness.tmp / username / "config.toml"
            with config_path.open("a", encoding="utf-8") as config:
                config.write('ice_local_address = "127.0.0.1"\n')
                if args.turn_server:
                    config.write(f'turn_server = "{args.turn_server}"\n')
                    config.write(f'turn_port = "{args.turn_port}"\n')
                    config.write(f'turn_username = "{args.turn_username}"\n')
                    config.write(f'turn_password = "{args.turn_password}"\n')
                if args.force_relay:
                    config.write('ice_force_relay = "true"\n')

        server_proc, server_log = harness.start(
            "server",
            ["stdbuf", "-oL", "-eL", harness.binary("chat-server")],
            os.environ.copy(),
        )
        require_marker(server_log, "chat-server listening", 15, "server startup")

        _, alexd_log = harness.start(
            "alexd",
            ["stdbuf", "-oL", "-eL", harness.binary("chatd")],
            harness.env_for("alex"),
        )
        nathand_log = None
        if not args.expect_offline:
            _, nathand_log = harness.start(
                "nathand",
                ["stdbuf", "-oL", "-eL", harness.binary("chatd")],
                harness.env_for("nathan"),
            )
        require_marker(alexd_log, "alex is online", 10, "alex presence")
        if nathand_log is not None:
            require_marker(nathand_log, "nathan is online", 10, "nathan presence")
        time.sleep(2.5)

        alex_ipc = IpcClient(harness.tmp / "alex.sock")
        nathan_ipc = None
        try:
            alex_ipc.send_line("OPEN_CHAT nathan")
            response = alex_ipc.read_line(160)
            if args.expect_offline:
                if response != "USER_OFFLINE nathan":
                    raise RuntimeError(f"expected offline response, got: {response}")
                alex_ipc.close()
                cli = subprocess.run(
                    [harness.binary("chat"), "nathan"],
                    cwd=ROOT,
                    env=harness.env_for("alex"),
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if cli.returncode != 2 or "nathan is offline." not in cli.stdout:
                    raise RuntimeError(
                        f"unexpected offline CLI result: code={cli.returncode}, "
                        f"stdout={cli.stdout!r}, stderr={cli.stderr!r}"
                    )
                print("e2e offline peer passed")
                success = True
                return 0

            if args.expect_identity_mismatch:
                if response != "IDENTITY_MISMATCH nathan":
                    raise RuntimeError(f"expected identity mismatch, got: {response}")
                require_marker(
                    nathand_log,
                    "chat session cancelled by alex",
                    5,
                    "remote identity-mismatch cancellation",
                )
                print("e2e identity mismatch passed")
                success = True
                return 0

            expected_mode = "relay" if args.force_relay else "direct"
            if response != f"ENCRYPTED_SESSION nathan {expected_mode}":
                raise RuntimeError(f"unexpected alex OPEN_CHAT response: {response}")

            nathan_ipc = IpcClient(harness.tmp / "nathan.sock")
            nathan_ipc.send_line("OPEN_CHAT alex")
            response = nathan_ipc.read_line(10)
            if response != f"ENCRYPTED_SESSION alex {expected_mode}":
                raise RuntimeError(f"unexpected nathan OPEN_CHAT response: {response}")

            if args.disconnect_control:
                server_proc.terminate()
                if wait_process(server_proc, 5, "control server") != 0:
                    raise RuntimeError("control server did not stop cleanly")
                require_marker(alexd_log, "control server connection closed", 5, "alex disconnect")
                require_marker(nathand_log, "control server connection closed", 5, "nathan disconnect")

            alex_ipc.send_line("SEND_MESSAGE hello nathan")
            response = nathan_ipc.read_line(10)
            if response != "MESSAGE alex hello nathan":
                raise RuntimeError(f"unexpected nathan message: {response}")

            nathan_ipc.send_line("SEND_MESSAGE salut alex")
            response = alex_ipc.read_line(10)
            if response != "MESSAGE nathan salut alex":
                raise RuntimeError(f"unexpected alex message: {response}")

            alex_ipc.send_line("CLOSE_CHAT")
            response = nathan_ipc.read_line(10)
            if response != "CHAT_CLOSED alex":
                raise RuntimeError(f"unexpected close notification: {response}")
        finally:
            alex_ipc.close()
            if nathan_ipc is not None:
                nathan_ipc.close()

        print("e2e chat passed")
        success = True
        return 0
    except Exception as exc:
        print(f"e2e chat failed: {exc}", file=sys.stderr)
        return 1
    finally:
        harness.cleanup(success)


if __name__ == "__main__":
    raise SystemExit(main())
