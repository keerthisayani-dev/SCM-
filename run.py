import socket
import subprocess
import sys

from backend.config import APP_HOST, APP_PORT, APP_RELOAD


def _ensure_port_available(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        if sock.connect_ex((host, port)) == 0:
            raise RuntimeError(
                f"Port {port} is already in use on {host}. Stop the existing server or change PORT in .env."
            )


def main() -> None:
    _ensure_port_available(APP_HOST, APP_PORT)

    command = [
        sys.executable,
        "-m",
        "uvicorn",
        "main:app",
        "--host",
        APP_HOST,
        "--port",
        str(APP_PORT),
    ]
    if APP_RELOAD:
        command.append("--reload")

    subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
