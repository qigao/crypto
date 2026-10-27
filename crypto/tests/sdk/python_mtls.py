#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native static Salts::Crypto C11 <-> Python ssl mTLS acceptance.

All external TLS client/server sockets and handshake policies use Python's
stdlib ssl.SSLContext; no openssl executable, OpenSSL C test program or
production OpenSSL provider is added. CPython ssl is normally implemented
using its own platform OpenSSL runtime; this is NOT an independent algorithm
implementation or exporter-byte oracle.

cryptography is used ONLY to construct ephemeral test-only RSA/X509
certificates in a private temporary directory. Nothing is uploaded or logged.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ADDRESS = "127.0.0.1"
REQUEST = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
RESPONSE = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
CASE_NAMES = ("missing", "wrongca", "eku", "expired", "chain")
PROTOCOLS = {"12": ssl.TLSVersion.TLSv1_2, "13": ssl.TLSVersion.TLSv1_3}
MIN_TLS_RESPONSE = b"HTTP/1.0 200"
TIMEOUT = 22.0


class GateFailure(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateFailure(message)


def rsa_identity() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def identity_name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def cert(
    subject: str,
    public_key: rsa.RSAPublicKey,
    issuer: x509.Name,
    issuer_key: rsa.RSAPrivateKey,
    *,
    ca: bool = False,
    eku: x509.ObjectIdentifier | None = None,
    expired: bool = False,
    server_san: bool = False,
) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    if expired:
        not_before = datetime(2020, 1, 1, tzinfo=timezone.utc)
        not_after = datetime(2020, 1, 2, tzinfo=timezone.utc)
    else:
        not_before, not_after = now - timedelta(hours=1), now + timedelta(days=2)
    obj = (
        x509.CertificateBuilder()
        .subject_name(identity_name(subject))
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=1 if ca else None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=not ca,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    )
    if eku is not None:
        obj = obj.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    if server_san:
        obj = obj.add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost")
        ]), critical=False)
    return obj.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def make_fixtures(folder: Path) -> dict[str, Path]:
    root_key, wrong_key, intermediate_key = (
        rsa_identity(), rsa_identity(), rsa_identity()
    )
    root_name = identity_name("Test mTLS root")
    wrong_name = identity_name("Untrusted mTLS root")
    intermediate_name = identity_name("Intermediate mTLS root")
    root = cert("Test mTLS root", root_key.public_key(), root_name, root_key, ca=True)
    wrong = cert("Untrusted mTLS root", wrong_key.public_key(), wrong_name, wrong_key, ca=True)
    intermediate = cert(
        "Intermediate mTLS root", intermediate_key.public_key(),
        root_name, root_key, ca=True,
    )
    result: dict[str, Path] = {}
    for label, c in (("ca", root), ("wrongroot", wrong), ("intermediate", intermediate)):
        p = folder / (label + ".pem")
        p.write_bytes(c.public_bytes(serialization.Encoding.PEM))
        result[label] = p
    subjects = {
        "server": (root_name, root_key, ExtendedKeyUsageOID.SERVER_AUTH, False, True),
        "client": (root_name, root_key, ExtendedKeyUsageOID.CLIENT_AUTH, False, False),
        "wrongca": (wrong_name, wrong_key, ExtendedKeyUsageOID.CLIENT_AUTH, False, False),
        "eku": (root_name, root_key, ExtendedKeyUsageOID.SERVER_AUTH, False, False),
        "expired": (root_name, root_key, ExtendedKeyUsageOID.CLIENT_AUTH, True, False),
        # The intermediate is deliberately OMITTED from the on-wire PEM leaf.
        "chain": (intermediate_name, intermediate_key, ExtendedKeyUsageOID.CLIENT_AUTH, False, False),
    }
    for label, (issuer, signing_key, usage, expired, san) in subjects.items():
        key = rsa_identity()
        leaf = cert(
            "localhost" if label == "server" else "mtls-" + label,
            key.public_key(), issuer, signing_key,
            eku=usage, expired=expired, server_san=san,
        )
        pem = folder / (label + ".pem")
        private = folder / (label + "-key.pem")
        pem.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        private.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        private.chmod(0o600)
        result[label] = pem
        result[label + "-key"] = private
        if label == "server":
            der = folder / "server.der"
            der.write_bytes(leaf.public_bytes(serialization.Encoding.DER))
            result["server-der"] = der
            result["server-sha256"] = Path(
                hashlib.sha256(der.read_bytes()).hexdigest()
            )
    return result


def python_tls_context(role: str, proto: str, f: dict[str, Path],
                       case: str, *, hostname: str = "localhost",
                       trusted_ca: str = "ca") -> ssl.SSLContext:
    require(proto in PROTOCOLS, "unsupported test TLS version")
    ctx = ssl.SSLContext(
        ssl.PROTOCOL_TLS_CLIENT if role == "client" else ssl.PROTOCOL_TLS_SERVER
    )
    ctx.minimum_version = ctx.maximum_version = PROTOCOLS[proto]
    ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    if role == "client":
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=str(f[trusted_ca]))
        if case != "missing":
            ctx.load_cert_chain(str(f[case]), str(f[case + "-key"]))
    else:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=str(f["ca"]))
        ctx.load_cert_chain(str(f["server"]), str(f["server-key"]))
    return ctx


def python_client_to_native(ctx: ssl.SSLContext, port: int, proto: str,
                            hostname: str) -> tuple[bool, str]:
    end = time.monotonic() + 9.0
    while True:
        try:
            raw = socket.create_connection((ADDRESS, port), timeout=5.0)
            break
        except ConnectionRefusedError:
            if time.monotonic() > end:
                raise GateFailure("native server did not bind within deadline")
            time.sleep(0.03)
    with raw:
        try:
            with ctx.wrap_socket(raw, server_hostname=hostname) as peer:
                require(peer.version() == "TLSv1." + proto[-1],
                        "Python TLS client negotiated wrong protocol")
                peer.settimeout(5.0)
                peer.sendall(REQUEST)
                data = peer.recv(2048)
                return MIN_TLS_RESPONSE in data, "authenticated-HTTP"
        except (ssl.SSLError, OSError, TimeoutError) as exc:
            return False, (
                type(exc).__name__ + ":" + str(getattr(exc, "reason", "transport"))
            )


def safe_native_diagnostic(raw: bytes) -> str:
    # Only fixed phase/status/counter lines; never TLS record bytes or keys.
    safe = raw.decode(errors="replace").splitlines()
    pattern = re.compile(
        r"^(Crypto test-only TLS server/exporter failed |"
        r"CRYPTO_TEST_REVERSE_PHASE (handshake_complete|request_received|response_sent)|"
        r"CRYPTO_TLS_PRIVATE_(STATE|HANDSHAKE_DIAG) )"
    )
    markers = []
    for line in safe:
        # Print only native filename/line evidence, never error_print's data,
        # X.509 dumps, CertificateVerify, transcript, or key materials.
        markers.extend(re.findall(
            r"(?:tls12|tls13|tls|tls_vrf|x509_cer|x509_ext)\.c:[0-9]{1,5}",
            line,
        )[:4])
    phases = " | ".join(x[:240] for x in safe if pattern.search(x))[-850:]
    return phases + " native_lines=" + ",".join(markers[-16:])


def python_to_native(native_server: str, f: dict[str, Path],
                     folder: Path, proto: str, case: str, port: int) -> None:
    work_secret = folder / ("native-" + proto + "-" + case + ".secret")
    argv = [
        native_server, proto, str(port), str(f["server"]),
        str(f["server-key"]), str(work_secret), str(f["ca"]),
    ]
    # Deliberately no fixture contents in stdout/stderr logs.
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        context = python_tls_context("client", proto, f, case)
        success, client_reason = python_client_to_native(context, port, proto, "localhost")
        try:
            stdout, stderr = proc.communicate(timeout=TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            raise GateFailure(
                f"native TLS{proto} server {case} did not terminate"
            ) from exc
        require(not work_secret.exists(), "mTLS test wrote forbidden exporter secret")
        if case == "client":
            require(success and proc.returncode == 0,
                    f"native server TLS{proto} rejected valid Python client: "
                    + client_reason + " | " + safe_native_diagnostic(stderr))
            require(
                b"handshake_complete protocol=" in stderr
                and b"auth=1" in stderr,
                "native server did not report REQUIRED authenticated client",
            )
        else:
            require(not success and proc.returncode != 0,
                    f"native server TLS{proto} ACCEPTED {case} client certificate")
            require(
                b"phase=3" in stderr and b"handshake=0" in stderr
                and b"client_auth=1" in stderr,
                f"native TLS{proto} {case}: rejection was NOT in handshake: "
                + safe_native_diagnostic(stderr),
            )
        print(f"PASS Python-client/native-C11-server TLS{proto} {case}")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=4)


def python_server_for_native(ctx: ssl.SSLContext, listener: socket.socket,
                             results: dict[str, object]) -> None:
    try:
        with listener:
            conn, _ = listener.accept()
            with conn:
                try:
                    with ctx.wrap_socket(conn, server_side=True) as tls:
                        results["authenticated"] = True
                        require(tls.getpeercert() is not None,
                                "Python server accepted missing client identity")
                        results["peer_version"] = tls.version()
                        tls.settimeout(7.0)
                        request = tls.recv(4096)
                        results["request"] = REQUEST in request
                        if results["request"]:
                            tls.sendall(RESPONSE)
                except ssl.SSLError as exc:
                    results["rejected_reason"] = str(
                        getattr(exc, "reason", type(exc).__name__)
                    )
    except (OSError, GateFailure, TimeoutError) as exc:
        results["error_type"] = type(exc).__name__


def native_to_python(native_client: str, f: dict[str, Path],
                     proto: str, case: str) -> None:
    ctx = python_tls_context("server", proto, f, case)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((ADDRESS, 0))
    listener.listen(1)
    listener.settimeout(15.0)
    port = listener.getsockname()[1]
    results: dict[str, object] = {"authenticated": False}
    worker = threading.Thread(
        target=python_server_for_native, args=(ctx, listener, results),
        daemon=True,
    )
    worker.start()
    sha = str(f["server-sha256"])
    argv = [
        native_client, proto, str(port), str(f["ca"]), "localhost",
        "good", sha, str(f["server-der"]), "--mtls",
    ]
    if case != "missing":
        argv.extend((str(f[case]), str(f[case + "-key"])))
    try:
        result = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=TIMEOUT, check=False,
        )
        worker.join(timeout=4.0)
        require(not worker.is_alive(), f"Python TLS{proto} server did not finish")
        if case == "client":
            require(
                result.returncode == 0
                and results.get("authenticated") is True
                and results.get("request") is True
                and results.get("peer_version") == "TLSv1." + proto[-1],
                f"native client TLS{proto} rejected valid identity"
                f" (status={result.returncode}, peer={results})",
            )
        else:
            require(
                result.returncode != 0 and not results.get("authenticated"),
                f"Python TLS{proto} server ACCEPTED invalid Crypto client {case}",
            )
            # Distinguish real peer rejection from an unexercised local abort.
            require(
                "rejected_reason" in results,
                f"TLS{proto}/{case} did not prove Python peer handshake rejection: "
                + str(results),
            )
        print(f"PASS native-C11-client/Python-server TLS{proto} {case}")
    finally:
        listener.close()
        worker.join(timeout=1.0)


def run(native_server: str, native_client: str, destination: Path) -> None:
    require(ssl.OPENSSL_VERSION_INFO[0] >= 3,
            "Python ssl needs an actively supported TLS1.3 implementation")
    destination.mkdir(parents=True, exist_ok=True)
    # Temp root and every key are private and deleted on failures, too.
    with tempfile.TemporaryDirectory(dir=destination, prefix="mtls-private-") as td:
        folder = Path(td)
        folder.chmod(0o700)
        fixtures = make_fixtures(folder)
        for proto in PROTOCOLS:
            for case in ("client", *CASE_NAMES):
                # One isolated native process per tested server connection.
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as port_probe:
                    port_probe.bind((ADDRESS, 0))
                    port = port_probe.getsockname()[1]
                python_to_native(
                    native_server, fixtures, folder, proto, case, port,
                )
            for case in ("client", *CASE_NAMES):
                native_to_python(native_client, fixtures, proto, case)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-server", required=True)
    parser.add_argument("--native-client", required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.native_server, args.native_client, args.work)
    except (GateFailure, ssl.SSLError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"FAIL Python/native mTLS: {type(exc).__name__}: {exc}", flush=True)
        raise SystemExit(1) from None
