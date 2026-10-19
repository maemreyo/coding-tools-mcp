#!/usr/bin/env python3
"""BG-P6W cross-language signed-stdin acceptance using actual compiled Manager code.

Archive an immutable Manager commit; compile its real BrowserV2SetupCommandHandler
against its MCPManagerCore. Inject temporary storage+Chrome folder, never the
production system-account store, and dispatch actual Gateway-signed requests.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from coding_tools_mcp.browser_v2_gateway import (
    BrowserCaller, BrowserGateway, SETUP_REQUEST_NAMESPACE, setup_arguments_json,
)

MANAGER_COMMIT = "4d907177d2df11e8943580fc7a916db38f8ad1fe"
SWIFT_MAIN = r"""
import Foundation
import MCPManagerCore

let env=ProcessInfo.processInfo.environment
let root=URL(fileURLWithPath:env["BG_P6W_FIXTURE_ROOT"]!,isDirectory:true)
let chrome=URL(fileURLWithPath:env["BG_P6W_CHROME_ROOT"]!,isDirectory:true)
let gatewayID=env["BG_P6W_GATEWAY_UUID"]!
let pub=env["BG_P6W_PUBKEY"]!
do {
    let storage=try AgentPrivateStorage(root:root)
    if try BrowserV2OwnerSetup.enrolledGatewayKey(storage:storage) == nil {
        let review=try BrowserV2OwnerSetup.reviewGatewayKey(
            id:gatewayID,publicKey:pub)
        try BrowserV2OwnerSetup.enrollGatewayKey(review,storage:storage)
    }
    let handler=BrowserV2SetupCommandHandler(
        storageProvider: { try AgentPrivateStorage(root:root) },
        inputProvider: { try FileHandle.standardInput.readToEnd() ?? Data() },
        serviceProvider: { BrowserV2SetupService(storage:$0,chromeDirectory:chrome) }
    )
    let router=AgentCommandRouter(handlers:[handler])
    let result=router.execute(arguments:["browser","v2","setup"])
    FileHandle.standardOutput.write(result.stdout)
    FileHandle.standardOutput.write(Data([10]))
    exit(result.exitCode.rawValue)
} catch {
    fputs("fixture failed closed\n",stderr)
    exit(99)
}
"""


def run(*args: str, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manager-repository", type=Path, required=True)
    p.add_argument("--commit", default=MANAGER_COMMIT)
    opts = p.parse_args()
    if opts.commit != MANAGER_COMMIT:
        p.error("Unreviewed Manager commit: first review and update the pinned commit")
    repository = opts.manager_repository.resolve()
    origin = Path(__file__).resolve().parents[1]
    (origin / "dist").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".bg-p6w-swift-manager-", dir=origin/"dist") as td:
        root=Path(td)
        source=root/"immutable-manager"
        source.mkdir()
        raw=run("git","-C",str(repository),"archive","--format=tar",opts.commit,
                capture_output=True).stdout
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
            tar.extractall(source,filter="data")
        handler=source/"Sources/AgentCLI/Commands/BrowserV2SetupCommandHandler.swift"
        verifier=source/"Sources/Core/Setup/BrowserV2SetupAgentAuthorization.swift"
        if not handler.is_file() or not verifier.is_file():
            raise RuntimeError("Manager setup source not found at immutable pin")
        if ("storageProvider:" not in handler.read_text() or
                "zam.browser.setup.caller.v1" not in verifier.read_text()):
            raise RuntimeError("Manager injection/claim contract drift")
        fixture=root/"compiled-fixture"
        swift_sources=fixture/"Sources"
        swift_sources.mkdir(parents=True)
        shutil.copyfile(handler,swift_sources/handler.name)
        (swift_sources/"main.swift").write_text(SWIFT_MAIN)
        (fixture/"Package.swift").write_text(
            '// swift-tools-version: 5.9\nimport PackageDescription\n'
            'let package=Package(name:"BGManagerWireFixture",'
            'platforms:[.macOS(.v13)],'
            f'dependencies:[.package(path:{json.dumps(str(source))})],'
            'targets:[.executableTarget(name:"BGManagerWireFixture",'
            'dependencies:[.product(name:"MCPManagerCore",package:"immutable-manager")],'
            'path:"Sources")])\n')
        run("swift","build","--jobs","4","--package-path",str(fixture),
            "--product","BGManagerWireFixture",stdout=subprocess.DEVNULL)
        executable=fixture/".build/debug/BGManagerWireFixture"
        if not executable.is_file():
            raise RuntimeError("Compiled Manager handler fixture missing")
        signing_key=Ed25519PrivateKey.generate()
        key_file=root/"owner.key"
        key_file.write_bytes(signing_key.private_bytes(
            serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
            serialization.NoEncryption()))
        key_file.chmod(0o600)
        fixture_root=root/"private-agent"
        fixture_root.mkdir(mode=0o700)
        fake_chrome=root/"fake-chrome"
        fake_chrome.mkdir(mode=0o700)
        gateway_id=str(uuid.uuid4()).upper()
        pub=signing_key.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        env=dict(os.environ,BG_P6W_FIXTURE_ROOT=str(fixture_root),
                 BG_P6W_CHROME_ROOT=str(fake_chrome),
                 BG_P6W_GATEWAY_UUID=gateway_id,
                 BG_P6W_PUBKEY=base64.b64encode(pub).decode())
        # Gateway subprocess.run explicitly restricts the environment to
        # PATH and HOME. The *disposable* test binary uses a pinned wrapper
        # to supply only a temporary root and public key, never a secret.
        launcher=root/"fixture-zam"
        launcher.write_text("#!/bin/sh\nexec /usr/bin/env " +
            " ".join(f"{k}={shlex.quote(v)}" for k,v in (
                ("BG_P6W_FIXTURE_ROOT",str(fixture_root)),
                ("BG_P6W_CHROME_ROOT",str(fake_chrome)),
                ("BG_P6W_GATEWAY_UUID",gateway_id),
                ("BG_P6W_PUBKEY",base64.b64encode(pub).decode()),
            )) + f" {shlex.quote(str(executable))} \"$@\"\n")
        launcher.chmod(0o700)
        gateway=BrowserGateway(gateway_id,key_file,launcher,
                               hashlib.sha256(launcher.read_bytes()).hexdigest())
        caller=BrowserCaller(str(uuid.uuid4()).upper(),str(uuid.uuid4()).upper())
        logical=str(uuid.uuid4()).upper()
        status=gateway.dispatch_setup(caller,{"operation":"status","request_id":logical})
        if (status["status"],status["request_id"],status["cli_exit_code"]) != (
                "complete",logical,0):
            raise RuntimeError("Cross-language signed Manager CLI status mismatch")
        # Actual Manager verifier consumes a nonce into its isolated store.
        scoped=str(uuid.uuid5(SETUP_REQUEST_NAMESPACE,
            caller.session_id+"|"+caller.consumer_instance_id+"|"+logical)).upper()
        args={"requestID":scoped,"operation":"status"}
        proof=gateway.setup_proof(caller,args)
        request=setup_arguments_json({"arguments":args,"proof":proof})
        one=subprocess.run([str(launcher),"browser","v2","setup"],input=request,
                           capture_output=True,timeout=25)
        two=subprocess.run([str(launcher),"browser","v2","setup"],input=request,
                           capture_output=True,timeout=25)
        if (one.returncode,two.returncode) != (0,4):
            raise RuntimeError(f"Manager nonce acceptance/replay mismatch: "
                               f"{one.returncode}/{two.returncode}")
        if json.loads(two.stdout)["reason_code"] != "policy_denied":
            raise RuntimeError("Manager replay denial is not typed")
        expired=gateway.setup_proof(caller,args,now_ms=int(time.time()*1000)-70000)
        old=setup_arguments_json({"arguments":args,"proof":expired})
        denied=subprocess.run([str(launcher),"browser","v2","setup"],input=old,
                              capture_output=True,timeout=25)
        if denied.returncode != 4:
            raise RuntimeError("Manager did not deny actual expired claim")
        print("BG_P6W_SWIFT_MANAGER_SIGNED_STDIN_PASS")
        print("Source Manager commit:",opts.commit)
        print("Manager authorization: real compiled source / fixture key + root")
        print("Gateway -> Manager: status complete 0; nonce replay denied 4; expiry denied 4")


if __name__ == "__main__":
    main()
