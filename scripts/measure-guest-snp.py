#!/usr/bin/env python3
"""Calculate candidate SNP reference values; never authorize a real worker."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'compute/guest-firmware-build.json'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked(path, record):
    if path.stat().st_size != record['bytes'] or sha(path) != record['sha256']:
        raise ValueError('A recorded boot artifact changed')


def snapshot(path, destination, record):
    """Hash the exact private copy the measurement library will consume."""
    digest = hashlib.sha256()
    total = 0
    created = False
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError('Require regular boot artifacts')
        with os.fdopen(descriptor, 'rb', closefd=False) as source, destination.open('xb') as target:
            created = True
            while chunk := source.read(1024 * 1024):
                total += len(chunk)
                if total > record['bytes']:
                    raise ValueError('A recorded boot artifact changed')
                target.write(chunk)
                digest.update(chunk)
        if total != record['bytes'] or digest.hexdigest() != record['sha256']:
            raise ValueError('A recorded boot artifact changed')
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--measurement-source', type=Path, required=True)
    parser.add_argument('--vcpu-type', required=True)
    parser.add_argument('--vcpus', type=int, required=True)
    parser.add_argument('--guest-features', type=lambda value:int(value,0), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux':
        raise ValueError('Use Linux for private measurement input snapshots')
    os.umask(0o077)
    if not 1 <= args.vcpus <= 256 or not 0 <= args.guest_features < 2**64 or not args.guest_features & 1:
        raise ValueError('Require 1..256 vCPUs and explicit SNP guest feature bits')
    source, firmware, image, out = [p.resolve() for p in (args.measurement_source,args.firmware,args.image,args.output)]
    if out.exists() or out == ROOT or ROOT in out.parents:
        raise ValueError('Require a new private output directory')
    lock = json.loads(LOCK.read_text())
    revision = subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
    if revision != lock['measurementTool']['revision'] or subprocess.check_output(['git','-C',str(source),'status','--porcelain','--untracked-files=no'],text=True).strip():
        raise ValueError('Measurement source differs from the pinned clean revision')
    fw = json.loads((firmware/'build.json').read_text())
    guest = json.loads((image/'build.json').read_text())
    if fw['schema'] != 'cannabis.guest-firmware-build-result.v1' or fw['sourceRevision'] != lock['source']['revision'] or fw['lockSHA256'] != sha(LOCK):
        raise ValueError('Firmware build does not match the pinned profile')
    if guest['schema'] != 'cannabis.guest-image-build.v1' or guest['executionAuthorized'] is not False:
        raise ValueError('Require the recorded guest component build')
    checked(firmware/'OVMF.fd',fw['output'])
    for name in ['vmlinuz','initramfs.cpio.gz','cmdline']:
        checked(image/name,guest['outputs'][name])
    # Import committed source only; ignored/untracked Python files or cached
    # bytecode in a checkout must not enter the measurement calculation.
    out.mkdir(parents=True)
    boot = out/'boot-inputs'
    boot.mkdir()
    snapshot(firmware/'OVMF.fd', boot/'OVMF.fd', fw['output'])
    for name in ['vmlinuz','initramfs.cpio.gz','cmdline']:
        snapshot(image/name, boot/name, guest['outputs'][name])
    raw_command = (boot/'cmdline').read_bytes()
    command = raw_command.removesuffix(b'\n').decode('ascii')
    if (not command or len(command.encode()) > 4096 or command != command.strip()
            or any(ord(c)<32 or ord(c)>126 for c in command)):
        raise ValueError('Require the recorded printable kernel command line')
    source_snapshot = out/'measurement-source'
    source_snapshot.mkdir()
    export = subprocess.Popen(['git','-C',str(source),'archive','--format=tar',revision,'sevsnpmeasure','LICENSE'],stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=export.stdout,mode='r|') as archive:
            archive.extractall(source_snapshot,filter='data')
    except BaseException:
        export.stdout.close();export.wait();raise
    export.stdout.close()
    if export.wait()!=0:
        raise ValueError('Pinned measurement source export failed')
    sys.path.insert(0,str(source_snapshot))
    from sevsnpmeasure import guest as measurement, vcpu_types
    from sevsnpmeasure.ovmf import OVMF, SectionType
    from sevsnpmeasure.sev_hashes import SevHashes
    from sevsnpmeasure.vmm_types import VMMType
    if args.vcpu_type not in vcpu_types.CPU_SIGS:
        raise ValueError('Unsupported explicit vCPU model')
    signature = vcpu_types.CPU_SIGS[args.vcpu_type]
    parsed = OVMF(str(boot/'OVMF.fd'))
    if not parsed.is_sev_hashes_table_supported() or not parsed.has_metadata_section(SectionType.SNP_KERNEL_HASHES):
        raise ValueError('Firmware lacks kernel/initrd/cmdline measurement metadata')
    hashes = SevHashes(str(boot/'vmlinuz'),str(boot/'initramfs.cpio.gz'),command)
    value = measurement.snp_calc_launch_digest(args.vcpus,signature,str(boot/'OVMF.fd'),str(boot/'vmlinuz'),str(boot/'initramfs.cpio.gz'),command,args.guest_features,'',VMMType.QEMU)
    if len(value) != 48:
        raise ValueError('Unexpected SNP digest size')
    # Recheck the privately retained inputs, never reopen the caller's originals.
    checked(boot/'OVMF.fd',fw['output'])
    for name in ['vmlinuz','initramfs.cpio.gz','cmdline']:
        checked(boot/name,guest['outputs'][name])
    table = hashes.construct_table()
    report = {'schema':'cannabis.snp-reference-candidate.v1','measurementToolRevision':revision,'firmwareSourceRevision':lock['source']['revision'],'firmware':fw['output'],'guestImage':guest['outputs'],'kernelCommandLine':command,'commandLineHashIncludesNul':True,'vcpuType':args.vcpu_type,'vcpuSignature':hex(signature),'vcpus':args.vcpus,'guestFeatures':hex(args.guest_features),'vmmModel':'QEMU as modeled by the pinned measurement source','expectedLaunchDigest':value.hex(),'hashesTable':{'gpa':hex(parsed.sev_hashes_table_gpa()),'bytes':len(table),'sha256':hashlib.sha256(table).hexdigest()},'metadata':[{'gpa':hex(item.gpa),'bytes':item.size,'type':item.section_type().name} for item in parsed.metadata_items()],'candidateOnly':True,'deploymentVMMValidated':False,'hardwareValidated':False,'executionAuthorized':False}
    (out/'hashes-table.bin').write_bytes(table)
    (out/'reference.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    try:
        main()
    except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None
