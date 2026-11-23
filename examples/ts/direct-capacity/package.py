"""Package the /5 TypeScript Direct product and Node coordinator for the shared driver."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


def digest(path):
    with path.open('rb') as f:
        return file_digest(f)


def file_digest(f):
    h = hashlib.sha256()
    for data in iter(lambda: f.read(1 << 20), b''): h.update(data)
    return h.hexdigest()


def assemble(source, previous, cell, work):
    node_dist = 'node-v26.8.1-linux-x64'
    archive = work / 'node.tar.xz'
    subprocess.run(['curl','--fail','--silent','--show-error','--location','--max-time','180','--output',str(archive),
                    'https://nodejs.org/dist/v26.8.1/'+node_dist+'.tar.xz'],check=True)
    if digest(archive) != '3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d':
        raise ValueError('incorrect Linux Node distribution')
    (cell/'bin').mkdir(parents=True)
    with tarfile.open(archive) as tar, (cell/'bin/node').open('wb') as out:
        shutil.copyfileobj(tar.extractfile(node_dist+'/bin/node'), out)
    (cell/'bin/node').chmod(0o755)
    assemble_runtime(source, previous, cell/'source')
    checksums = {f.relative_to(cell).as_posix():digest(f) for f in sorted(cell.rglob('*')) if f.is_file()}
    (cell/'typescript-worker.sha256').write_text(''.join(v+'  '+k+'\n' for k,v in checksums.items()))
    return checksums


def assemble_runtime(source, driver, runtime):
    sdk = source/'flowersec-ts'
    target = runtime/'flowersec-ts'
    def put(src, dst):
        dst.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(src, dst)
    interop = {'currentCapacityProduct.js','currentCapacityCoordinator.js','currentDirectCapacityWorker.js','currentCapacityChannel.js','parityTLS.js',
               'currentDirectCapacityStore.js','currentDirectOverlapWorker.js','currentTunnelCapacityProduct.js','currentTunnelCapacityWorker.js'}
    for f in sorted((sdk/'dist').rglob('*')):
        if not f.is_file() or not (f.suffix == '.js' or f.name.endswith('.d.ts')):
            continue
        relative = f.relative_to(sdk/'dist')
        if 'v4' in relative.parts or 'transportV4' in f.name:
            raise ValueError('distribution includes a v4 runtime')
        if relative.parts[0] != 'interop' or f.name in interop:
            put(f, target/'dist'/relative)
    for name in interop:
        if not (target/'dist/interop'/name).is_file(): raise ValueError('missing product input: '+name)
    put(sdk/'package.json', target/'package.json')
    requirements = json.loads((sdk/'package.json').read_bytes())['dependencies']
    lock = json.loads((sdk/'package-lock.json').read_bytes())['packages']
    pending = [name for name in requirements if not name.startswith('@types/')]; seen = set()
    while pending:
        name = pending.pop()
        if name in seen: continue
        seen.add(name); src = sdk/'node_modules'/name
        meta = json.loads((src/'package.json').read_bytes())
        if meta['version'] != lock['node_modules/'+name]['version']: raise ValueError('dependency differs: '+name)
        pending.extend(meta.get('dependencies',{}))
        for f in sorted(src.rglob('*')):
            if f.is_file() and (f.suffix in {'.js','.json','.mjs','.cjs'} or f.name.startswith(('LICENSE','COPYING'))):
                put(f,target/'node_modules'/name/f.relative_to(src))
    for rel in ['examples/ts/parity.mjs','examples/ts/parity.d.mts','examples/ts/capacity-business.mjs','examples/ts/capacity-business.d.mts','examples/parity-contracts.json']:
        put(source/rel,runtime/rel)
    put(driver/'scripts/capacity-browser-protocol.mjs',runtime/'scripts/capacity-browser-protocol.mjs')
    library = runtime/'node_modules/@floegence/flowersec-core'
    library.parent.mkdir(parents=True)
    library.symlink_to('../../flowersec-ts', target_is_directory=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--driver-source',required=True,type=Path); p.add_argument('--out',required=True,type=Path)
    a = p.parse_args(); out = a.out.resolve()
    if out.exists(): raise FileExistsError(out)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp); cell = work/'cell'; cell.mkdir(); rows = assemble(Path(__file__).resolve().parents[3],a.driver_source,cell,work)
        partial = work/'worker.tar.gz'
        with partial.open('wb') as raw, gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0,compresslevel=3) as gz, tarfile.open(fileobj=gz,mode='w|') as tar:
            for f in sorted(cell.rglob('*')):
                meta=tar.gettarinfo(str(f),arcname=f.relative_to(cell).as_posix()); meta.uid=meta.gid=meta.mtime=0; meta.uname=meta.gname=''
                if f.is_file():
                    with f.open('rb') as data: tar.addfile(meta,data)
                else: tar.addfile(meta)
        with tarfile.open(partial) as tar:
            if len(tar.getnames()) != len(set(tar.getnames())): raise ValueError('duplicate member')
            for name,h in rows.items():
                if file_digest(tar.extractfile(name))!=h: raise ValueError(name)
        out.parent.mkdir(parents=True,exist_ok=True); os.link(partial,out); print(digest(out),out,len(rows))
