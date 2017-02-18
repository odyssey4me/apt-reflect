#!/usr/bin/env python3

import binascii
import base64
from datetime import datetime
import hashlib
import logging
from io import BytesIO
import re
import sys
import queue
import threading

import boto3
import botocore.exceptions
import requests

try:
    import bz2
    HAS_BZ2 = True
except ImportError:
    HAS_BZ2 = True

try:
    import lzma
    HAS_LZMA = True
except ImportError:
    HAS_LZMA = True

try:
    import zlib
    HAS_ZLIB = True
except ImportError:
    HAS_ZLIB = False

try:
    import gnupg
    HAS_GNUPG = True
except ImportError:
    HAS_GNUPG = False


logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)

DATE_FMT = '%a, %d %b %Y %H:%M:%S %Z'

OPT_MAP = {
    'MD5sum': 'md5',
    'MD5Sum': 'md5',
    'Size': 'size',
    'SHA1': 'sha1',
    'SHA256': 'sha256',
    'Filename': 'filename',
}


class PackagesFile:
    def __init__(self, data):
        self.packages = dict()
        self._parse(data)

    def _parse(self, data):
        def save(info):
            if not info:
                return
            filename = info.pop('filename')
            self.packages[filename] = info

        word_opt = set([
            'Filename',
            'MD5sum',
            'SHA1',
            'SHA256',
        ])
        int_opt = set([
            'Size',
        ])
        info = dict()
        lines = data.split('\n')
        while lines:
            line = lines.pop()
            if not line.strip():
                save(info)
                info = dict()
                continue

            split = line.split(':', 1)
            opt = split[0].strip()
            value = split[1].strip() if len(split) > 1 else None

            if opt in word_opt:
                info[OPT_MAP[opt]] = value
            elif opt in int_opt:
                info[OPT_MAP[opt]] = int(value)
        save(info)


class ReleaseFile:
    def __init__(self, data, url, codename):
        self.url = url
        self.codename = codename
        self.release = dict()
        self.indices = dict()
        self.files = dict()
        self.pool = dict()
        self._parse(data)

    def _get_index_paths(self, **kwargs):
        return \
            self._get_translation_index_paths() + \
            self._get_packages_index_paths(**kwargs)

    def _get_packages_index_paths(self, components, architectures):
        ret = list()
        for component in components:
            if component not in self.release['Components']:
                LOG.error('Component "{}" not found'.format(component))
                continue
            for arch in architectures:
                if arch == 'source':
                    LOG.warning('Source mirroring is not implemented yet')
                    continue
                if arch not in self.release['Architectures']:
                    LOG.error('Architecture "{}" not found'.format(arch))
                    continue
                ret.append('/'.join(['dists', self.codename, component,
                    'binary-' + arch, 'Packages']))
        return ret

    def _get_translation_index_paths(self):
        return [k for k in self.files if '/i18n/' in k]

    def _get_packages_index(self, path):
        keys = [x for x in self.files if x.startswith(path)]
        path = min(keys, key=(lambda key: self.files[key]['size']))
        raw_data = fetch('/'.join([self.url, path]))
        verify_data(self.files[path], raw_data)
        data = decompress(path, raw_data)
        verify_data(self.files['.'.join(path.split('.')[:-1])], data)
        return PackagesFile(data.decode("utf-8")).packages

    def get_indices(self, **kwargs):
        return {k: self.files[k] for k in self._get_index_paths(**kwargs)}

    def get_packages(self, **kwargs):
        return {
            k: v
            for i in self._get_packages_index_paths(**kwargs)
            for k, v in self._get_packages_index(i).items()
        }

    def _parse(self, data):
        # NOTE: Non-implemented
        #   No-Support-for-Architecture-all
        #   Acquire-By-Hash
        #   Signed-By

        # NOTE: Validate and/or block on Valid-Until field

        date_opt = set([
            'Date',
            'Valid-Until',
        ])
        list_opt = set([
            'Architectures',
            'Components',
        ])
        multiline_opt = set([
            'MD5Sum',
            'SHA1',
            'SHA256',
        ])

        for line in data.split('\n'):
            if not re.match(r'\s', line):
                split = line.split(':', 1)
                opt = split[0].strip()
                value = split[1].strip() if len(split) > 1 else None

                if opt in list_opt:
                    self.release[opt] = [x for x in value.split()]
                elif opt in multiline_opt:
                    section = OPT_MAP[opt]
                elif opt in date_opt:
                    self.release[opt] = datetime.strptime(value, DATE_FMT)
            else:
                if not section:
                    LOG.error("White space found before key, ignoring line")
                    return
                checksum, size, path = line.split()
                size = int(size)
                path = '/'.join(['dists', self.codename, path])

                if path in self.files:
                    if size != self.files[path]['size']:
                        LOG.error('size mismatch for file: {}'.format(path))
                else:
                    self.files[path] = {'size': size}
                self.files[path][section] = checksum


def fetch(url, can_be_missing=False):
    LOG.debug('Fetching {}'.format(url))
    r = requests.get(url)
    if r.status_code != requests.codes.ok:
        if can_be_missing:
            return
        LOG.error('Failed request to {}. Code: {}'.format(url, r.status_code))
        raise
    return r.content


# NOTE: Not implemented
def verify():
    if not HAS_GNUPG:
        LOG.warning('The python-gnupg library is not available')
        # TODO: ALL THE THINGS

    debian_signing_key = 'https://ftp-master.debian.org/keys/archive-key-8.asc'
    debian_signing_security_key = 'https://ftp-master.debian.org/keys/archive-key-8-security.asc'
    debian_fingerprint = '126C0D24BD8A2942CC7DF8AC7638D0442B90D010'
    debian_security_fingerprint = 'D21169141CECD440F2EB8DDA9D6D8F6BC857C906'
    gpg = gnupg.GPG(gnupghome='/tmp/gnupg')
    gpg.recv_keys('keyserver.ubuntu.com', debian_fingerprint, debian_security_fingerprint)

    base = 'http://deb.debian.org/debian'
    codename = 'jessie'
    gpg_file = fetch('/'.join([base, 'dists', codename, 'Release.gpg']))
    with open('/tmp/gpgfile', 'wb') as f:
        f.write(gpg_file)
    gpg.verify_data('/tmp/gpgfile', fetch('/'.join([base, 'dists', codename, 'Release.gpg'])))


def decompress(name, data):
    if name.endswith('.gz'):
        return zlib.decompress(data)
    elif name.endswith(('.xz', '.lzma')):
        return lzma.decompress(data)
    elif name.endswith('.bz2'):
        return bz2.decompress(data)
    return data


def verify_data(info, data):
    for k, v in info.items():
        if k == 'size':
            if len(data) != v:
                LOG.error('Filesize mismatch')
                raise
        elif k in ['md5', 'sha1', 'sha256']:
            if getattr(hashlib, k)(data).hexdigest() != v:
                LOG.error('{} mismatch'.format(k))
                raise
        else:
            LOG.error('Unknown verification data key "{}"'.format(k))


def download_package(release, filename, info, client, can_be_missing=False):
    try:
        meta = client.head_object(Bucket='testing', Key=filename)
    except botocore.exceptions.ClientError:
        meta = None

    if \
        meta and \
        meta['ContentLength'] == info['size'] and \
        meta['ETag'][1:-1] == info['md5']:
        LOG.info('Already downloaded {}, Skipping'.format(filename))
        return

    data = fetch('/'.join([release.url, filename]), can_be_missing)
    if not data:
        return
    verify_data(info, data)
    return data


def upload_package(client, key, data, info):
    md5_hex = binascii.a2b_hex(info['md5'])
    LOG.debug('Pushing {}'.format(key))
    client.put_object(
        ACL='public-read',
        Body=data,
        Bucket='testing',
        ContentLength=info['size'],
        ContentMD5=base64.b64encode(md5_hex).decode('utf-8'),
        Key=key,
    )


def main():
    s3_client = boto3.client('s3', endpoint_url='http://10.10.1.1:7480')
    bucket = s3_client.create_bucket(Bucket='testing', ACL='public-read')

    base = 'http://deb.debian.org/debian'
    codename = 'jessie'
    kwargs = {
        'components': ['main', 'contrib', 'non-free'],
        'architectures': ['amd64', 'i386'],
    }
    release_data = fetch('/'.join([base, 'dists', codename, 'Release']))
    release = ReleaseFile(release_data.decode('utf-8'), base, codename)

    threads = 200
    q = queue.Queue(threads * 2)
    for i in range(threads):
        t = threading.Thread(target=do_work, args=(q,))
        t.daemon = True
        t.start()
    for filename, info in release.get_packages(**kwargs).items():
        q.put((release, filename, info, False))

    q.join()
    for filename, info in release.get_packages(**kwargs).items():
        q.put((release, filename, info, True))

    q.join()

def do_work(work_queue):
    while True:
        queue_item = work_queue.get()
        release, filename, info, can_be_missing = queue_item
        s3_client = boto3.client('s3', endpoint_url='http://10.10.1.1:7480')
        data = download_package(release, filename, info, s3_client, can_be_missing)
        if not data:
            work_queue.task_done()
            continue
        upload_package(s3_client, filename, data, info)
        work_queue.task_done()

if __name__ == '__main__':
    main()
