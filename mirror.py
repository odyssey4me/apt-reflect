#!/usr/bin/env python3

import binascii
import base64
from datetime import datetime
import hashlib
import logging
from io import BytesIO
import re
import sys

import boto3
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

class PackagesFile:
    def __init__(self, data):
        self.packages = dict()
        self._parse(data)

    def _parse(self, data):
        def save(info):
            if not info:
                return
            filename = info['Filename']
            info.pop('Filename')
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
                info[opt] = value
            elif opt in int_opt:
                info[opt] = int(value)
        save(info)


class ReleaseFile:
    def __init__(self, data, url, codename, components, architectures):
        self.url = url
        self.codename = codename
        self.release = dict()
        self.indices = dict()
        self.files = dict()
        self.pool = dict()
        self.components = dict()
        self._parse(data)
        self._fetch_packages(components, architectures)
        self._add_translation_indices()

    def _add_translation_indices(self):
        for k, v in self.files.items():
            if '/i18n/' in k:
                self.indices.update({k: v})

    def _fetch_packages(self, components, architectures):
        for component in components:
            if component not in self.release['Components']:
                LOG.error('Component "{}" not found'.format(component))
                continue
            self.components[component] = dict()
            for arch in architectures:
                path = '/'.join([
                    'dists', self.codename, component, arch, 'Packages'])
                manifest = self._get_packages_index(path, arch)
                for k in [x for x in self.files if x.startswith(path)]:
                    self.indices.update({k: self.files[k]})
                self.pool.update(manifest.packages)
                self.components[component][arch] = manifest

    def _get_packages_index(self, path, arch):
        keys = [x for x in self.files if x.startswith(path)]
        if not keys:
            LOG.error('Architecture "{}" not found'.format(arch))
            raise
        path = min(keys, key=(lambda key: self.files[key]['size']))
        raw_data = fetch('/'.join([self.url, path]))
        verify_data(self.files[path], raw_data)
        data = decompress(path, raw_data)
        verify_data(self.files['.'.join(path.split('.')[:-1])], data)
        return PackagesFile(data.decode("utf-8"))

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
                    section = opt
                elif opt in date_opt:
                    self.release[opt] = datetime.strptime(value, DATE_FMT)
            else:
                if not section:
                    LOG.error("White space found before key, ignoring line")
                    return
                if section not in self.release:
                    self.release[section] = list()
                checksum, size, path = line.split()
                size = int(size)
                path = '/'.join(['dists', self.codename, path])

                self.release[section].append((checksum, size, path))

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
        if k == 'Size' or k == 'size':
            if len(data) != v:
                LOG.error('Filesize mismatch')
                raise
        elif k == 'MD5Sum' or k == 'MD5sum':
            if hashlib.md5(data).hexdigest() != v:
                LOG.error('MD5 mismatch')
                raise
        elif k == 'SHA1':
            if hashlib.sha1(data).hexdigest() != v:
                LOG.error('SHA1 mismatch')
                raise
        elif k == 'SHA256':
            if hashlib.sha256(data).hexdigest() != v:
                LOG.error('SHA256 mismatch')
                raise



def download_package(release, filename, info, can_be_missing=False):
    data = fetch('/'.join([release.url, filename]), can_be_missing)
    if not data:
        return
    verify_data(info, data)
    return data


def upload_package(bucket, key, data, info):
    if 'MD5sum' in info:
        md5_str = info['MD5sum']
    else:
        md5_str = info['MD5Sum']
    if 'Size' in info:
        size = info['Size']
    else:
        size = info['size']
    md5_hex = binascii.a2b_hex(md5_str)
    LOG.debug('Pushing {}'.format(key))
    bucket.put_object(
        ACL='public-read',
        Body=data,
        ContentLength=size,
        ContentMD5=base64.b64encode(md5_hex).decode('utf-8'),
        Key=key,
    )


def main():
    s3 = boto3.resource('s3', endpoint_url='http://10.10.1.1:7480')
    bucket = s3.Bucket('testing')
    bucket.create(ACL='public-read')

    base = 'http://deb.debian.org/debian'
    codename = 'jessie'
    components = ['main', 'contrib', 'non-free']
    architectures = ['binary-amd64', 'binary-i386']
    release_data = fetch('/'.join([base, 'dists', codename, 'Release']))
    release = ReleaseFile(release_data.decode('utf-8'), base, codename,
        components, architectures)

    for filename, info in release.pool.items():
        data = download_package(release, filename, info)

    for filename, info in release.indices.items():
        data = download_package(release, filename, info, can_be_missing=True)
        if not data:
            continue
        upload_package(bucket, filename, data, info)


if __name__ == '__main__':
    main()
