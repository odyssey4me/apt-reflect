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
        while True:
            try:
                line = lines.pop()
            except IndexError:
                if info:
                    save(info)
                break
            if not line.strip():
                if info:
                    save(info)
                info = dict()

            split = line.split(':', 1)
            opt = split[0].strip()
            if len(split) > 1:
                value = split[1].strip()

            if opt in word_opt:
                info[opt] = value
            elif opt in int_opt:
                info[opt] = int(value)


class ReleaseFile:
    def __init__(self, data, url, codename):
        self.url = url
        self.codename = codename
        self.release = dict()
        self.files = dict()
        self.components = dict()
        self._parse(data)

    def get_packages_manifest(self, component, arch):
        manifest = '/'.join([component, arch, 'Packages'])
        keys = [x for x in self.files if manifest in x]
        if not keys:
            LOG.error('Architecture "{}" not found'.format(arch))
            raise
        path = min(keys, key=(lambda key: self.files[key]['size']))
        raw_data = fetch('/'.join([self.url, 'dists', self.codename, path]))
        verify_data(self.files[path], raw_data)
        data = decompress(path, raw_data)
        verify_data(self.files['.'.join(path.split('.')[:-1])], data)
        if component not in self.components:
            self.components[component] = dict()
        self.components[component][arch] = PackagesFile(data.decode("utf-8"))

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

                self.release[section].append((checksum, size, path))

                if path in self.files:
                    if size != self.files[path]['size']:
                        LOG.error('size mismatch for file: {}'.format(path))
                else:
                    self.files[path] = {'size': size}
                self.files[path][section] = checksum


def fetch(url):
    LOG.debug('Fetching {}'.format(url))
    r = requests.get(url)
    if r.status_code != requests.codes.ok:
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
    elif name.endswith('.xz'):
        return lzma.decompress(data)
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



def download_package(release, filename, info):
    data = fetch('/'.join([release.url, filename]))
    verify_data(info, data)
    return data


def upload_package(bucket, key, data, info):
    md5_hex = binascii.a2b_hex(info['MD5sum'])
    LOG.debug('Pushing {}'.format(key))
    bucket.put_object(
        ACL='public-read',
        Body=data,
        ContentLength=info['Size'],
        ContentMD5=base64.b64encode(md5_hex).decode('utf-8'),
        Key=key,
    )


def main():
    s3 = boto3.resource('s3', endpoint_url='http://10.10.1.1:7480')
    bucket = s3.Bucket('testing')
    bucket.create(ACL='public-read')

    base = 'http://deb.debian.org/debian'
    codename = 'jessie'
    release_data = fetch('/'.join([base, 'dists', codename, 'Release']))
    release = ReleaseFile(release_data.decode('utf-8'), base, codename)
    for component in ['main', 'contrib', 'non-free']:
        if component not in release.release['Components']:
            LOG.error('Component "{}" not found'.format(component))
            continue
        for arch in ['binary-amd64', 'binary-i386']:
            release.get_packages_manifest(component, arch)
            for package, info in release.components[component][arch].packages.items():
                data = download_package(release, package, info)
                upload_package(bucket, package, data, info)


if __name__ == '__main__':
    main()
