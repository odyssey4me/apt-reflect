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
import lzma
import requests

# Start hack, look away
# TODO: Remove when resolved https://github.com/boto/botocore/issues/1151
from botocore.auth import SigV4Auth
from botocore.compat import urlsplit
def canonical_request(self, request):
    cr = [request.method.upper()]
    path = urlsplit(request.url).path
    cr.append(path)
    cr.append(self.canonical_query_string(request))
    headers_to_sign = self.headers_to_sign(request)
    cr.append(self.canonical_headers(headers_to_sign) + '\n')
    cr.append(self.signed_headers(headers_to_sign))
    if 'X-Amz-Content-SHA256' in request.headers:
        body_checksum = request.headers['X-Amz-Content-SHA256']
    else:
        body_checksum = self.payload(request)
    cr.append(body_checksum)
    return '\n'.join(cr)
SigV4Auth.canonical_request = canonical_request
# End hack

logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)

try:
    import gnupg
    HAS_GNUPG = True
except ImportError:
    HAS_GNUPG = False

DATE_FMT = '%a, %d %b %Y %H:%M:%S %Z'

class PackagesFile:
    def __init__(self, data):
        self.word_opt = set([
            'Filename',
            'MD5sum',
            'SHA1',
            'SHA256',
        ])
        self.int_opt = set([
            'Size',
        ])
        self.packages = self._parse(data)

    def _parse(self, data):
        def save(packages, info):
            if 'Filename' not in info:
                print(info)
            filename = info['Filename']
            info.pop('Filename')
            packages[filename] = info

        packages = dict()
        info = dict()
        lines = data.split('\n')
        while True:
            try:
                line = lines.pop()
            except IndexError:
                if info:
                    save(packages, info)
                break
            if not line.strip():
                if info:
                    save(packages, info)
                info = dict()
            split = line.split(':')
            if split[0] in self.word_opt:
                info[split[0]] = split[1].strip()
            elif split[0] in self.int_opt:
                info[split[0]] = int(split[1].strip())
        return packages


class ReleaseFile:
    def __init__(self, data):
        # NOTE: Non-implemented
        #   No-Support-for-Architecture-all
        #   Acquire-By-Hash
        #   Signed-By

        # NOTE: Validate and/or block on Valid-Until field

        self.date_opt = set([
            'Date',
            'Valid-Until',
        ])
        self.list_opt = set([
            'Architectures',
            'Components',
        ])
        self.multiline_opt = set([
            'MD5Sum',
            'SHA1',
            'SHA256',
        ])
        self.release = self._parse(data)

    def _parse(self, data):
        release = dict()
        for line in data.split('\n'):
            if not re.match(r'\s', line):
                split = line.split(':')
                if split[0] in self.list_opt:
                    release[split[0]] = [x.strip() for x in split[1].split()]
                elif split[0] in self.multiline_opt:
                    self.mode = split[0]
                elif split[0] in self.date_opt:
                    release[split[0]] = datetime.strptime(
                        ':'.join(split[1:]).strip(), DATE_FMT)
            else:
                if not self.mode:
                    LOG.error("White space found before key, ignoring line")
                    return
                if self.mode not in release:
                    release[self.mode] = list()
                checksum, size, path = line.split()
                size = int(size)

                release[self.mode].append((checksum, size, path))

                if 'files' not in release:
                    release['files'] = dict()
                if path in release['files']:
                    if size != release['files'][path]['size']:
                        LOG.error('size mismatch for file: {}'.format(path))
                else:
                    release['files'][path] = {'size': size}
                release['files'][path][self.mode] = checksum
        return release


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


def main():
    s3 = boto3.resource(
        's3',
        region_name='default',
        endpoint_url='http://10.10.1.1:7480',
    )
    bucket = s3.Bucket('testing')
    bucket.create(ACL='public-read')

    base = 'http://deb.debian.org/debian'
    codename = 'jessie'
    release_data = fetch('/'.join([base, 'dists', codename, 'Release']))
    release = ReleaseFile(release_data.decode('utf-8'))
    files = release.release['files']
    for component in ['main', 'contrib', 'non-free']:
        if component not in release.release['Components']:
            LOG.error('Component "{}" not found'.format(component))
            continue
        for arch in ['binary-amd64', 'binary-i386']:
            base_path = '/'.join([component, arch, 'Packages'])
            keys = [x for x in files if base_path in x]
            if not keys:
                LOG.error('Architecture "{}" not found'.format(arch))
                continue
            path = min(keys, key=(lambda key: files[key]['size']))
            raw_data = fetch('/'.join([base, 'dists', codename, path]))
            verify_data(files[path], raw_data)
            data = decompress(path, raw_data)
            verify_data(files['.'.join(path.split('.')[:-1])], data)
            packages = PackagesFile(data.decode("utf-8"))
            for package, info in packages.packages.items():
                obj_data = fetch('/'.join([base, package]))
                verify_data(info, obj_data)
                LOG.debug('Pushing {}'.format(package))
                obj = bucket.put_object(
                    ACL='public-read',
                    ContentLength=info['Size'],
                    ContentMD5=base64.b64encode(binascii.a2b_hex(info['MD5sum'])).decode('utf-8'),
                    Body=obj_data,
                    Key=package,
                )


if __name__ == '__main__':
    main()
