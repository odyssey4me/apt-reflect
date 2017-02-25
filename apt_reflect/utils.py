#!/usr/bin/env python3

import base64
import binascii
import bz2
import contextlib
import gzip
import hashlib
import io
import logging
from io import BytesIO
import re
import sys
import queue
import threading

import boto3
import botocore
import requests


try:
    import lzma
    HAS_LZMA = True
except ImportError:
    HAS_LZMA = False

try:
    import gnupg
    HAS_GNUPG = True
except ImportError:
    HAS_GNUPG = False


logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)
LOG = logging.getLogger(__name__)


def fetch(url, can_be_missing=False):
    LOG.debug('Fetching {}'.format(url))
    with contextlib.closing(requests.get(url)) as r:
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
        return gzip.GzipFile(fileobj=io.BytesIO(data)).read()
    elif name.endswith('.bz2'):
        return bz2.decompress(data)
    elif name.endswith(('.xz', '.lzma')):
        if not HAS_LZMA:
            LOG.error('Please install python3-lzma')
            raise
        return lzma.decompress(data)
    return data


def verify_data(info, data):
    for k, v in info.items():
        if k == 'size':
            if len(data) != v:
                LOG.error('Filesize mismatch')
                raise
        elif k in ['md5', 'sha1', 'sha256', 'sha512']:
            if getattr(hashlib, k)(data).hexdigest() != v:
                LOG.error('{} mismatch'.format(k))
                raise
        else:
            LOG.error('Unknown verification data key "{}"'.format(k))


def download_package(release, filename, info, can_be_missing=False):
    data = fetch('/'.join([release.url, filename]), can_be_missing)
    if not data:
        return
    verify_data(info, data)
    return data


def upload_package(bucket, key, data, info):
    md5_hex = binascii.a2b_hex(info['md5'])
    LOG.debug('Pushing {}'.format(key))
    bucket.Object(key).put(
        ACL='public-read',
        Body=data,
        ContentLength=info['size'],
        ContentMD5=base64.b64encode(md5_hex).decode('utf-8'),
    )


def check_arch_exists(base_url, path):
    index = '/'.join([base_url, path])
    for ext in ['.gz', '.bz2', '.xz', '.lzma', str()]:
        url = index + ext
        if check_exists(url):
            return path + ext


def find_packages_indices(base, codename, components, architectures):
    packages_indices = list()
    for comp in components:
        for arch in architectures:
            url = '/'.join(['dists', codename, comp, arch, 'Packages'])
            path = check_arch_exists(base, url)
            if path:
                packages_indices.append(path)
    return packages_indices


def check_exists(url):
    with contextlib.closing(requests.head(url, allow_redirects=True)) as r:
        return r.status_code == requests.codes.ok


def get_session(bucket):
    session = boto3.session.Session()
    s3 = session.resource('s3', endpoint_url='http://10.10.1.1:7480')
    return s3.Bucket(bucket)
