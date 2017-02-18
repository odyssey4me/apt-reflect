#!/usr/bin/env python3

import base64
import binascii
import bz2
import hashlib
import logging
from io import BytesIO
import re
import sys
import queue
import threading
import zlib

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


logging.getLogger("requests").setLevel(logging.WARNING)
LOG = logging.getLogger(__name__)


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
