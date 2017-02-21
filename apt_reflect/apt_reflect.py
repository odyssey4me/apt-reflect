#!/usr/bin/env python3

import logging
import queue
import threading

import boto3

from apt_reflect import utils
from apt_reflect.indices import release as release_index

logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)


def main():
    s3_client = boto3.client('s3', endpoint_url='http://10.10.1.1:7480')
    bucket = s3_client.create_bucket(Bucket='testing', ACL='public-read')

    base = 'http://deb.debian.org/debian'
    codename = 'jessie'
    kwargs = {
        'components': ['main', 'contrib', 'non-free'],
        'architectures': ['amd64', 'i386'],
    }
    release_data = utils.fetch('/'.join([base, 'dists', codename, 'Release']))
    release = release_index.ReleaseIndex(release_data.decode('utf-8'), base, codename)

    threads = 200
    q = queue.Queue(threads * 2)
    for i in range(threads):
        t = threading.Thread(target=do_work, args=(q,))
        t.daemon = True
        t.start()
    for filename, info in release.get_packages(**kwargs).items():
        q.put((release, filename, info, False))

    q.join()
    for filename, info in release.get_indices(**kwargs).items():
        q.put((release, filename, info, True))

    q.join()

def do_work(work_queue):
    while True:
        queue_item = work_queue.get()
        release, filename, info, can_be_missing = queue_item
        s3_client = boto3.client('s3', endpoint_url='http://10.10.1.1:7480')
        data = utils.download_package(release, filename, info, s3_client, can_be_missing)
        if not data:
            work_queue.task_done()
            continue
        utils.upload_package(s3_client, filename, data, info)
        work_queue.task_done()

if __name__ == '__main__':
    main()
