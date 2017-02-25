#!/usr/bin/env python3

import logging
import queue
import threading

from apt_reflect import utils
from apt_reflect.indices import release as release_index
from apt_reflect.indices import packages as packages_index

logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)


def main():
    base = 'http://deb.debian.org/debian'
    codename = 'jessie'
    comps = ['non-free', 'contrib']
    arches = ['binary-amd64', 'binary-i386']

    release_path = '/'.join([base, 'dists', codename, 'Release'])
    release = None
    if utils.check_exists(release_path):
        release = release_index.ReleaseIndex(release_path, base, codename)
        packages_indices = release.get_packages_indices(
            comps, arches, smallest=True)
    else:
        packages_indices = utils.find_packages_indices(base, codename,
            comps, arches)

    threads = 20
    q = queue.Queue(threads * 2)
    for i in range(threads):
        t = threading.Thread(target=do_work, args=(q,))
        t.daemon = True
        t.start()

    bucket = utils.get_session('testing')
    items = {x.key for x in bucket.objects.all()}
    for path in packages_indices:
        packages = packages_index.PackagesIndex('/'.join([base, path]))
        for filename, info in packages.files.items():
            if filename in items:
                continue
            q.put((release, filename, info, False))
        q.join()

    if release:
        for filename, info in release.get_indices(components=comps, architectures=arches).items():
            q.put((release, filename, info, True))
        q.join()

def do_work(work_queue):
    bucket = utils.get_session('testing')
    while True:
        queue_item = work_queue.get()
        release, filename, info, can_be_missing = queue_item
        data = utils.download_package(release, filename, info, can_be_missing)
        if not data:
            work_queue.task_done()
            continue
        utils.upload_package(bucket, filename, data, info)
        work_queue.task_done()

if __name__ == '__main__':
    main()
