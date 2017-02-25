#!/usr/bin/env python3

import queue
import threading

from apt_reflect import utils


def main():
    bucket = utils.get_session('testing')
    delete = {'Objects': []}
    for i in bucket.objects.all():
        if len(delete) < 1000:
            delete['Objects'].append({'Key': i.key})
        else:
            bucket.delete_objects(Delete=delete)
            delete['Objects'] = [{'Key': i.key}]
    else:
        bucket.delete_objects(Delete=delete)


if __name__ == '__main__':
    main()
