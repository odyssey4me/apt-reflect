#!/usr/bin/env python3

import queue
import threading

import boto3


def main():
    session = boto3.session.Session()
    s3 = session.resource('s3', endpoint_url='http://10.10.1.1:7480')
    bucket = s3.Bucket('testing')
    items = set([x.key for x in bucket.objects.all()])
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
