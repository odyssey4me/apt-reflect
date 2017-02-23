#!/usr/bin/env python3

import queue
import threading

import boto3

def main():
    threads = 20
    q = queue.Queue()
    for i in range(threads):
        t = threading.Thread(target=do_work, args=(q,))
        t.daemon = True
        t.start()

    s3_client = boto3.client('s3', endpoint_url='http://10.10.1.1:7480')
    while s3_client.list_objects(Bucket='testing')['Contents']:
        for i in s3_client.list_objects(Bucket='testing')['Contents']:
            q.put(i['Key'])
        q.join()
        print('done loop')

def do_work(work_queue):
    while True:
        item = work_queue.get()
        s3_client = boto3.client('s3', endpoint_url='http://10.10.1.1:7480')
        s3_client.delete_object(Key=item, Bucket='testing')
        work_queue.task_done()
        print(item)

if __name__ == '__main__':
    main()
