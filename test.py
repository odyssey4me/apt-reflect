#!/usr/bin/env python3

import boto3

s3 = boto3.resource(
    's3',
    region_name='default',
    endpoint_url='http://10.10.1.1:7480',
)

bucket = s3.Bucket('testing')
#bucket.Acl().put(ACL='public-read')

for obj in bucket.objects.all():
    #obj.Acl().put(ACL='public-read')
    print(obj)
