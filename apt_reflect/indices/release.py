#!/usr/bin/env python3

from datetime import datetime
import logging
import re

from apt_reflect.indices import packages as packages_index
from apt_reflect import utils

LOG = logging.getLogger(__name__)

DATE_FMT = '%a, %d %b %Y %H:%M:%S %Z'

OPT_MAP = {
    'Filename': 'filename',
    'MD5Sum': 'md5',
    'Size': 'size',
    'SHA1': 'sha1',
    'SHA256': 'sha256',
}


class ReleaseIndex:
    def __init__(self, data, url, codename):
        self.url = url
        self.codename = codename
        self.release = dict()
        self.indices = dict()
        self.files = dict()
        self.pool = dict()
        self._parse(data)

    def _get_index_paths(self, **kwargs):
        return \
            self._get_translation_index_paths() + \
            self._get_packages_index_paths(**kwargs)

    def _get_packages_index_paths(self, components, architectures):
        ret = list()
        for component in components:
            if component not in self.release['Components']:
                LOG.error('Component "{}" not found'.format(component))
                continue
            for arch in architectures:
                if arch == 'source':
                    LOG.warning('Source mirroring is not implemented yet')
                    continue
                if arch not in self.release['Architectures']:
                    LOG.error('Architecture "{}" not found'.format(arch))
                    continue
                ret.append('/'.join(['dists', self.codename, component,
                    'binary-' + arch, 'Packages']))
        return ret

    def _get_translation_index_paths(self):
        return [k for k in self.files if '/i18n/' in k]

    def _get_packages_index(self, path):
        keys = [x for x in self.files if x.startswith(path)]
        path = min(keys, key=(lambda key: self.files[key]['size']))
        raw_data = utils.fetch('/'.join([self.url, path]))
        utils.verify_data(self.files[path], raw_data)
        data = utils.decompress(path, raw_data)
        utils.verify_data(self.files['.'.join(path.split('.')[:-1])], data)
        return packages_index.PackagesIndex(data.decode("utf-8")).packages

    def get_indices(self, **kwargs):
        return {k: self.files[k] for k in self._get_index_paths(**kwargs)}

    def get_packages(self, **kwargs):
        return {
            k: v
            for i in self._get_packages_index_paths(**kwargs)
            for k, v in self._get_packages_index(i).items()
        }

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
                    section = OPT_MAP[opt]
                elif opt in date_opt:
                    self.release[opt] = datetime.strptime(value, DATE_FMT)
            else:
                if not section:
                    LOG.error("White space found before key, ignoring line")
                    return
                checksum, size, path = line.split()
                size = int(size)
                path = '/'.join(['dists', self.codename, path])

                if path in self.files:
                    if size != self.files[path]['size']:
                        LOG.error('size mismatch for file: {}'.format(path))
                else:
                    self.files[path] = {'size': size}
                self.files[path][section] = checksum
