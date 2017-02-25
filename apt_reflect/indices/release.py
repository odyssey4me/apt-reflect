#!/usr/bin/env python3

from datetime import datetime
import logging
import re

from apt_reflect.indices import packages as packages_index
from apt_reflect import utils

LOG = logging.getLogger(__name__)

DATE_FMT = '%a, %d %b %Y %H:%M:%S %Z'

OPT_MAP = {
    'Architectures': 'architectures',
    'Components': 'components',
    'Date': 'date',
    'Filename': 'filename',
    'MD5Sum': 'md5',
    'Size': 'size',
    'SHA1': 'sha1',
    'SHA256': 'sha256',
    'SHA512': 'sha512',
    'Valid-Until': 'valid-until',
}


class ReleaseIndex:
    def __init__(self, release_url, url, codename):
        self.url = url
        self.codename = codename
        self.indices = dict()
        self.pool = dict()
        self.metadata = dict()

        self.date_opt = {
            'Date',
            'Valid-Until',
        }
        self.list_opt = {
            'Architectures',
            'Components',
        }
        self.multiline_opt = {
            'MD5Sum',
            'SHA1',
            'SHA256',
        }

        self.files = dict()
        self._parse(utils.fetch(release_url).decode('utf-8'))

    def _get_index_paths(self, **kwargs):
        return \
            self._get_translation_index_paths() + \
            self._get_packages_index_paths(**kwargs)

    def get_packages_indices(self, components, architectures, **kwargs):
        return [
            self._get_packages_index(
                '/'.join(['dists', self.codename, comp, arch, 'Packages']),
                **kwargs
            )
            for comp in components
            for arch in architectures
        ]

    def _get_packages_index_paths(self, components, architectures):
        ret = list()
        for component in components:
            if component not in self.metadata['components']:
                LOG.error('Component "{}" not found'.format(component))
                continue
            for arch in architectures:
                if arch == 'source':
                    LOG.warning('Source mirroring is not implemented yet')
                    continue
                if arch not in self.metadata['architectures']:
                    LOG.error('Architecture "{}" not found'.format(arch))
                    continue
                ret.append('/'.join(['dists', self.codename, component,
                    'binary-' + arch, 'Packages']))
        return ret

    def _get_translation_index_paths(self):
        return [k for k in self.files if '/i18n/' in k]

    def _get_packages_index(self, path, smallest=False):
        if smallest:
            keys = [x for x in self.files if x.startswith(path)]
            paths = sorted(keys, key=lambda key: self.files[key]['size'])
        else:
            paths = ['.'.join([path, x]) for x in ['gz', 'bz2', 'xz', 'lzma']]

        for path in paths:
            if utils.check_exists('/'.join([self.url, path])):
                return path

        # NOTE: No supported compression was found, return uncompressed path
        return path

    #def _get_packages_index(self, path):
    #    path = self._get_packages_index_path(path)
    #    raw_data = utils.fetch('/'.join([self.url, path]))
    #    utils.verify_data(self.files[path], raw_data)
    #    data = utils.decompress(path, raw_data)
    #    utils.verify_data(self.files['.'.join(path.split('.')[:-1])], data)
    #    return packages_index.PackagesIndex(data.decode("utf-8")).files

    def get_indices(self, **kwargs):
        return {k: self.files[k] for k in self._get_index_paths(**kwargs)}

    def get_packages(self, **kwargs):
        return {
            k: v
            for i in self._get_packages_index_paths(**kwargs)
            for k, v in self._get_packages_index(i).items()
        }

    def _parse(self, data):
        section = str()
        for line in data.split('\n'):
            if not re.match(r'\s', line):
                section = self._parse_line(line)
            else:
                self._parse_multiline(line, section)

    def _parse_line(self, line):
        split = line.split(':', 1)
        opt = split[0].strip()
        value = split[-1].strip()

        if opt in self.list_opt:
            self.metadata[OPT_MAP[opt]] = [x for x in value.split()]
        elif opt in self.multiline_opt:
            return OPT_MAP[opt]
        elif opt in self.date_opt:
            self.metadata[OPT_MAP[opt]] = datetime.strptime(value, DATE_FMT)

    def _parse_multiline(self, line, section):
        if not section in ['md5', 'sha1', 'sha256', 'sha512']:
            return

        checksum, size, partial_path = line.split()
        path = '/'.join(['dists', 'jessie', partial_path])
        size = int(size)
        if path not in self.files:
            self.files[path] = dict()
        if 'size' in self.files[path] and size != self.files[path]['size']:
            LOG.error('size mismatch for file: {}'.format(path))
            raise
        else:
            self.files[path]['size'] = size
        self.files[path][section] = checksum
