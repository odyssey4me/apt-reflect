import logging
import re

LOG = logging.getLogger(__name__)

OPT_MAP = {
    'Files': 'md5',
    'Checksums-Sha1': 'sha1',
    'Checksums-Sha256': 'sha256',
    'Checksums-Sha512': 'sha512',
}


class SourcesIndex:
    def __init__(self, data):
        self.files = dict()
        self._parse(data)

    def _parse(self, data):
        def save(info):
            if not info:
                return
            directory = info.pop('Directory')
            for k, v in info.items():
                path = '/'.join([directory, k])
                self.files[path] = v

        word_opt = set([
            'Directory',
        ])
        multiline_opt = set([
            'Checksums-Sha1',
            'Checksums-Sha256',
            'Checksums-Sha512',
            'Files',
        ])

        info = dict()
        for line in data.split('\n'):
            if not line.strip():
                save(info)
                info = dict()
                continue

            if re.match(r'\s', line):
                if not section:
                    continue
                checksum, size, filename = line.split()
                size = int(size)

                if filename not in info:
                    info[filename] = dict()
                if 'size' in info[filename] and size != info[filename]['size']:
                    LOG.error('size mismatch for file: {}'.format(filename))
                else:
                    info[filename]['size'] = size
                info[filename][section] = checksum
            else:
                section = None
                split = line.split(':', 1)
                opt = split[0].strip()
                value = split[-1].strip()

                if opt in word_opt:
                    info[opt] = value
                elif opt in multiline_opt:
                    section = OPT_MAP[opt]
        save(info)
