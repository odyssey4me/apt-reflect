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
        self.word_opt = {
            'Directory',
        }
        self.multiline_opt = {
            'Checksums-Sha1',
            'Checksums-Sha256',
            'Checksums-Sha512',
            'Files',
        }

        self.files = dict()
        self._parse(data)

    def _parse(self, data):
        info = dict()
        section = str()
        for line in data.split('\n'):
            if not line.strip():
                self._save_info(info)
                info = dict()
                continue

            if not re.match(r'\s', line):
                section = self._parse_line(line, info)
            else:
                self._parse_multiline(line, info, section)
        else:
            self._save_info(info)

    def _save_info(self, info):
        if not info:
            return
        directory = info.pop('Directory')
        for k, v in info.items():
            path = '/'.join([directory, k])
            self.files[path] = v

    def _parse_line(self, line, info):
        split = line.split(':', 1)
        opt = split[0].strip()
        value = split[-1].strip()

        if opt in self.word_opt:
            info[opt] = value
        elif opt in self.multiline_opt:
           return OPT_MAP[opt]

    def _parse_multiline(self, line, info, section):
        if not section in ['md5', 'sha1', 'sha256', 'sha512']:
            return

        checksum, size, filename = line.split()
        size = int(size)
        if filename not in info:
            info[filename] = dict()
        if 'size' in info[filename] and size != info[filename]['size']:
            LOG.error('size mismatch for file: {}'.format(filename))
            raise
        else:
            info[filename]['size'] = size
        info[filename][section] = checksum
