import logging

LOG = logging.getLogger(__name__)

OPT_MAP = {
    'Filename': 'filename',
    'MD5sum': 'md5',
    'Size': 'size',
    'SHA1': 'sha1',
    'SHA256': 'sha256',
    'SHA512': 'sha512',
}


class PackagesIndex:
    def __init__(self, data):
        self.word_opt = set([
            'Filename',
            'MD5sum',
            'SHA1',
            'SHA256',
        ])
        self.int_opt = set([
            'Size',
        ])

        self.files = dict()
        self._parse(data)

    def _parse(self, data):
        info = dict()
        for line in data.split('\n'):
            if not line.strip():
                self._save_info(info)
                info = dict()
                continue
            self._parse_line(line, info)
        else:
            self._save_info(info)

    def _parse_line(self, line, info):
        split = line.split(':', 1)
        opt = split[0].strip()
        value = split[-1].strip()

        if opt in self.word_opt:
            info[OPT_MAP[opt]] = value
        elif opt in self.int_opt:
            info[OPT_MAP[opt]] = int(value)

    def _save_info(self, info):
        if not info:
            return
        filename = info.pop('filename')
        self.files[filename] = info
