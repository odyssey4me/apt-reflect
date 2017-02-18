OPT_MAP = {
    'Filename': 'filename',
    'MD5sum': 'md5',
    'Size': 'size',
    'SHA1': 'sha1',
    'SHA256': 'sha256',
}


class PackagesIndex:
    def __init__(self, data):
        self.packages = dict()
        self._parse(data)

    def _parse(self, data):
        def save(info):
            if not info:
                return
            filename = info.pop('filename')
            self.packages[filename] = info

        word_opt = set([
            'Filename',
            'MD5sum',
            'SHA1',
            'SHA256',
        ])
        int_opt = set([
            'Size',
        ])
        info = dict()
        lines = data.split('\n')
        while lines:
            line = lines.pop()
            if not line.strip():
                save(info)
                info = dict()
                continue

            split = line.split(':', 1)
            opt = split[0].strip()
            value = split[1].strip() if len(split) > 1 else None

            if opt in word_opt:
                info[OPT_MAP[opt]] = value
            elif opt in int_opt:
                info[OPT_MAP[opt]] = int(value)
        save(info)
