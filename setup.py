from distutils.core import setup
setup(
    name = 'apt-reflect',
    packages = [
        'apt_reflect',
        'apt_reflect.cmd',
        'apt_reflect.indices',
    ],
    version = '0.2.0',
    description = 'APT mirror to object storage',
    author = 'Sam Yaple',
    author_email = 'sam+apt-reflect@yaple.net',
    url = 'https://github.com/SamYaple/apt-reflect',
    download_url = 'https://github.com/SamYaple/apt-reflect/tarball/0.2.0',
    keywords = ['radosgw', 'swift', 's3', 'rgw', 'apt', 'deb', 'mirror'],
    classifiers = [],
    entry_points={
        'console_scripts': [
            'apt-reflect=apt_reflect.cmd.mirror:main',
            'apt-reflect-purge=apt_reflect.cmd.purge:main',
        ],
    },
)
