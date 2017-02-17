# apt-reflect
apt-reflect (AR) is an http apt repository mirroring tool.
AR is unique among the myriad of other tools that aim to mirror apt repositories in that it does not use local storage. AR mirrors directly to object storage with implementations for S3 and RGW (radosgw), with Swift soon to follow.

# Main Features
  - Mirror from a remote repository directly into object storage
  - In-line data validation of size and checksums
  - Preservation of signed Release and GPG files

# TODO
Features in progress or planned:
  - OpenStack Swift backend
  - Partial mirror updates (process and compare Packages indices)
  - Quick validation (check all files exist with proper size and md5)
  - Full validation (download all files and validate size and all hashes)
  - Repository from scratch creation
  - Sign or re-sign repository with new key
  - Verify signature against known signing key
  - Generate InRelease from Release and Release.gpg and vice-versa
  - Control indices compression types
