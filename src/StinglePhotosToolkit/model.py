from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Optional


class DataFolderType(StrEnum):
    S3 = "s3"
    Local = "local"


class Album:
    id: str
    name: str

    def __init__(self, id: str, name: str):
        self.id = id
        self.name = name

    def __repr__(self):
        return f"Album(id={self.id}, name={self.name})"


class FileType(IntEnum):
    General = 1
    Photo = 2
    Video = 3


class Header:
    file_version: int
    file_id: str
    header_size: int
    header_version: int
    chunk_size: int
    data_size: int
    symmetric_key: bytes
    file_type: FileType
    file_name: str
    video_duration: int

    def __init__(
        self,
        file_version: int,
        file_id: str,
        header_size: int,
        header_version: int,
        chunk_size: int,
        data_size: int,
        symmetric_key: bytes,
        file_type: FileType,
        file_name: str,
        video_duration: int,
    ):
        self.file_version = file_version
        self.file_id = file_id
        self.header_size = header_size
        self.header_version = header_version
        self.chunk_size = chunk_size
        self.data_size = data_size
        self.symmetric_key = symmetric_key
        self.file_type = file_type
        self.file_name = file_name
        self.video_duration = video_duration

    def __repr__(self):
        return f"Header(chunk_size={self.chunk_size}, data_size={self.data_size}, file_type={self.file_type.name}, file_name={self.file_name}, video_duration={self.video_duration})"


class File:
    id: str
    encrypted_file_name: str
    version: int
    size: int
    date_created: datetime
    date_modified: datetime
    header: Header
    thumbnail_header: Optional[Header]

    def __init__(
        self,
        id: str,
        encrypted_file_name: str,
        version: int,
        size: int,
        date_created: datetime,
        date_modified: datetime,
        header: Header,
        thumbnail_header: Optional[Header] = None,
    ):
        self.id = id
        self.encrypted_file_name = encrypted_file_name
        self.version = version
        self.size = size
        self.date_created = date_created
        self.date_modified = date_modified
        self.header = header
        self.thumbnail_header = thumbnail_header

    def __repr__(self):
        return f"File(id={self.id}, encrypted_file_name={self.encrypted_file_name}, version={self.version}, size={self.size}, date_created={self.date_created}, date_modified={self.date_modified}, file_type={self.header.file_type.name}, file_name={self.header.file_name}, video_duration={self.header.video_duration})"
