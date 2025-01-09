from typing import List, Optional
import mysql.connector
import boto3
import base64
import io
import os
from datetime import datetime
from libnacl import (
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
    crypto_box_NONCEBYTES,
    crypto_secretbox_MACBYTES,
    crypto_secretbox_KEYBYTES,
    crypto_box_seal_open,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    crypto_aead_xchacha20poly1305_ietf_ABYTES,
    crypto_secretbox_open_easy,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_kdf_derive_from_key,
)
from nacl.pwhash.argon2id import OPSLIMIT_MODERATE, MEMLIMIT_MODERATE, kdf, SALTBYTES
from .model import DataFolderType, Album, File, FileType, Header
from .mnemonic import mnemonic_to_keys


class Client:
    def __init__(
        self,
        mysql_host: Optional[str] = None,
        mysql_port: Optional[int] = 3306,
        mysql_database: Optional[str] = None,
        mysql_username: Optional[str] = None,
        mysql_password: Optional[str] = None,
        data_folder_type: Optional[DataFolderType] = None,
        data_folder_path: Optional[str] = None,
        data_folder_bucket: Optional[str] = None,
        data_folder_region: Optional[str] = None,
        data_folder_access_key: Optional[str] = None,
        data_folder_secret_key: Optional[str] = None,
        stingle_username: Optional[str] = None,
        stingle_password: Optional[str] = None,
        stingle_key_mnemonic: Optional[str] = None,
    ):
        self.__mysql_host = mysql_host
        self.__mysql_port = mysql_port
        self.__mysql_database = mysql_database
        self.__mysql_username = mysql_username
        self.__mysql_password = mysql_password
        self.__data_folder_type = data_folder_type
        self.__data_folder_path = data_folder_path
        self.__data_folder_bucket = data_folder_bucket
        self.__data_folder_region = data_folder_region
        self.__data_folder_access_key = data_folder_access_key
        self.__data_folder_secret_key = data_folder_secret_key
        self.__stingle_username = stingle_username
        self.__stingle_password = stingle_password
        self.__stingle_key_mnemonic = stingle_key_mnemonic
        self.__user_key = None
        self.__album_keys = {}
        self.__opened = False
        self.__validate()
        self.__make_s3_client()

    def __validate(self) -> None:
        if self.__data_folder_type == DataFolderType.S3:
            if self.__data_folder_bucket is None:
                raise ValueError("Bucket is required for S3 data folder")
            if self.__data_folder_region is None:
                raise ValueError("Region is required for S3 data folder")
        elif self.__data_folder_type == DataFolderType.Local:
            if self.__data_folder_path is None:
                raise ValueError("Path is required for local data folder")
        else:
            raise ValueError("Invalid data folder type")
        if self.__mysql_host is None:
            raise ValueError("Host is required for MySQL connection")
        if self.__mysql_database is None:
            raise ValueError("Database is required for MySQL connection")
        if self.__mysql_username is None:
            raise ValueError("Username is required for MySQL connection")
        if self.__mysql_password is None:
            raise ValueError("Password is required for MySQL connection")
        if self.__stingle_username is None:
            raise ValueError("Username is required for Stingle API")
        if self.__stingle_password is None and self.__stingle_key_mnemonic is None:
            raise ValueError("Password or secret key is required for Stingle API")

    def __make_s3_client(self) -> None:
        if self.__data_folder_type != DataFolderType.S3:
            return
        self.s3_client = boto3.client(
            "s3",
            region_name=self.__data_folder_region,
            aws_access_key_id=self.__data_folder_access_key,
            aws_secret_access_key=self.__data_folder_secret_key,
        )

    def open(self) -> None:
        self.connection = mysql.connector.connect(
            host=self.__mysql_host,
            port=self.__mysql_port,
            database=self.__mysql_database,
            user=self.__mysql_username,
            password=self.__mysql_password,
        )
        self.__get_user()
        self.__opened = True

    def close(self) -> None:
        self.connection.close()
        self.__opened = False

    def __get_user(self) -> None:
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT id FROM wum_users WHERE login = %s", (self.__stingle_username,)
        )
        row = cursor.fetchone()
        cursor.close()
        if row is None:
            raise ValueError("User not found")
        self.__user_id = row[0]
        self.__get_user_key()

    def __get_user_key(self) -> None:
        if self.__stingle_key_mnemonic is not None:
            self.__user_key = mnemonic_to_keys(self.__stingle_key_mnemonic)
            return
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT key_bundle FROM sp_key_bundles WHERE id = %s", (self.__user_id,)
        )
        row = cursor.fetchone()
        cursor.close()
        if row is None:
            raise ValueError(
                "User key has not been backed up, you must specify it in client initialization"
            )
        key = row[0]
        if not key:
            raise ValueError(
                "User key has not been backed up, you must specify it in client initialization"
            )
        self.__user_key = self.__decrypt_key_bundle(key, self.__stingle_password)

    def __get_key_from_password(self, password: str, salt: bytes) -> bytes:
        return kdf(
            crypto_secretbox_KEYBYTES,
            password.encode(),
            salt,
            opslimit=OPSLIMIT_MODERATE,
            memlimit=MEMLIMIT_MODERATE,
        )

    def __decrypt_symmetric(self, key: bytes, nonce: bytes, data: bytes) -> bytes:
        return crypto_secretbox_open_easy(data, nonce, key)

    def __decrypt_seal(
        self, data: bytes, public_key: bytes = None, private_key: bytes = None
    ) -> bytes:
        self.__check_opened()
        if public_key is None:
            public_key = self.__user_key[0]
        if private_key is None:
            private_key = self.__user_key[1]
        return crypto_box_seal_open(data, public_key, private_key)

    def __decrypt_key_bundle(self, bundle: str, password: str) -> tuple[bytes, bytes]:
        dec = base64.b64decode(bundle)
        if dec[:3] != b"SPK":
            raise ValueError("invalid bundle")
        version = dec[3]
        if version != 1:
            raise ValueError(f"unsupported version: {version}")
        type = dec[4]
        if type != 0:
            raise ValueError(f"unsupported type: {type}")
        buf = dec[5:]
        public_key = buf[:crypto_box_PUBLICKEYBYTES]
        buf = buf[crypto_box_PUBLICKEYBYTES:]
        encrypted_private_key = buf[
            : crypto_box_SECRETKEYBYTES + crypto_secretbox_MACBYTES
        ]
        buf = buf[crypto_box_SECRETKEYBYTES + crypto_secretbox_MACBYTES :]
        pwd_salt = buf[:SALTBYTES]
        buf = buf[SALTBYTES:]
        sk_nonce = buf[:crypto_box_NONCEBYTES]
        buf = buf[crypto_box_NONCEBYTES:]
        key_from_password = self.__get_key_from_password(password, pwd_salt)
        private_key = self.__decrypt_symmetric(
            key_from_password, sk_nonce, encrypted_private_key
        )
        return public_key, private_key

    def __check_opened(self) -> None:
        if not self.__opened:
            raise ValueError("Client is not opened, please call open() first")

    def __parse_album_name(self, metadata: bytes) -> str:
        if metadata[0] != 1:
            raise ValueError("Unsupported album metadata version")
        len = int.from_bytes(metadata[1:5], "big")
        return metadata[5 : 5 + len].decode("utf-8")

    def __get_album_key(self, album_id: str) -> tuple[bytes, bytes]:
        if album_id in self.__album_keys:
            return self.__album_keys[album_id]
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT encPrivateKey, publicKey FROM sp_albums WHERE albumId = %s AND userId = %s",
            (album_id, self.__user_id),
        )
        row = cursor.fetchone()
        cursor.close()
        if row is None:
            raise ValueError("Album not found")
        enc_private_key, public_key = row
        public_key = base64.b64decode(public_key)
        enc_private_key = base64.b64decode(enc_private_key)
        private_key = self.__decrypt_seal(enc_private_key)
        self.__album_keys[album_id] = (public_key, private_key)
        return public_key, private_key

    def get_albums(self) -> List[Album]:
        self.__check_opened()
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT albumId, encPrivateKey, publicKey, metadata FROM sp_albums WHERE userId = %s",
            (self.__user_id,),
        )
        albums = []
        try:
            for row in cursor:
                album_id, enc_private_key, public_key, metadata = row
                public_key = base64.b64decode(public_key)
                enc_private_key = base64.b64decode(enc_private_key)
                metadata = base64.b64decode(metadata)
                private_key = self.__decrypt_seal(enc_private_key)
                self.__album_keys[album_id] = (public_key, private_key)
                dec_metadata = self.__decrypt_seal(metadata, public_key, private_key)
                albums.append(Album(album_id, self.__parse_album_name(dec_metadata)))
            return albums
        finally:
            cursor.close()

    def __get_file_version(self, data: io.BufferedReader) -> int:
        magic_bytes = data.read(2)
        if magic_bytes != b"SP":
            raise ValueError("unrecognized file")
        file_version = int.from_bytes(data.read(1), "big")
        if file_version != 1:
            raise ValueError(f"unsupported file version: {file_version}")
        return file_version

    def __parse_header(
        self,
        data: io.BufferedReader,
        public_key: Optional[bytes] = None,
        private_key: Optional[bytes] = None,
    ) -> Header:
        if public_key is None:
            public_key = self.__user_key[0]
        if private_key is None:
            private_key = self.__user_key[1]
        file_version = self.__get_file_version(data)
        file_id = self.__encode_url_base64(data.read(32))
        header_size = int.from_bytes(data.read(4), "big")
        enc_header_content = data.read(header_size)
        header_content = io.BytesIO(
            self.__decrypt_seal(enc_header_content, public_key, private_key)
        )
        header_version = int.from_bytes(header_content.read(1), "big")
        chunk_size = int.from_bytes(header_content.read(4), "big")
        data_size = int.from_bytes(header_content.read(8), "big")
        symmetric_key = header_content.read(32)
        file_type = int.from_bytes(header_content.read(1), "big")
        file_name_size = int.from_bytes(header_content.read(4), "big")
        file_name = header_content.read(file_name_size).decode("utf-8")
        video_duration = int.from_bytes(header_content.read(4), "big")
        return Header(
            file_version,
            file_id,
            header_size,
            header_version,
            chunk_size,
            data_size,
            symmetric_key,
            FileType(file_type),
            file_name,
            video_duration,
        )

    def __skip_header(self, data: io.BufferedReader) -> None:
        _ = self.__get_file_version(data)
        _ = data.read(32)
        header_size = int.from_bytes(data.read(4), "big")
        _ = data.read(header_size)

    def __decode_url_base64(self, data) -> bytes:
        data += "=" * (len(data) % 4)
        return base64.urlsafe_b64decode(data)

    def __encode_url_base64(self, data) -> str:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    def list_files(
        self, album_id: Optional[str] = None, skip: int = 0, limit: int = 0
    ) -> List[File]:
        self.__check_opened()
        if album_id is None:
            public_key, private_key = self.__user_key
        else:
            public_key, private_key = self.__get_album_key(album_id)
        search_param = album_id if album_id is not None else self.__user_id
        if limit > 0:
            offset_limit = "LIMIT %s OFFSET %s"
            params = (search_param, limit, skip)
        elif skip > 0:
            offset_limit = "OFFSET %s"
            params = (search_param, skip)
        else:
            offset_limit = ""
            params = (search_param,)
        cursor = self.connection.cursor()
        try:
            if album_id is None:
                cursor.execute(
                    f"SELECT file, fileId, size, version, dateCreated, dateModified, headers FROM sp_files WHERE userId = %s ORDER BY dateCreated, id {offset_limit}",
                    params,
                )
            else:
                cursor.execute(
                    f"SELECT file, fileId, size, version, dateCreated, dateModified, headers FROM sp_album_files WHERE albumId = %s ORDER BY dateCreated, id {offset_limit}",
                    params,
                )
            files = []
            for row in cursor:
                file, file_id, size, version, date_created, date_modified, headers = row
                splitted_headers = headers.split("*")
                file_header = self.__parse_header(
                    io.BytesIO(self.__decode_url_base64(splitted_headers[0])),
                    public_key,
                    private_key,
                )
                thumbnail_header = None
                if len(splitted_headers) > 1:
                    thumbnail_header = self.__parse_header(
                        io.BytesIO(self.__decode_url_base64(splitted_headers[1])),
                        public_key,
                        private_key,
                    )
                if file_header.file_id != file_id:
                    raise ValueError("File ID mismatch")
                files.append(
                    File(
                        file_id,
                        file,
                        version,
                        size,
                        datetime.fromtimestamp(date_created / 1000),
                        datetime.fromtimestamp(date_modified / 1000),
                        file_header,
                        thumbnail_header,
                    )
                )
            return files
        finally:
            cursor.close()

    def __open_file(self, path: List[str]) -> io.BufferedReader:
        if self.__data_folder_type == DataFolderType.S3:
            key = "/".join(path)
            return self.s3_client.get_object(Bucket=self.__data_folder_bucket, Key=key)[
                "Body"
            ]
        path = os.path.join(self.__data_folder_path, *path)
        return open(path, "rb")

    def __decrypt_chunk(
        self, chunk_number: int, chunk_data: bytes, key: bytes
    ) -> bytes:
        if (
            len(chunk_data)
            < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
            + crypto_aead_xchacha20poly1305_ietf_ABYTES
            + 1
        ):
            raise ValueError("invalid chunk data")
        nonce = chunk_data[:crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]
        data = chunk_data[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:]
        derived_key = crypto_kdf_derive_from_key(
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES, chunk_number, b"__data__", key
        )
        return crypto_aead_xchacha20poly1305_ietf_decrypt(data, b"", nonce, derived_key)

    def __decrypt_data(
        self,
        data: io.BufferedReader,
        out: io.BufferedWriter,
        key: bytes,
        chunk_size: int,
    ) -> None:
        full_chunk_size = (
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
            + chunk_size
            + crypto_aead_xchacha20poly1305_ietf_ABYTES
        )
        chunk_number = 1
        while True:
            chunk_data = data.read(full_chunk_size)
            if not chunk_data:
                break
            res = self.__decrypt_chunk(chunk_number, chunk_data, key)
            out.write(res)
            chunk_number += 1

    def write_file(self, file: File, out: io.BufferedWriter) -> None:
        path = ["uploads", "files", file.encrypted_file_name]
        fh = self.__open_file(path)
        self.__skip_header(fh)
        self.__decrypt_data(fh, out, file.header.symmetric_key, file.header.chunk_size)

    def get_file(self, file: File) -> bytes:
        out = io.BytesIO()
        self.write_file(file, out)
        return out.getvalue()

    def write_thumbnail(self, file: File, out: io.BufferedWriter) -> None:
        if file.thumbnail_header is None:
            raise ValueError("File has no thumbnail")
        path = ["uploads", "thumbs", file.encrypted_file_name]
        fh = self.__open_file(path)
        self.__skip_header(fh)
        self.__decrypt_data(
            fh,
            out,
            file.thumbnail_header.symmetric_key,
            file.thumbnail_header.chunk_size,
        )

    def get_thumbnail(self, file: File) -> bytes:
        out = io.BytesIO()
        self.write_thumbnail(file, out)
        return out.getvalue()
