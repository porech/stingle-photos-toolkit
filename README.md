# stingle-photos-toolkit

A Python library to interact with [Stingle Photos](https://stingle.org/) database and data files. It supports connecting to the MySQL database, either live or a dump restore, and to the file system or a copy of it, either local or S3.

Please note that this library does not interact with the Stingle API, but directly with files and database, so it's suitable only for self-hosted setups.

## Project status

This is a work in progress: documentation is still missing. However, it works. You can refer to the example below, it should be pretty clear how to use it.

## Installing

The package is published on PyPi so you can install it with your preferred package manager, for example:

```
pip install stingle-photos-toolkit
```

## Building from source

You need to have `uv` installed to build the wheel:

```
uv build
```

Then, you can install the wheel in the virtualenv you prefer (no uv required) with something like:

```
pip install dist/*.whl
```

## Using

This is a fairly complete example of everything the library currently supports:

```python
from StinglePhotosToolkit import Client, DataFolderType

# Initialize the client
client = Client(
    mysql_host="localhost",
    mysql_database="stingle_api",
    mysql_username="user",
    mysql_password="mypassword",
    data_folder_type=DataFolderType.S3,  # If DataFolderType.Local you need to pass the data_folder_path argument instead of the next 4 ones
    data_folder_bucket="my-bucket",
    data_folder_region="eu-central-1",
    data_folder_access_key="MYACCESSKEY",
    data_folder_secret_key="mySecr3tKey",
    stingle_username="mymail@example.org",
    stingle_key_mnemonic="my key recovery mnemonic words",  # Instead, you can pass the stingle_password argument if you backed up the key to the server: the key will be retrieved and decrypted from the database
)

# Opens the MySQL connection and gets some data about the user (id, key if needed)
client.open()

# Get a list of albums available for the users (id and name are returned)
albums = client.get_albums()

# Get a list of files from the first album, get 3 of them
files = client.list_files(album_id=albums[0].id, limit=3)

# Get a list of files that are not in an album, skip the first 6 and get 3 of them
files = client.list_files(skip=6, limit=3)

for f in files:
    # Decrypt the file and save it with its original filename
    with open(f.header.file_name, "wb") as out:
        client.write_file(f, out)
    # Save the thumbnail to another file (thumbnails are all JPEG)
    with open(f"{f.header.file_name}_thumb.jpg", "wb") as out:
        client.write_thumbnail(f, out)
    # You can also get the file content as bytes
    file_data = client.get_file(f)
    thumbnail_data = client.get_thumbnail(f)

# Close the connection to MySQL
client.close()
```

## License

This is released as GNU AFFERO GENERAL PUBLIC LICENSE, the same license of the Stingle API code.
