"""JSON and gzip transport for the original portable proof schema."""

from gzip import GzipFile, compress
from io import BytesIO
from pathlib import Path
from zlib import error as ZlibError

from .model import LabError, canonical, loads, write_bytes, write_json

GZIP_MAGIC = b"\x1f\x8b"
GZIP_MIME = "application/gzip"


def _read_proof(stream, compressed, max_content=None):
    if not compressed:
        return loads(stream.read())
    try:
        with GzipFile(fileobj=stream, mode="rb") as wrapper:
            contents = wrapper.read() if max_content is None else wrapper.read(max_content + 1)
    except (OSError, EOFError, ZlibError) as exc:
        raise LabError("The gzip proof is damaged or incomplete") from exc
    if max_content is not None and len(contents) > max_content:
        raise LabError("The decompressed proof exceeds the browser limit. Verify it using the CLI.")
    return loads(contents)


def decode_proof(data, *, compressed=None, max_content=None):
    if compressed is None:
        compressed = data.startswith(GZIP_MAGIC)
    return _read_proof(BytesIO(data), compressed, max_content)


def read_proof(path):
    with Path(path).open("rb") as stream:
        return _read_proof(stream, stream.peek(2).startswith(GZIP_MAGIC))


def gzip_proof(document):
    return compress(canonical(document), compresslevel=6, mtime=0)


def write_proof(path, document):
    if Path(path).suffix.lower() == ".gz":
        write_bytes(path, gzip_proof(document))
    else:
        write_json(path, document)
