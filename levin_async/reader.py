import sys
import asyncio
from io import BytesIO

from levin_async.utils import rshift
from levin_async.exceptions import BadPortableStorageSignature
from levin_async.ctypes import *
from levin_async.constants import *


class LevinReader:
    def __init__(self, buffer: BytesIO):
        if isinstance(buffer, bytes):
            buffer = BytesIO(buffer)
        self.buffer = buffer

    async def read_payload(self):
        sig1 = await c_uint32.from_buffer(self.buffer)
        sig2 = await c_uint32.from_buffer(self.buffer)
        sig3 = await c_ubyte.from_buffer(self.buffer)

        if sig1 != PORTABLE_STORAGE_SIGNATUREA:
            raise BadPortableStorageSignature()
        elif sig2 != PORTABLE_STORAGE_SIGNATUREB:
            raise BadPortableStorageSignature()
        elif sig3 != PORTABLE_STORAGE_FORMAT_VER:
            raise BadPortableStorageSignature()

        return await self.read_section()

    async def read_section(self):
        from levin_async.section import Section
        section = Section()
        count = await self.read_var_int()

        while count > 0:
            section_name = await self.read_section_name()
            storage_entry = await self.load_storage_entry()
            section.add(section_name, storage_entry)
            count -= 1

        return section

    async def read_section_name(self) -> str:
        len_name = await c_ubyte.from_buffer(self.buffer)
        name = self.buffer.read(len_name.value)
        return name.decode('ascii')

    async def load_storage_entry(self):
        _type = await c_ubyte.from_buffer(self.buffer)

        if (_type & SERIALIZE_FLAG_ARRAY) != 0:
            return await self.load_storage_array_entry(_type)
        if _type == SERIALIZE_TYPE_ARRAY:
            return await self.read_storage_entry_array_entry()
        else:
            return await self.read_storage_entry(_type)

    async def read_storage_entry(self, _type: int):
        return await self.read(_type=_type)

    async def load_storage_array_entry(self, _type: int):
        _type &= ~SERIALIZE_FLAG_ARRAY.value
        return await self.read_array_entry(_type)

    async def read_storage_entry_array_entry(self):
        _type = await c_ubyte.from_buffer(self.buffer)

        if (_type & SERIALIZE_FLAG_ARRAY) != 0:
            raise IOError("wrong type sequences")

        return await self.load_storage_array_entry(_type)

    async def read_array_entry(self, _type: int):
        data = []
        size = await self.read_var_int()

        while size > 0:
            data.append(await self.read(_type=_type))
            size -= 1
        return data

    async def read(self, _type: int = None, count: int = None):
        if isinstance(count, int):
            if count > sys.maxsize:
                raise IOError()
            _data = self.buffer.read(count)
            return _data

        if _type == SERIALIZE_TYPE_UINT64:
            return await c_uint64.from_buffer(self.buffer)
        elif _type == SERIALIZE_TYPE_INT64:
            return await c_int64.from_buffer(self.buffer)
        elif _type == SERIALIZE_TYPE_UINT32:
            return await c_uint32.from_buffer(self.buffer)
        elif _type == SERIALIZE_TYPE_INT32:
            return await c_int32.from_buffer(self.buffer)
        elif _type == SERIALIZE_TYPE_UINT16:
            return await c_uint16.from_buffer(self.buffer)
        elif _type == SERIALIZE_TYPE_INT16:
            return await c_int16.from_buffer(self.buffer)
        elif _type == SERIALIZE_TYPE_UINT8:
            return await c_ubyte.from_buffer(self.buffer)
        elif _type == SERIALIZE_TYPE_INT8:
            return await c_byte.from_buffer(self.buffer)
        elif _type == SERIALIZE_TYPE_OBJECT:
            return await self.read_section()
        elif _type == SERIALIZE_TYPE_STRING:
            return await self.read_byte_array()

    async def read_byte_array(self, count: int = None):
        if not isinstance(count, int):
            count = await self.read_var_int()
        return await self.read(count=count)

    async def read_var_int(self):
        b = await c_ubyte.from_buffer(self.buffer)
        size_mask = b & PORTABLE_RAW_SIZE_MARK_MASK

        if size_mask == PORTABLE_RAW_SIZE_MARK_BYTE:
            v = rshift(b, 2)
        elif size_mask == PORTABLE_RAW_SIZE_MARK_WORD:
            v = rshift(await self.read_rest(b, 1), 2)
        elif size_mask == PORTABLE_RAW_SIZE_MARK_DWORD:
            v = rshift(await self.read_rest(b, 3), 2)
        elif size_mask == PORTABLE_RAW_SIZE_MARK_INT64:
            v = rshift(await self.read_rest(b, 7), 2)
        else:
            raise IOError('invalid var_int')
        return v

    async def read_rest(self, first_byte: int, _bytes: int):
        result = first_byte
        for i in range(0, _bytes):
            result += (await c_ubyte.from_buffer(self.buffer) << 8)

        return result
