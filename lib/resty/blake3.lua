---
--- FFI Based BLAKE3 cryptographic hash API
--- @copyright appla <bhg@live.it>
--- @license Apache
---

local type = type
local error = error
local assert = assert
local tostring = tostring
local setmetatable = setmetatable

local new_str_buf = require "string.buffer".new
local ffi = require "ffi"
local ffi_string = ffi.string
local ffi_new = ffi.new
local ffi_cast = ffi.cast

ffi.cdef [[
    typedef struct {
      uint32_t cv[8];
      uint64_t chunk_counter;
      uint8_t buf[64];
      uint8_t buf_len;
      uint8_t blocks_compressed;
      uint8_t flags;
    } blake3_chunk_state;

    typedef struct {
      uint32_t key[8];
      blake3_chunk_state chunk;
      uint8_t cv_stack_len;
      uint8_t cv_stack[1760];
    } blake3_hasher;

    const char *blake3_version(void);

    void blake3_hasher_init(blake3_hasher *self);
    void blake3_hasher_init_keyed(blake3_hasher *self, const uint8_t *key);
    void blake3_hasher_init_derive_key(blake3_hasher *self, const char *context);
    void blake3_hasher_init_derive_key_raw(blake3_hasher *self, const void *context, size_t context_len);

    void blake3_hasher_update(blake3_hasher *self, const void *input, size_t input_len);

    void blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out, size_t out_len);
    void blake3_hasher_finalize_seek(const blake3_hasher *self, uint64_t seek, uint8_t *out, size_t out_len);

    void blake3_hasher_reset(blake3_hasher *self);
]]

local LIB_BLAKE3 = ffi.load("blake3")

local BLAKE3_OUT_LEN = 32
--local BLAKE3_KEY_LEN = 32
--local BLAKE3_BLOCK_LEN = 64
--local BLAKE3_CHUNK_LEN = 32
--local BLAKE3_MAX_DEPTH = 54
-- ours max output len
local MAX_OUT_OUT_LEN = 32 * 1024

local HASHER_NORMAL = 0
local HASHER_KEYED = 1
local HASHER_DERIVED_KEY = 2

-- C types
local blake3_hasher_ct = ffi.typeof("blake3_hasher")
local uint64_ct = ffi.typeof("uint64_t")

-- global vars
local BLAKE3_VERSION
local shared_s_buf = new_str_buf(4096)
local last_big_s_buf = { [0] = 0, nil }
local shared_out_buf = ffi.new("uint8_t[?]", BLAKE3_OUT_LEN)
local G_SHARED_HASHER

local _M = {
    _NAME = "blake3",
    _VERSION = '0.0.1',
    _REVERSION = '2025082501',
}

local BLAKE3 = { }

local blake3_mt = {
    __index = BLAKE3
}

-- Allocate string buffer
---@param size number
---@return cdata, cdata, number
local function alloc_str_buf(size)
    -- we using ref but reserve for known size
    if size <= 4096 then
        return shared_s_buf:reset(), shared_s_buf:ref()
    elseif size <= last_big_s_buf[0] then
        return last_big_s_buf[1]:reset(), last_big_s_buf[1]:ref()
    end
    if size > MAX_OUT_OUT_LEN then
        error("hash output size must be less than 32KiB", 2)
    end
    local tmp_s_buf = new_str_buf(size)
    last_big_s_buf[0] = size
    last_big_s_buf[1] = tmp_s_buf
    return tmp_s_buf, tmp_s_buf:reserve(size)
end

local to_hex
do
    local hex_s_buf = new_str_buf(64 * 1024)
    if ngx then
        -- this is much faster than string.buffer.putf
        ffi.cdef [[
            void ngx_hex_dump(char *buf, const unsigned char *data, size_t len);
        ]]
        local C = ffi.C
        function to_hex(data, sz)
            if type(data) ~= "string" then
                return nil, "data must be a string"
            end
            if type(sz) ~= "number" then
                sz = #data
            elseif sz > #data then
                return nil, "sz is too big"
            end
            local ptr = hex_s_buf:reset():reserve(sz * 2)
            C.ngx_hex_dump(ptr, data, sz)
            local s = hex_s_buf:commit(sz * 2):tostring()
            return s
        end
    else
        local HEX_TPL_VEC = {
            "%02x",
            "%02x%02x",
            "%02x%02x%02x",
            "%02x%02x%02x%02x",
            "%02x%02x%02x%02x%02x",
            "%02x%02x%02x%02x%02x%02x",
            "%02x%02x%02x%02x%02x%02x%02x",
            "%02x%02x%02x%02x%02x%02x%02x%02x",
        }
        -- @TODO using bit.tohex is more efficient
        function to_hex(data, sz)
            if type(data) ~= "string" then
                return nil, "data must be a string"
            end
            if type(sz) ~= "number" then
                sz = #data
            elseif sz > #data then
                return nil, "sz is too big"
            end
            hex_s_buf:reset()
            local left = sz % 8
            for i = 1, sz - left, 8 do
                hex_s_buf:putf("%02x%02x%02x%02x%02x%02x%02x%02x", data:byte(i, i + 7))
            end
            if left > 0 then
                hex_s_buf:putf(HEX_TPL_VEC[left], data:byte(sz - left + 1, sz))
            end
            local s = hex_s_buf:tostring()
            return s
        end
    end
end

_M.to_hex = to_hex

-- The BLAKE3 library version
---@return string
local function lib_version()
    if not BLAKE3_VERSION then
        BLAKE3_VERSION = ffi_string(LIB_BLAKE3.blake3_version())
    end
    return BLAKE3_VERSION
end

BLAKE3.version = lib_version

-- Initialize hasher
---@param self table
---@return table|nil, string|nil
local function hasher_init(self)
    if self._hasher then
        -- @TODO omit this?
        return nil, "hasher already initialized";
    end
    local hasher = ffi_new(blake3_hasher_ct)
    LIB_BLAKE3.blake3_hasher_init(hasher)
    self._hasher = hasher
    return self
end

BLAKE3.init = hasher_init

-- Initialize hasher with a key
---@param self table
---@param key string
---@return table|nil, string|nil
local function hasher_init_keyed(self, key)
    if self._hasher then
        if self._key_kind ~= HASHER_KEYED or self._key ~= key then
            return nil, "hasher already initialized"
        end
        return self._hasher
    elseif type(key) ~= "string" or #key ~= 32 then
        return nil, "key must be 32 bytes, got " .. #key
    end
    local hasher = ffi_new(blake3_hasher_ct)
    LIB_BLAKE3.blake3_hasher_init_keyed(hasher, key)
    self._hasher = hasher
    self._key = key
    self._key_kind = HASHER_KEYED
    return self
end

BLAKE3.init_keyed = hasher_init_keyed

-- Init hasher with derive key
---@param self table
---@param context string|any
---@param context_len number|nil
---@return table|nil, string|nil
local function hasher_init_derive_key_raw(self, context, context_len)
    if self._hasher then
        if self._key_kind ~= HASHER_DERIVED_KEY or self._key ~= context then
            return nil, "hasher already initialized"
        end
        return self._hasher
    end
    if type(context) ~= "string" then
        context = tostring(context)
    end
    if type(context_len) ~= "number" then
        context_len = #context
    end
    if context_len < 1 then
        return nil, "context_len must be greater than 0"
    end
    local hasher = ffi_new(blake3_hasher_ct)
    LIB_BLAKE3.blake3_hasher_init_derive_key_raw(hasher, context, context_len)
    self._hasher = hasher
    self._key = context
    self._key_kind = HASHER_DERIVED_KEY
    return self
end

BLAKE3.init_derive_key = hasher_init_derive_key_raw
BLAKE3.init_derive_key_raw = hasher_init_derive_key_raw

-- Update the hasher with the given input
---@param self table
---@param input string|any
---@param input_len number|nil
---@return table
local function hasher_update_safe(self, input, input_len)
    if type(input) ~= "string" then
        input = tostring(input)
        -- override input_len for non-string input
        input_len = #input
    elseif type(input_len) ~= "number" then
        input_len = #input
    end
    if input_len > 0 then
        LIB_BLAKE3.blake3_hasher_update(self._hasher, input, input_len)
    end
    return self, input_len
end

BLAKE3.update = hasher_update_safe

-- Finalize with seek
---@param self table
---@param seek number
---@param out_len number|nil
---@return string
local function hasher_finalize_seek(self, seek, out_len)
    if type(seek) ~= "number" or seek < 0 then
        return nil, "seek must be a positive integer number"
    end
    local out_buf
    if type(out_len) ~= "number" then
        LIB_BLAKE3.blake3_hasher_finalize_seek(self._hasher, ffi_cast(uint64_ct, seek), shared_out_buf, BLAKE3_OUT_LEN)
        return ffi_string(shared_out_buf, BLAKE3_OUT_LEN)
    elseif out_len > 0 then
        local s_buf_obj
        s_buf_obj, out_buf = alloc_str_buf(out_len)
        LIB_BLAKE3.blake3_hasher_finalize_seek(self._hasher, ffi_cast(uint64_ct, seek), out_buf, out_len)
        return s_buf_obj:commit(out_len):tostring()
    end
    return nil, "out_len must be positive"
end

BLAKE3.finalize_seek = hasher_finalize_seek
BLAKE3.final_seek = hasher_finalize_seek

--- Finalize and return the hash digest
---@param self table
---@param out_len number|nil
---@return string
local function hasher_finalize(self, out_len)
    local out_buf
    if type(out_len) ~= "number" then
        LIB_BLAKE3.blake3_hasher_finalize(self._hasher, shared_out_buf, BLAKE3_OUT_LEN)
        return ffi_string(shared_out_buf, BLAKE3_OUT_LEN)
    elseif out_len > 0 then
        local s_buf_obj
        s_buf_obj, out_buf = alloc_str_buf(out_len)
        LIB_BLAKE3.blake3_hasher_finalize(self._hasher, out_buf, out_len)
        return s_buf_obj:commit(out_len):tostring()
    end
    return nil, "out_len must be positive"
end

BLAKE3.final = hasher_finalize
BLAKE3.finalize = hasher_finalize

--- void blake3_hasher_reset(blake3_hasher *self);
---@param self table
---@return table
local function hasher_reset(self)
    LIB_BLAKE3.blake3_hasher_reset(self._hasher)
    return self
end

BLAKE3.reset = hasher_reset

-- Calc digest
---@param self table
---@param out_len number|nil
---@param kind number|nil { 1: hex, 2: upper hex, nil/rest: raw digest }
---@return string
function BLAKE3.digest(self, out_len, kind)
    local s, err = hasher_finalize(self, out_len)
    if not s then
        return nil, err
    elseif kind == 1 then
        return to_hex(s)
    elseif kind == 2 then
        return to_hex(s):upper()
    end
    return s
end

-- Calc digest with seek
---@param self table
---@param seek number
---@param out_len number|nil
---@param kind number|nil { 1: hex, 2: upper hex, nil/rest: raw digest }
---@return string
function BLAKE3.digest_with_seek(self, seek, out_len, kind)
    local s, err = hasher_finalize_seek(self, seek, out_len)
    if not s then
        return nil, err
    elseif kind == 1 then
        return to_hex(s)
    elseif kind == 2 then
        return to_hex(s):upper()
    end
    return s
end

-- finalize with cdata
---@param self table
---@param seek number|nil
---@param out_len number|nil
---@return cdata, cdata, number
local function cdata_hasher_finalize(self, seek, out_len)
    if type(out_len) ~= "number" then
        out_len = BLAKE3_OUT_LEN
    end

    local s_buf_obj, out_buf = alloc_str_buf(out_len)
    if type(seek) == "number" then
        if seek < 0 then
            return nil, "seek must be a positive integer number"
        end
        LIB_BLAKE3.blake3_hasher_finalize_seek(self._hasher, ffi_cast(uint64_ct, seek), out_buf, out_len)
    else
        LIB_BLAKE3.blake3_hasher_finalize(self._hasher, out_buf, out_len)
    end
    s_buf_obj:commit(out_len)
    return s_buf_obj, out_buf, out_len
end

-- finalize callback with context
---@param self table
---@param fn function Prototype: fn(ptr, ptr_sz, fn_ctx)
---@param fn_ctx any|nil
---@param seek number|nil
---@param out_len number|nil
---@return any
function BLAKE3.finalize_callback_with_ctx(self, fn, fn_ctx, seek, out_len)
    if type(fn) ~= "function" then
        return nil, "fn must be a function"
    end
    local s_buf_obj, out_buf, wsz = cdata_hasher_finalize(self, seek, out_len)
    if not s_buf_obj then
        return nil, out_len
    end
    return fn(out_buf, wsz, fn_ctx)
end

-- finalize callback
---@param self table
---@param fn function Prototype: fn(ptr, ptr_sz, ...)
---@param seek number|nil
---@param out_len number|nil
---@param ... any
---@return any
function BLAKE3.finalize_callback(self, fn, seek, out_len, ...)
    if type(fn) ~= "function" then
        return nil, "fn must be a function"
    end
    local s_buf_obj, out_buf, wsz = cdata_hasher_finalize(self, seek, out_len)
    if not s_buf_obj then
        return nil, out_len
    end
    return fn(out_buf, wsz, ...)
end

-- Calc digest in hex format
---@param self table
---@param out_len number|nil
---@return string
function BLAKE3.hexdigest(self, out_len)
    return to_hex(hasher_finalize(self, out_len))
end

local pad_str
do
    local rep = string.rep
    local char = string.char

    function pad_str(str, sz, chr)
        if type(str) ~= "string" then
            error("str must be a string", 2)
        end
        if type(sz) ~= "number" then
            error("sz must be a number", 2)
        end
        if type(chr) == "number" and chr >= 0 and chr < 256 then
            chr = char(chr)
        else
            chr = "\0"
        end
        local pad_sz = sz - #str
        if pad_sz < 1 then
            return str
        end
        return str .. rep(chr, pad_sz)
    end
end

_M.pad_str = pad_str

---@param opts table|nil
---@return table
local function new(opts)
    local obj = {
        _hasher = nil,
        _key = nil,
        _key_kind = HASHER_NORMAL,
    }
    setmetatable(obj, blake3_mt)
    if type(opts) == "table" and opts.init == true then
        if type(opts.key) == "string" then
            assert(hasher_init_keyed(obj, opts.key))
        elseif type(opts.context) == "string" then
            assert(hasher_init_derive_key_raw(obj, opts.context))
        else
            hasher_init(obj)
        end
    end
    return obj
end

_M.new = new

-- Reset or Create global hasher
---@param hasher table|nil
---@return table
local function reset_default_hasher_if_needed(hasher)
    if not hasher then
        hasher = new()
        hasher_init(hasher)
        G_SHARED_HASHER = hasher
    end
    reset_default_hasher_if_needed = hasher_reset
    return hasher
end

--- static function
---@param str string|any
---@param out_len number|nil
---@return string
local function digest(str, out_len)
    local hasher = reset_default_hasher_if_needed(G_SHARED_HASHER)
    hasher_update_safe(hasher, str)
    return hasher_finalize(hasher, out_len)
end

-- calc hex digest
---@param str string|any
---@param out_len number|nil
---@return string
_M.hexdigest = function(str, out_len)
    return to_hex(digest(str, out_len))
end

-- calc raw digest
---@param str string|any
---@param out_len number|nil
---@return string
_M.digest = digest

-- Library version
_M.lib_version = lib_version

return _M
