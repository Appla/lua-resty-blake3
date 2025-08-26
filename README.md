# lua-resty-blake3 Library Documentation

This is an FFI-based BLAKE3 cryptographic hash library that provides high-performance BLAKE3 hash computation for LuaJIT environments.

## dependencies
- `LuaJIT` with `string.buffer` API
- `blake3` C library (pre-installed)

## Key Features

- Supports standard BLAKE3 hash computation
- Supports keyed hashing
- Supports key derivation
- High performance through FFI calls to C implementation
- Arbitrary length output support
- Hexadecimal output format provided

## Core API

### 1. Creating Hasher Instances

#### `blake3.new([opts])`

Creates a new BLAKE3 hasher instance.

**Parameters:**
- `opts` (table, optional): Initialization options
    - `init` (boolean): Whether to initialize immediately
    - `key` (string): 32-byte key for keyed hashing mode
    - `context` (string): Context string for key derivation mode

**Returns:**
- BLAKE3 hasher object

### 2. Initialization Methods

#### `hasher:init()`

Initializes a standard BLAKE3 hasher.

#### `hasher:init_keyed(key)`

Initializes a BLAKE3 hasher with a key.

**Parameters:**
- `key` (string): 32-byte key

#### `hasher:init_derive_key(context)`

Initializes a hasher in key derivation mode with a context string.

**Parameters:**
- `context` (string): Context string

### 3. Data Processing Methods

#### `hasher:update(input[, input_len])`

Adds data to the hasher.

**Parameters:**
- `input` (string): Data to hash
- `input_len` (number, optional): Length of data, defaults to string length

**Returns:**
- The hasher object itself (for chaining)

### 4. Result Output Methods

#### `hasher:finalize([out_len])`

Completes the hash computation and returns the result.

**Parameters:**
- `out_len` (number, optional): Output length, defaults to 32 bytes

**Returns:**
- Hash result (binary string)

#### `hasher:digest([out_len[, kind]])`

Completes the hash computation and returns the result in the specified format.

**Parameters:**
- `out_len` (number, optional): Output length, defaults to 32 bytes
- `kind` (number, optional): Output format (1=lowercase hex, 2=uppercase hex, others=raw binary)

#### `hasher:digest_with_seek(seek, [out_len[, kind]])`

Completes the hash computation and returns the result in the specified format starting from the specified position.

**Parameters:**
- `seek` (number): Starting position
- `out_len` (number, optional): Output length, defaults to 32 bytes
- `kind` (number, optional): Output format (1=lowercase hex, 2=uppercase hex, others=raw binary)

#### `hasher:hexdigest([out_len])`

Completes the hash computation and returns the result in hexadecimal format.

**Parameters:**
- `out_len` (number, optional): Output length, defaults to 32 bytes

#### `hasher:finalize_seek(seek, out_len)`

Outputs hash result starting from a specified position (supports long output).

**Parameters:**
- `seek` (number): Starting position
- `out_len` (number): Output length

#### `hasher:finalize_callback(fn, seek, out_len, ...)`

Outputs hash result starting from a specified position (supports long output) with a callback function and variable arguments.

**Parameters:**
- `fn` (function): Callback function to handle output, protocol: `function(cdata, len, ...)`
- `seek` (number): Starting position
- `out_len` (number): Output length
- `...` (any): Variable arguments to pass to the callback function

#### `hasher:finalize_callback_with_ctx(fn, fn_ctx, seek, out_len)`

Outputs hash result starting from a specified position (supports long output) with a callback function.

**Parameters:**
- `fn` (function): Callback function to handle output, protocol: `function(cdata, len, fn_ctx)`
- `fn_ctx` (any): Callback function context
- `seek` (number): Starting position
- `out_len` (number): Output length

### 5. Other Methods

#### `hasher:reset()`

Resets the hasher state for reuse.

#### `hasher:version()`

Gets the BLAKE3 library version information.

## Static Functions

### `blake3.digest(data[, out_len])`

Directly computes the BLAKE3 hash of data (binary format).

### `blake3.hexdigest(data[, out_len])`

Directly computes the BLAKE3 hash of data (hexadecimal format).

### `blake3.to_hex(data[, sz])`

Converts binary data to hexadecimal string.

### `blake3.lib_version()`

Gets the version information of the underlying BLAKE3 library.

## Usage Examples

### Basic Usage

```lua
local blake3 = require "resty.blake3"

-- Create hasher instance
local hasher = blake3.new()
hasher:init()

-- Add data
hasher:update("Hello, World!")

-- Get result
local digest = hasher:finalize()
print("Hash:", blake3.to_hex(digest))

-- Or using shortcut
local digest_hex = blake3.hexdigest("Hello, World!")
print("Hash:", digest_hex)
```


### Using Static Functions

```lua
local blake3 = require "resty.blake3"

-- Direct hash computation
local hash1 = blake3.digest("data to hash")
local hex_hash1 = blake3.to_hex(hash1)

-- Direct hexadecimal hash
local hex_hash2 = blake3.hexdigest("data to hash")

-- Custom output length
local long_hash = blake3.digest("data to hash", 64)  -- 64-byte output
```


### Keyed Hashing Mode

```lua
local blake3 = require "resty.blake3"

-- Create 32-byte key
local key = string.rep("k", 32)  -- 32 'k' characters

-- Initialize with key
local hasher = blake3.new()
hasher:init_keyed(key)
hasher:update("message to hash")
local keyed_hash = hasher:hexdigest()
```


### Key Derivation Mode

```lua
local blake3 = require "resty.blake3"

-- Key derivation with context
local hasher = blake3.new()
hasher:init_derive_key("my context string")
hasher:update("data to hash")
local derived_hash = hasher:hexdigest()
```


### Long Output Hash

```lua
local blake3 = require "resty.blake3"

local hasher = blake3.new()
hasher:init()
hasher:update("data")

-- Generate 100-byte hash output
local long_output = hasher:finalize(100)
print("Length:", #long_output)

-- Using seek functionality for even longer output
local long_output_part1 = hasher:finalize_seek(0, 1000)
local long_output_part2 = hasher:finalize_seek(1000, 2000)
local long_output_part3 = hasher:finalize_seek(2000, 3000)
print("Length:", #long_output_part1, #long_output_part2, #long_output_part3)
```


### Callback Function for Output

```lua
local blake3 = require "resty.blake3"

local hasher = blake3.new()
hasher:init()
hasher:update("data")

local ctx = {
    cmp_str = "some binary string",
}

local function cmp_with_my_hash(raw, sz, fn_ctx)
    return #fn_ctx.cmp_str >= sz and string.find(fn_ctx.cmp_str, raw, 1, true) == 1
end

local res = hasher:finalize_callback_with_ctx(cmp_with_my_hash, ctx)


local function cmp_with_my_hash_v1(raw, sz, cmp_str)
    return #cmp_str >= sz and string.find(cmp_str, raw, 1, true) == 1
end

local res2 = hasher:finalize_callback(cmp_with_my_hash_v1, nil, nil, ctx.cmp_str)
```


### Chaining Calls

```lua
local blake3 = require "resty.blake3"

local result = blake3.new()
    :init()
    :update("Hello, ")
    :update("World!")
    :hexdigest()

print("Hash:", result)
```


### Reset and Reuse

```lua
local blake3 = require "resty.blake3"

local hasher = blake3.new()
hasher:init()

-- First computation
hasher:update("first message")
local hash1 = hasher:hexdigest()

-- Reset and compute second time
hasher:reset()
hasher:update("second message")
local hash2 = hasher:hexdigest()

-- Alternatively, you can reset and update in one step
local hash3 = hasher:reset():update("second message"):hexdigest()
```


## Notes

1. Key length must be exactly 32 bytes
2. Output length should not exceed the `32KiB` limit(using finalize_seek for large outputs)
3. When using in OpenResty environment, ensure the BLAKE3 C library is properly installed
4. After using `finalize` or `digest` functions, the hasher state is reset; call `reset` method to continue using