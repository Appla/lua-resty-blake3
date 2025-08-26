# lua-resty-blake3 库文档

这是一个基于 FFI 的 BLAKE3 加密哈希算法库，为 LuaJIT 环境提供高性能的 BLAKE3 哈希计算功能。

## 项目依赖
- `LuaJIT` with `string.buffer` API
- `blake3` C 库（需预先安装）

## 主要特性

- 支持标准 BLAKE3 哈希计算
- 支持密钥哈希（keyed hashing）
- 支持密钥派生（key derivation）
- 高性能，基于 C 语言实现的 FFI 调用
- 支持任意长度输出
- 提供十六进制输出格式

## 核心 API

### 1. 创建哈希器实例

#### `blake3.new([opts])`

创建一个新的 BLAKE3 哈希器实例。

**参数：**
- `opts` (table, 可选): 初始化选项
    - `init` (boolean): 是否立即初始化
    - `key` (string): 32字节密钥，用于密钥哈希模式
    - `context` (string): 上下文字符串，用于密钥派生模式

**返回值：**
- BLAKE3 哈希器对象

### 2. 初始化方法

#### `hasher:init()`

初始化标准 BLAKE3 哈希器。

#### `hasher:init_keyed(key)`

使用密钥初始化 BLAKE3 哈希器。

**参数：**
- `key` (string): 32字节密钥

#### `hasher:init_derive_key(context)`

使用上下文字符串初始化密钥派生模式的哈希器。

**参数：**
- `context` (string): 上下文字符串

### 3. 数据处理方法

#### `hasher:update(input[, input_len])`

向哈希器中添加数据。

**参数：**
- `input` (string): 要哈希的数据
- `input_len` (number, 可选): 数据长度，默认为字符串长度

**返回值：**
- 哈希器对象本身（支持链式调用）

### 4. 结果输出方法

#### `hasher:finalize([out_len])`

完成哈希计算并返回结果。

**参数：**
- `out_len` (number, 可选): 输出长度，默认为32字节

**返回值：**
- 哈希结果（二进制字符串）

#### `hasher:digest([out_len[, kind]])`

完成哈希计算并根据指定格式返回结果。

**参数：**
- `out_len` (number, 可选): 输出长度，默认为32字节
- `kind` (number, 可选): 输出格式（1=小写十六进制，2=大写十六进制，其他=原始二进制）

#### `hasher:digest_with_seek(seek, [out_len[, kind]])`

完成哈希计算并根据指定格式返回结果，从指定位置开始输出（支持长输出）。

**参数：**
- `seek` (number): 起始位置
- `out_len` (number, 可选): 输出长度，默认为32字节
- `kind` (number, 可选): 输出格式（1=小写十六进制，2=大写十六进制，其他=原始二进制）


#### `hasher:hexdigest([out_len])`

完成哈希计算并返回十六进制格式结果。

**参数：**
- `out_len` (number, 可选): 输出长度，默认为32字节

#### `hasher:finalize_seek(seek, out_len)`

从指定位置开始输出哈希结果（支持长输出）。

**参数：**
- `seek` (number): 起始位置
- `out_len` (number): 输出长度

#### `hasher:finalize_callback(fn, seek, out_len, ...)`

从指定位置开始输出哈希结果（支持长输出），并通过回调函数处理输出。

**Parameters:**
- `fn` (function): 回调函数，协议：`function(cdata, len, ...)`
- `seek` (number): 起始位置
- `out_len` (number): 输出长度
- `...` (any): 回调函数的参数

#### `hasher:finalize_callback_with_ctx(fn, fn_ctx, seek, out_len)`

从指定位置开始输出哈希结果（支持长输出），并通过回调函数处理输出。

**Parameters:**
- `fn` (function): 回调函数，协议：`function(cdata, len, fn_ctx)`
- `fn_ctx` (any): 回调函数的参数
- `seek` (number): 起始位置
- `out_len` (number): 输出长度


### 5. 其他方法

#### `hasher:reset()`

重置哈希器状态，可以重新使用。

#### `hasher:version()`

获取 BLAKE3 库版本信息。

## 静态函数

### `blake3.digest(data[, out_len])`

直接计算数据的 BLAKE3 哈希值（二进制格式）。

### `blake3.hexdigest(data[, out_len])`

直接计算数据的 BLAKE3 哈希值（十六进制格式）。

### `blake3.to_hex(data[, sz])`

将二进制数据转换为十六进制字符串。

### `blake3.lib_version()`

获取底层 BLAKE3 库的版本信息。

## 使用示例

### 基本用法

```lua
local blake3 = require "resty.blake3"

-- 创建哈希器实例
local hasher = blake3.new()
hasher:init()

-- 添加数据
hasher:update("Hello, World!")

-- 获取结果
local digest = hasher:finalize()
print("Hash:", blake3.to_hex(digest))

-- 或者使用快捷方式
local digest_hex = blake3.hexdigest("Hello, World!")
print("Hash:", digest_hex)
```


### 使用静态函数

```lua
local blake3 = require "resty.blake3"

-- 直接计算哈希
local hash1 = blake3.digest("data to hash")
local hex_hash1 = blake3.to_hex(hash1)

-- 直接获取十六进制哈希
local hex_hash2 = blake3.hexdigest("data to hash")

-- 自定义输出长度
local long_hash = blake3.digest("data to hash", 64)  -- 64字节输出
```


### 密钥哈希模式

```lua
local blake3 = require "resty.blake3"

-- 创建32字节密钥
local key = string.rep("k", 32)  -- 32个字符'k'

-- 使用密钥初始化
local hasher = blake3.new()
hasher:init_keyed(key)
hasher:update("message to hash")
local keyed_hash = hasher:hexdigest()
```


### 密钥派生模式

```lua
local blake3 = require "resty.blake3"

-- 使用上下文进行密钥派生
local hasher = blake3.new()
hasher:init_derive_key("my context string")
hasher:update("data to hash")
local derived_hash = hasher:hexdigest()
```


### 长输出哈希

```lua
local blake3 = require "resty.blake3"

local hasher = blake3.new()
hasher:init()
hasher:update("data")

-- 生成100字节的哈希输出
local long_output = hasher:finalize(100)
print("Length:", #long_output)

-- 使用seek功能生成更长的输出
local long_output_part1 = hasher:finalize_seek(0, 1000)
local long_output_part2 = hasher:finalize_seek(1000, 2000)
local long_output_part3 = hasher:finalize_seek(2000, 3000)
print("Length:", #long_output_part1, #long_output_part2, #long_output_part3)
```

### 回调函数

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


### 链式调用

```lua
local blake3 = require "resty.blake3"

local result = blake3.new()
    :init()
    :update("Hello, ")
    :update("World!")
    :hexdigest()

print("Hash:", result)
```


### 重置和重复使用

```lua
local blake3 = require "resty.blake3"

local hasher = blake3.new()
hasher:init()

-- 第一次计算
hasher:update("first message")
local hash1 = hasher:hexdigest()

-- 重置并计算第二次
hasher:reset()
hasher:update("second message")
local hash2 = hasher:hexdigest()

-- 链式调用重置并计算
local hash3 = hasher:reset():update("second message"):hexdigest()
```


## 注意事项

1. 密钥长度必须为32字节
2. 输出长度不应超过`32KiB`限制(可使用finalize_seek方法获取更长输出)
3. 在OpenResty环境中使用时，确保已正确安装BLAKE3 C库
4. 使用`finalize`或`digest`系列函数后，哈希器状态会被重置，如需继续使用需要调用`reset`方法