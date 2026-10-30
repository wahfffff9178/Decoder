# decoder v2.0.0

一个轻量、单文件、跨平台的 C++ 命令行加密工具。加密后生成 `.dec` 文件，文件头部携带可读元信息（备注、源 IP、原始文件名、创建时间等），正文用 ChaCha20 流式加密，并附带防篡改认证。

## 特性

- **交互式向导**：提供 `-W` 模式，全程引导用户输入路径、密码、备注等，无需记忆复杂参数。
- **单文件输出**：一个原文件对应一个 `.dec`，支持目录递归加密。
- **流式处理**：加解密均采用 64 KB 分块流式处理，内存占用恒定，可处理超大文件。
- **完整性认证**：基于 HMAC-SHA256（Encrypt-then-MAC），任何对密文或头部的篡改、截断都会在解密时被拦截并报错。
- **加密头**：头部用 ChaCha20 加密，密码为空时不加密头部（但保留完整性标记）。
- **可读元数据**：`-R` 无需解密正文即可查看备注、源 IP、原始文件名、加密时间等。
- **真实公网 IP**：加密时自动通过系统 `curl` 获取真实的公网 IP 记录在头部（若无网络将自动降级为局域网 IP，且不会卡住流程）。
- **快速改头**：`-M` 只重写加密头，正文密文原样保留，同时自动重新计算全文件的 MAC 签名，大文件也是秒级完成。
- **无第三方依赖**：内置 SHA-256、ChaCha20、HMAC-SHA256、Base64、JSON 解析器，不依赖 OpenSSL 或任何外部库。
- **跨平台**：Linux / macOS / Windows 均可编译，只需 C++17 编译器。

## 安全设计

| 环节 | 算法 / 做法 |
|------|------------|
| 密钥派生 | SHA-256 迭代 100 000 次（`password + salt + counter`） |
| 头部加密 | ChaCha20，20 轮，独立 nonce |
| 正文加密 | ChaCha20，20 轮，密钥由头部密钥二次派生，独立 nonce |
| 文件认证 | HMAC-SHA256 (Encrypt-then-MAC)，覆盖文件头、头部密文与正文密文 |
| 密码校验 | 头部内嵌 `check` 字段（派生密钥的 SHA-256 前缀），用于区分"密码错误"和"文件损坏" |
| 盐 / nonce | 每次加密随机生成（盐 16 字节，nonce 12 字节） |

> ⚠️ **注意**：v2 版本加入了文件完整性（MAC）校验，如果文件在下载或传输过程中损坏、截断，解密时会直接报错，拒绝输出损坏的数据。`-M` 修改头部时，不仅会重新加密头部，还会自动重算全文件 MAC，确保修改后的文件依然合法。本工具定位为个人文件保护，不用于云存储防伪造等场景。

## 文件格式

`.dec` 文件结构（小端序，当前版本 `v2`）：

 
┌──────────────────────────────────────────┐
│ 魔数 "DECF"              (4 字节)         │
│ 格式版本 (v2)            (2 字节)         │
│ 标志位                   (1 字节)         │
│    bit0: 头部已加密                       │
│    bit1: 需要密码                         │
│ 保留                     (1 字节)         │
│ 头部长度                 (4 字节)         │
│ 保留                     (4 字节)         │
├──────────────────────────────────────────┤
│ 盐 (16 字节)                              │
│ 头部 nonce (12 字节)                      │
│ 迭代次数 (4 字节)                         │
│ 加密后的头部 JSON (变长)                  │
├──────────────────────────────────────────┤
│ 加密后的正文密文 (变长)                   │
├──────────────────────────────────────────┤
│ HMAC-SHA256 完整性签名   (32 字节)        │
└──────────────────────────────────────────┘
 

头部 JSON 包含：`format`、`remarks`、`source_ip`、`original_name`、`original_size`、`original_mtime`、`encrypted_at`、`modified_at`、`cipher`、`kdf`、`body_nonce`、`check`。

## 编译

### 依赖
- C++17 编译器（GCC ≥ 9 / Clang ≥ 7 / MSVC ≥ 2019）
- CMake ≥ 3.16（可选）

### 使用 CMake（推荐）
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j
 
产物位于 `build/decoder`（Windows 为 `build/decoder.exe`）。

### 直接编译
g++ -std=c++17 -O2 -Wall -Wextra \
    src/main.cpp src/crypto.cpp src/json.cpp src/decfile.cpp src/util.cpp \
    -o decoder
 
Windows (MinGW) 需额外链接 Winsock：
g++ -std=c++17 -O2 -Wall -Wextra src/*.cpp -o decoder.exe -lws2_32
 
### 安装到 PATH
sudo cp build/decoder /usr/local/bin/
 
## 用法
decoder <操作> [...]
 
| 操作 | 长选项 | 说明 |
|------|--------|------|
| `-W` | `--wizard`      | **交互式加密向导** |
| `-E` | `--encryption`  | 加密文件或目录 |
| `-U` | `--decryption`  | 解密 `.dec` 文件 |
| `-R` | `--readinghead` | 只读取并显示加密头 |
| `-M` | `--modifyhead`  | 修改加密头（不改正文） |
| `-h` | `--help`        | 帮助 |
| `-V` | `--version`     | 版本号 |

每个操作都有自己的子帮助，例如 `decoder -E -h`。

### 加密向导 `-W` (推荐新手使用)
decoder -W
 
运行后会进入一问一答模式，避免记错参数：
1. 输入要加密的路径（支持从文件管理器直接拖拽，程序会自动去除路径两端的双引号）。
2. 询问是否设置密码（选 y 则需连续输入两次，防手误）。
3. 输入文件备注（可直接回车留空）。
4. 询问当目标文件已存在时是否强制覆盖。
5. 显示汇总信息，确认无误后开始加密。

### 加密 `-E`

decoder -E <路径> <密码> <备注> [-f]
 
- `<路径>` 可以是文件或目录，目录会**递归**处理。
- 已存在的 `.dec` 文件默认跳过，避免重复加密。
- `<密码>` 传 `""` 表示不设密码（解密时也无需密码）。
- `-f, --force` 覆盖已存在的 `.dec` 文件。

# 加密单文件
decoder -E ./report.docx "mypass" "季度报告"

# 无密码加密整个目录
decoder -E ./photos "" "家庭相册"

# 强制覆盖
decoder -E ./a.txt "pw" "示例" -f
 
### 解密 `-U`

decoder -U <dec文件路径> [密码] [-o <输出>] [-f]
 
- 默认按头部记录的 `original_name` 还原到 `.dec` 文件所在目录。
- `-o, --output` 可指定目标文件或目标目录。
- `-f, --force` 覆盖已存在的目标文件。
- 如果 MAC 校验失败（文件被篡改或损坏），将拒绝解密。

# 解密到原目录
decoder -U ./report.docx.dec "mypass"

# 解密到指定目录
decoder -U ./report.docx.dec "mypass" -o ./restored/

# 指定输出文件并覆盖
decoder -U ./report.docx.dec "mypass" -o ./x.docx -f
 
成功时输出：
 
---------------Decryption complete---------------

Decryption file: ./report.docx.dec decrypted to target file ./report.docx
Encryption Header   : "季度报告"
Encryption Source IP: "112.65.12.34"

------------------------------------------------------
 
### 读头 `-R`

decoder -R <dec文件路径> [密码] [--json]
 
- 默认输出易读摘要。
- `--json` 输出完整 JSON，便于脚本处理。
- 只解密头部，不触碰正文，速度快。

decoder -R ./report.docx.dec "mypass"
decoder -R ./report.docx.dec "mypass" --json
 
### 改头 `-M`

decoder -M <dec文件路径> [密码] [--remarks <文本>] [-i <IP>] [-e]
 
| 选项 | 说明 |
|------|------|
| `--remarks <文本>` | 直接设置备注 |
| `-i, --ip <地址>`  | 直接设置源 IP |
| `-e, --edit`       | 用 `$VISUAL` / `$EDITOR`（默认 `vi`）打开完整头部 JSON 编辑 |
| 无选项             | 进入交互式修改备注 |

修改仅重写头部，正文密文原样保留，同时系统会自动扫描正文并重新计算全文件 MAC 签名，速度极快。

decoder -M ./report.docx.dec "mypass" --remarks "已归档"
decoder -M ./report.docx.dec "mypass" -i 10.0.0.1
decoder -M ./report.docx.dec "mypass" -e
decoder -M ./report.docx.dec "mypass"       # 交互式
 
> `format`、`original_name`、`original_size`、`body_nonce` 为保护字段，即使在编辑器里改了也会被强制还原，防止正文无法解密。

## 错误提示

| 提示 | 含义 |
|------|------|
| `这不是一个DEC加密文件` | 文件头魔数不是 `DECF` |
| `dec版本大于当前decoder版本：此版本不支持这个Dec文件` | 文件格式版本比当前程序高 |
| `此文件需要密码` | 文件头标记了需要密码，但未提供 |
| `密码错误` | 密码不对（通过头部 `check` 字段校验） |
| `文件已被篡改或损坏 (MAC 校验失败)` | 文件在传输中被截断、修改，或伪造的密文 |
| `目标文件已存在` | 加 `-f` 覆盖 |
| `没有指定操作 (使用 -h 获取帮助)` | 未传入任何操作 |
| `错误: 路径不存在: ...	` |输入的文件或文件夹路径找不到 |
| `拒绝访问 / Permission denied	`  |权限不足（例如无权限写入目标目录，或读取受限文件） |

## 项目结构

 
decoder/
├── CMakeLists.txt
├── README.md
└── src/
    ├── main.cpp        入口与子命令
    ├── crypto.h/.cpp   SHA-256、ChaCha20、HMAC-SHA256、Base64、KDF
    ├── json.h/.cpp     极简 JSON 序列化/解析
    ├── decfile.h/.cpp  .dec 文件格式读写、加解密与完整性校验
    └── util.h/.cpp     时间格式化、公网/局域网 IP 探测
 
## 快速自测

# 使用交互向导加密
./build/decoder -W

# 命令行快捷加密
echo "hello decoder" > t.txt
./build/decoder -E t.txt "pw" "测试"           # 生成 t.txt.dec
./build/decoder -R t.txt.dec "pw"              # 查看头部
./build/decoder -M t.txt.dec "pw" --remarks "改过的备注"
./build/decoder -U t.txt.dec "pw" -f           # 还原 t.txt

## 许可证

GNU GPL V3
