# ExtractIPEKformattedTR31

RSA暗号化されたTMK（Terminal Master Key）を復号化し、TR-31キーブロックからIPEK（Initial PIN Encryption Key）を抽出するツールです。

## 概要

このツールは、以下を実行します。

1. TMKをRSA秘密鍵で復号化（Base64/HEX入力対応）
2. 復号TMKからKBPKを取り出し、TR-31キーブロックをバージョン別ロジックで復号化
3. 抽出したIPEKを16進数で出力
4. TR-31のMAC検証を実行して結果を出力（Version A/B/D）

## ディレクトリ構造

```text
extract-ipek-formatted-tr31/
├── README.md
├── ExtractIPEKformattedTR31.php
├── key/
│   ├── private_key.pem
│   ├── private_key_apc.pem
│   ├── private_key_rsa4096.pem
│   ├── public_key.pem
│   └── public_key_apc.pem
└── src/
    ├── RKIEncryptedParametersValidator.php
    ├── TR31KeyBlock.php
    └── TR31/
        ├── TR31VersionA.php
        ├── TR31VersionB.php
        ├── TR31VersionC.php
        └── TR31VersionD.php
```

## 処理概要（バージョン別）

### 1. TMK復号化（共通）

1. RSA秘密鍵を読み込み
2. `format` に応じて暗号化TMKをデコード（`base64` または `hex`）
3. OAEPで復号（SHA-256を優先、失敗時にSHA-1へフォールバック）
4. 16進文字列へ変換
5. 復号TMKはそのまま16進文字列として扱う（補完は行わない）

復号TMKの扱い:

- 先頭に `00008000`（default string-to-key parameters）があれば除去
- なければそのままKBPKとして扱う

### 2. IPEK取得（TR-31 Version A/B/D）

共通処理:

1. TR-31先頭1文字でバージョン判定（A/B/D）
2. ヘッダー・暗号文・MACを分離
3. バージョン別に KBEK/KBMK, IV, 復号アルゴリズム, MAC検証方式を適用
4. 平文先頭2バイト（bit長）からIPEKを切り出し

Version A:

- KBEK/KBMK: KBPK XORバリアント（`0x45` / `0x4D`）
- 復号: `DES-EDE3-CBC`
- IV: header先頭8バイト
- MAC: `header + encryptedKey` から算出（4バイト）

Version B:

- KBEK/KBMK: TDES-CMACベース導出
- 復号: `DES-EDE3-CBC`
- IV: MAC先頭8バイト
- MAC: `header + plainKeyBlock` を TDES-CMAC（8バイト）

Version D:

- KBEK/KBMK: AES-CMACサブキー（K1/K2）を利用したAES導出
- 復号: `AES-CBC`（KBPK長に応じて `aes-128/192/256-cbc`）
- IV: MAC先頭16バイト
- MAC: `header + plainKeyBlock` を AES-CMAC（16バイト）

## 使用方法

### コマンド形式

```bash
php ExtractIPEKformattedTR31.php <rsaPrivateKeyPemPath> <passphrase> <encryptedTMK> <tr31String> [format]
```

### パラメータ

| パラメータ | 説明 | 例 |
|---|---|---|
| `rsaPrivateKeyPemPath` | RSA秘密鍵のPEMファイルパス | `./key/private_key.pem` |
| `passphrase` | 秘密鍵のパスフレーズ | `password` |
| `encryptedTMK` | RSA公開鍵で暗号化されたTMK（Base64またはHEX） | `LlgTff+W6B0f...` / `2e58137d...` |
| `tr31String` | TR-31キーブロック（`R`始まり可） | `RA0072...` |
| `format` | TMKの入力形式（省略時 `base64`） | `base64` / `hex` |

## コマンド例

### 例1: Version A（Base64 TMK）

```bash
php ExtractIPEKformattedTR31.php "./key/private_key.pem" password "LlgTff+W6B0f23pJr7ATABVM/anuv5bFfBFys1EFEhbtA0cserRHlrqmgeEnXmayPLgJ24TLyzMi1wituHx6Tl6in3HG8HJp64ZVaOe1pbKh44BnxtuD06qFGPSAGNE084DAPjQ2GnJMX0HUS2jwhs7YH44WZDOlcyUAywfCrEv6uKg5LKAuPTDTVgeKydVP+dD7Zq//lg/mUtjcvO+QgxfVBgS/Efs85kO56pbfvabXrlFxVF4rrt/8S6lLOzAU8cPpnlqBZ00ksA40+QCpoVWSFpFq9HjSqQgIYBgit+lEIhWAYsy+JIuDTitU/rhTVHOcFZu2ZMRXeLt1tWTdGQ==" RA0072B1TN00S00006D2F59B60F3BCCAC8A869370685F00EBF3AD3865414CFAAC77412898
```

### 例2: Version B（Base64 TMK）

```bash
php ExtractIPEKformattedTR31.php "./key/private_key.pem" password "Y3a/YaG1IXfoKqFmQrf9XVOxDAYNygEEEmzShKCmMrgPjF7TC8f6z1d9ohTtXOF3xYRYPNxRGun2J9t9bbqedzO2xSu6JyaBjHE1kHXSByoRkj5bLAW6JXy+nj+xRUEVCL+efeNanGk0GfmZMNj/8lAZ+F8ITw5CL1GhRN+q+BfujdFROtM1UlWoqlXsKYTe+k8t/v4goRkLsXGdRC/x+kZgNZzR/UNWmrH9Fe61nuVkMSI6fk0JoMQd9yD4LQa+VoiPtC+P5hFfWn+SRWM6mVqF5xwX2XuHplUXXlBZrsj67ivWm18OcueDnpy5CsYj7PnVlO4ysZKZ8uv5mW6xJg==" RB0080B1TN00N00005D94BB551567F53FD0937E7183971B9353DDFB880708383DE53735D2A1D246EA
```

### 例3: Version B（APC生成 / HEX TMK）

```bash
php ExtractIPEKformattedTR31.php "./key/private_key_apc.pem" password "0b63226064b65428d960b178a1e8aeb435d055aaf8681149dc78518de522284726dec2916185f06e3e608780ed1d8d8fba266dd6e1245ec173d988071818bda894a21c90971d81b882e41b95b3e167de78784be2ae11fede9ebf1940a3f56f3af652d3b8536bfbcfce90d05ac95769cfe17cd7a5dbfdc6b2e102ed5a36b57c89b6a4e6ae52ec136d9c710078a4c61d8f3baa09be96e72d0c5fac57e53fc03ff6d14fd435aa49021e51b5df40dbbaee70fc80e563d1101d010c8936620a8936717b8315d5a227d81a3a2f5d42c74e5a1348b746664282f5773fee621e43f9b9b47fc515904bb305aa94ffea80b01f148cc89e1328e46c352b00cb2d9d90bb607a" B0096B1TX00S0000FAADEE5B7F5BDEA7788A9A15F76FB3B42AB8E59F7DF8E4C2327ECE108C5D0068B0B3A3EDFA4AA909 hex
```

### 例4: Version D（APC生成AES鍵 / HEX TMK）

```bash
php ExtractIPEKformattedTR31.php "./key/private_key_rsa4096.pem" password "937E1CDCED2812FB5B23C42B018FA016B377C5113F3A57B158B2E63A1E686947FCE9A8182C7D50989D92F0CB2B622380AC7C9F418421ECA88C5CB87A875C7072D6AF86F978816C6BE90D23444587F658215B19829F29B578A1450B792747F527D676E3F0B2ACC83CE2EFDD50F56DAD22D1115FE1DC7DD6B6BAAD6375D7FA9A449F8086D5AF23848E4A9572B99653173B5A019C9820CF0F15BD403EA069AB81BB432E21FAA845EC314213405B4CEDA0F945485CAE290D5174643145380D208CE0D6AB73947D853209F6687BF08C733219B085F07BF42048A6FAAA8C498079E47EC9C2AB2F61CC32F1D9B5D16C3D1198A234A1713C3A29AFBF576B204C6970C1DBB9503983A65F293C7DAC6FD4A6BD254500DA6CE1BA707E81A25A2AC620878E8D6A4CBFB62CAF6C1D0338107225F419B5455DA3E74248831A63FF5AC24CFE584561783F550C21E76BB5249CF00F882AC77EC9185645D9DE3C48AA20D87641E3367D564A8ED71106CEAD72C171B413138FEB5558C7835AAE2EC9E9D747C36CEED6D9FDF0603625E3F712B81CA094C2C0E6A6B0665AAB2CA18C75ABAA2783BD1309987AB30D35B9671A65B90E0EA07E06CED21E66216B6F67477BFBDFD1F5497046D48311FF5AC663868675010611ACD846ACA371E0C3E97BE37943C88172FBA4E17BE83887A928547B238DAFA22E59CAD86AA76592AFC0358C931D019257DD0262" D0112B1AX00S0000604B45F35C79CCD900A2D60554575D1F097CED98FB9168765A54EE5427D411EF2176D9E810244FCA015D2AB6810D81FA hex
```

### 例5: Version B（オプショナルブロックあり / Base64 TMK）

```bash
php ExtractIPEKformattedTR31.php "./key/private_key_apc.pem" password "YTzcm0SUI5GayQGutH3J5saae4AFKw2d+avXGEDYWoay2wMt9us6LABTrdQB7WTz9cu0N2Xa5ORNAYr1oxFUovhWZfyIZ/3JzGtaKF3kJB2H1xpBhl+ZioP0OBOor3wazBmLFBrHf87Y0Tl9Yk5NZvNFyspRgohDH8stzxO/+gTCLcdAMGfWXT0xm19amxlPeq/+u4gnLEddYt1kjX24bb3ODZKs0z5yZnvC4gKhPxc8IdkKCIH2UnYwzrGcCORHqvULaAjLMWpaEINIrtlJfkuMVd+NngRLQKCo0jnEtyhp4vch7JbLyo4ZBGyPsmd9skOfiKH7XuAKFL0KVPe5/A==" RB0112B1TN00S0200KP0A29903EPB0600EA4F2D7B5D90FA83DADF6047591555BD6C047FD475C66EBF8413BA9D5D9DA8777DAD67A1E0EDB2F4
```

### 例6: Version D（オプショナルブロックあり / Base64 TMK）

```bash
php ExtractIPEKformattedTR31.php "./key/private_key_apc.pem" password "uxmtURDMGNbuifcUF3+SxJ0Wkt4lCewpnAqcD59WR46/ta86mG4liQaCwe5RIPuVE0pI1/xZeRK2PRtUK8eyTaRkItDg/+hmOqo32HRFUSkzEZkzd7+ywpDh6jJ2wVlWvnb5+7Y65HvjvVe5K6cArTg8XIOSCfSYnSltarOHKTXwSYfUX8jPmji2+Szvx248P8Kgts9AT332Q3L82SxTL3lnPZLLGbhLc1RoLQA3/4IMGPenE4zuYLXdNWN0zXA4q1vcTItBpuqO7QO6/XO4oCrAhs1jyfpNWsTFTLYx13pf9IQMQI9zhcsocXG93PQDpv5R1N3EJghzozof1CQp9g==" RD0128B1AN00S0200KP0A29903EPB0600D301BC679ADC19D042676F0EA0054FF8D36C1F437A84124F286E646AB3E7036D670B1B0A03146A00DCDFB4DF6590B752
```

## 想定結果

### Version A の正常終了例

```text
=== RESULT ===
Decrypted TMK: 0000800062c776ba57576dfdd60146ea1fdaae6e (leading 00008000 indicates default string-to-key parameters)
TMK Decryption OAEP Hash: SHA-1
Valid IPEK: 8b931e0e0b1e5dcfdc2d31e0f9ed0281
MAC Verification: PASSED (Version A)

```

### Version B の正常終了例

```text
=== RESULT ===
Decrypted TMK: 0000800062c776ba57576dfdd60146ea1fdaae6e (leading 00008000 indicates default string-to-key parameters)
TMK Decryption OAEP Hash: SHA-1
Valid IPEK: 10c2c3211b4706bdee719dd50701d016
MAC Verification: PASSED (Version B)
```

### Version D の正常終了例

```text
=== RESULT ===
Decrypted TMK: 9f1fa1f6ce455bfc03caca8ccb96c06f
TMK Decryption OAEP Hash: SHA-256
Valid IPEK: 4299b3bfa94d0cf55734735574797704
MAC Verification: PASSED (Version D)
```

### Version B（オプショナルブロックあり）の正常終了例

```text
=== RESULT ===
Decrypted TMK: 00008000832c7f1a83c425b39b317098a49d2a79 (leading 00008000 indicates default string-to-key parameters)
TMK Decryption OAEP Hash: SHA-1
Valid IPEK: 18656231ef0aaec2801a82991e0f2490
MAC Verification: PASSED (Version B)
```

### Version D（オプショナルブロックあり）の正常終了例

```text
=== RESULT ===
Decrypted TMK: 000080009f1fa1f6ce455bfc03caca8ccb96c06f (leading 00008000 indicates default string-to-key parameters)
TMK Decryption OAEP Hash: SHA-1
Valid IPEK: 5ed1af8baacd2d384dc48f06c834fd03
MAC Verification: PASSED (Version D)
```

### 出力項目

- `Decrypted TMK`: 復号TMK（16進）。先頭が `00008000` の場合は除去後をKBPKとして使用
- `Valid IPEK`: 抽出されたIPEK（16進）
- `MAC Verification`: MAC検証結果（A/B/Dすべてで実行）

### エラー時の出力例

```text
Failed to read the private key PEM file.
```

```text
TMK decryption failed.
```

```text
=== RESULT ===
Decrypted TMK: ...
IPEK extraction failed.
```

## 技術仕様

### サポート状況

- 対応バージョン: `A`, `B`, `D`
- `C` はクラスは存在しますが未実装です

### バージョン別仕様（実装準拠）

| Version | KBPK長 | 復号アルゴリズム | MAC長 | 復号IV | KBEK/KBMK導出 | MAC検証 |
|---|---:|---|---:|---|---|---|
| A | 16byte入力を3DESキー化（24byte） | 3DES-CBC | 4 | Header先頭8byte | XORバリアント（0x45/0x4D） | `header + encryptedKey` |
| B | 16byte入力を3DESキー化（24byte） | 3DES-CBC | 8 | MAC先頭8byte | TDES-CMACベース導出 | `header + plainKeyBlock` |
| D | 16/24/32byte（AES-128/192/256） | AES-CBC | 16 | MAC先頭16byte | AESベース導出（K1/K2使用） | `header + plainKeyBlock`（AES-CMAC） |

### TMK復号仕様

- 入力形式: Base64 / HEX
- パディング: OAEP
- 優先ハッシュ: SHA-256（失敗時 SHA-1）
- 出力形式: 16進文字列

## 注意事項

1. 秘密鍵ファイルとパスフレーズは厳重に管理してください。
2. TR-31文字列の先頭 `R` は入力時に付いていても処理可能です。
3. 復号TMK先頭の `00008000` は任意です。あれば除去し、なければそのままKBPKとして処理します。
4. IPEK抽出とMAC検証は分離されており、出力にはMAC検証結果を併記します。
