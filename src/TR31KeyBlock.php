<?php

namespace ExtractIpekFormattedTR31;

use Exception;
use ExtractIpekFormattedTR31\TR31\TR31VersionA;
use ExtractIpekFormattedTR31\TR31\TR31VersionB;
use ExtractIpekFormattedTR31\TR31\TR31VersionC;
use ExtractIpekFormattedTR31\TR31\TR31VersionD;
use InvalidArgumentException;

abstract class TR31KeyBlock
{
    private const HEADER_LEN = 16;
    private const TRANSFORMATION = 'DES-EDE3-CBC';

    protected string $header;
    protected string $encryptedKey;
    protected string $mac;
    protected ?string $plainKey = null;
    protected ?string $plainKeyBlock = null;

    protected string $KBPK;
    protected string $KBEK;
    protected string $KBMK;

    /**
     * キーブロック先頭のバージョン文字から適切な実装クラスを生成する。
     *
     * @param string $keyBlock TR-31鍵ブロック文字列（先頭1文字がバージョン）。
     *
     * @return self|null 対応するバージョン実装。未対応・不正形式の場合はnull。
     */
    public static function createFromKeyBlock(string $keyBlock): ?self
    {
        if ($keyBlock === '' || !preg_match('/^[ABCD]/', $keyBlock)) {
            return null;
        }

        require_once __DIR__ . '/TR31/TR31VersionA.php';
        require_once __DIR__ . '/TR31/TR31VersionB.php';
        require_once __DIR__ . '/TR31/TR31VersionC.php';
        require_once __DIR__ . '/TR31/TR31VersionD.php';

        return match ($keyBlock[0]) {
            'A' => new TR31VersionA(),
            'B' => new TR31VersionB(),
            'C' => new TR31VersionC(),
            'D' => new TR31VersionD(),
            default => null,
        };
    }

    /**
     * この実装クラスが扱うTR-31バージョン文字を返す。
     *
     * @return string バージョン文字（例: A/B/C/D）。
     */
    abstract public function getVersion(): string;

    /**
     * 当該バージョンで使用するMAC長（バイト数）を返す。
     *
     * @return int MAC長（バイト）。
     */
    abstract protected function getMacLen(): int;

    /**
     * 当該バージョン実装が利用可能かどうかを返す。
     *
     * @return bool true: 実装済み / false: 未実装。
     */
    abstract protected function isImplemented(): bool;

    /**
     * 当該バージョンでMAC検証を行うかどうかを返す。
     *
     * @return bool true: 検証する / false: 検証しない。
     */
    abstract protected function supportsMacVerification(): bool;

    /**
     * バージョン仕様に従ってKBEK/KBMKを導出する。
     *
     * @param string $kbpk 3DES長に整形済みのKBPKバイナリ。
     *
     * @return array{string,string} [KBEK, KBMK]
     */
    abstract protected function deriveKeysByVersion(string $kbpk): array;

    /**
     * バージョン仕様に従って復号時IVを算出する。
     *
     * @param string $header TR-31ヘッダ（バイナリ）。
     * @param string $mac 鍵ブロック末尾のMAC（バイナリ）。
     *
     * @return string 復号に使用するIV（8バイト）。
     */
    abstract protected function getDecryptIvByVersion(string $header, string $mac): string;

    /**
     * バージョン仕様に従ってMACを計算する。
     *
     * @return string|null 計算したMAC。計算不可時はnull。
     */
    abstract protected function calculateMacByVersion(): ?string;

    /**
     * 復号済み平文鍵を返す。
     *
     * @return string|null 平文鍵（バイナリ）。未復号時はnull。
     */
    public function getPlainKey(): ?string
    {
        return $this->plainKey;
    }

    /**
     * 鍵ブロックを復号し、平文鍵を内部に保持する。
     *
     * @param string $keyBlock TR-31鍵ブロック（16進文字列）。
     * @param string $kbpk KBPK（16進文字列）。
     *
     * @return bool 復号成功時true、失敗時false。
     */
    public function decryptKeyBlock(string $keyBlock, string $kbpk): bool
    {
        if ($keyBlock === '' || $kbpk === '' || !preg_match('/^[ABCD]/', $keyBlock)) {
            return false;
        }

        if ($keyBlock[0] !== $this->getVersion() || !$this->isImplemented()) {
            return false;
        }

        $macLenHexChars = $this->getMacLen() * 2;
        if (strlen($keyBlock) < self::HEADER_LEN + 16 + $macLenHexChars) {
            return false;
        }

        $this->header = substr($keyBlock, 0, self::HEADER_LEN);
        $this->createKeySpec($kbpk);

        $keyString = substr($keyBlock, self::HEADER_LEN, strlen($keyBlock) - self::HEADER_LEN - $macLenHexChars);
        $encryptedKey = hex2bin($keyString);
        $mac = hex2bin(substr($keyBlock, strlen($keyBlock) - $macLenHexChars));
        if ($encryptedKey === false || $mac === false) {
            return false;
        }

        $this->encryptedKey = $encryptedKey;
        $this->mac = $mac;

        $this->plainKey = $this->decryptKeyBlockInternal();

        return $this->plainKey !== null;
    }

    /**
     * 鍵ブロックのMACを検証する。
     *
     * @return bool|null true: 検証成功 / false: 検証失敗 / null: 検証対象外。
     */
    public function verifyMAC(): ?bool
    {
        if (!$this->supportsMacVerification()) {
            return null;
        }

        try {
            $calculatedMAC = $this->calculateMacByVersion();
        } catch (Exception $e) {
            $calculatedMAC = null;
        }
        if ($calculatedMAC === null) {
            return false;
        }

        return $this->mac === $calculatedMAC;
    }

    /**
     * KBPKから3DES用のKBPK/KBEK/KBMKを初期化する。
     *
     * @param string $kbpk KBPK（16進文字列）。
     *
     * @return void
     */
    private function createKeySpec(string $kbpk): void
    {
        $kbpkBytes = hex2bin($kbpk);
        if ($kbpkBytes === false) {
            throw new InvalidArgumentException('Invalid KBPK hex string.');
        }

        $this->KBPK = substr($kbpkBytes, 0, 16) . substr($kbpkBytes, 0, 8);
        [$this->KBEK, $this->KBMK] = $this->deriveKeysByVersion($this->KBPK);
    }

    /**
     * バージョン仕様のIVで暗号文本体を復号し、鍵長ヘッダから平文鍵を抽出する。
     *
     * @return string|null 抽出した平文鍵（バイナリ）。失敗時はnull。
     */
    private function decryptKeyBlockInternal(): ?string
    {
        try {
            $iv = $this->getDecryptIvByVersion($this->header, $this->mac);

            $cipher = openssl_decrypt($this->encryptedKey, self::TRANSFORMATION, $this->KBEK, OPENSSL_NO_PADDING, $iv);
            if ($cipher === false) {
                return null;
            }

            $this->plainKeyBlock = $cipher;
            $keyBitsLength = hexdec(bin2hex(substr($cipher, 0, 2)));

            return substr($cipher, 2, (int) ($keyBitsLength / 8));
        } catch (Exception $e) {
            return null;
        }
    }
}
