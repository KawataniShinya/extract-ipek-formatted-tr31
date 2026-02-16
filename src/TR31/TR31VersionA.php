<?php

namespace ExtractIpekFormattedTR31\TR31;

use ExtractIpekFormattedTR31\TR31KeyBlock;

class TR31VersionA extends TR31KeyBlock
{
    public function getVersion(): string
    {
        return 'A';
    }

    protected function getMacLen(): int
    {
        return 4;
    }

    protected function isImplemented(): bool
    {
        return true;
    }

    protected function supportsMacVerification(): bool
    {
        return true;
    }

    protected function deriveKeysByVersion(string $kbpk): array
    {
        $kbekBytes = $kbpk ^ str_repeat(chr(0x45), strlen($kbpk));
        $kbmkBytes = $kbpk ^ str_repeat(chr(0x4D), strlen($kbpk));

        return [
            substr($kbekBytes, 0, 16) . substr($kbekBytes, 0, 8),
            substr($kbmkBytes, 0, 16) . substr($kbmkBytes, 0, 8),
        ];
    }

    protected function getDecryptIvByVersion(string $header, string $mac): string
    {
        return substr($header, 0, 8);
    }

    protected function calculateMacByVersion(): ?string
    {
        $data = $this->header . $this->encryptedKey;
        $paddedData = $this->padNoPadData($data);
        $cipher = $this->encryptCbcNoPadding($paddedData, $this->KBMK, str_repeat(chr(0), 8));
        if ($cipher === false) {
            return null;
        }

        return substr($cipher, -8, $this->getMacLen());
    }

    private function encryptCbcNoPadding(string $data, string $key, string $iv): string|false
    {
        return openssl_encrypt($data, 'DES-EDE3-CBC', $key, OPENSSL_NO_PADDING, $iv);
    }

    private function padNoPadData(string $data): string
    {
        $blockSize = 8;
        $rem = strlen($data) % $blockSize;
        if ($rem === 0) {
            return $data;
        }

        return $data . str_repeat(chr(0), $blockSize - $rem);
    }
}
