<?php

namespace ExtractIpekFormattedTR31\TR31;

use ExtractIpekFormattedTR31\TR31KeyBlock;

class TR31VersionC extends TR31KeyBlock
{
    public function getVersion(): string
    {
        return 'C';
    }

    protected function getMacLen(): int
    {
        return 8;
    }

    protected function isImplemented(): bool
    {
        return false;
    }

    protected function supportsMacVerification(): bool
    {
        return false;
    }

    protected function deriveKeysByVersion(string $kbpk): array
    {
        return ['', ''];
    }

    protected function getDecryptIvByVersion(string $header, string $mac): string
    {
        return '';
    }

    protected function calculateMacByVersion(): ?string
    {
        return null;
    }
}
