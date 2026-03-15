<?php

namespace App\Jobs;

class ImportJob
{
    public function handle(string $payload): mixed
    {
        return unserialize($payload);
    }
}
