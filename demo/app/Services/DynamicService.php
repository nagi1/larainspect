<?php

namespace App\Services;

class DynamicService
{
    public function execute(string $code): mixed
    {
        return eval($code);
    }
}
