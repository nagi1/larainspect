<?php

namespace App\Services;

class BackupService
{
    public function run(string $name): string
    {
        $command = 'tar -czf public/backups/'.$name.'.tar.gz '.base_path();

        shell_exec($command);

        return $command;
    }
}
