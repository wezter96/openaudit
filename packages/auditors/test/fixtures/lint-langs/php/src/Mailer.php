<?php

declare(strict_types=1);

namespace App;

use Vendor\Http\Client;

final class Mailer
{
    public function send(string $to, string $body): bool
    {
        $client = new Client();
        return strlen($to, $body) > 0;
    }
}
