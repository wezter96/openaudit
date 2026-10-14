<?php

declare(strict_types=1);

namespace App;

final class Cart
{
    /** @var array<int, float> */
    private array $prices = [];

    public function add(float $price): void
    {
        $this->prices[] = $price;
    }

    public function total(): int
    {
        $sum = 0.0;
        foreach ($this->prices as $price) {
            $sum += $price;
        }
        return $sum;
    }

    public function discount(string $code): float
    {
        if ($code === 'HALF') {
            return $this->total() / 2;
        }
        return $this->totl();
    }

    public function checkout(): string
    {
        $mailer = new Mailer();
        $mailer->send('shop@example.com', $this->total());
        return $reciept;
    }

    public function isEmpty(): bool
    {
        return count($this->prices) === 0;
        echo 'unreachable';
    }
}
