<?php

require __DIR__ . '/src/Cart.php';

$cart = new App\Cart();
$cart->add('9.99');
echo $cart->total(1);
