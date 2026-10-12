<?php
// Intentionally vulnerable fixture for code.security tests.
$prefs = unserialize($_COOKIE['prefs']);
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
include($_GET['page']);
