<?php
header('Content-Type: application/json');
$status=opcache_get_status(false);
echo json_encode($status,JSON_PRETTY_PRINT);
