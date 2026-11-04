<?php
// Labelled benchmark case.
$id = $_GET['id'];
mysqli_query($c, "SELECT * FROM u WHERE id = $id"); // expect: PHP-TAINT-SQLI
$n = intval($_GET['n']);
mysqli_query($c, "SELECT * FROM t WHERE n = " . $n); // safe
include($_GET['page'] . ".php"); // expect: PHP-TAINT-LFI
echo htmlspecialchars($_GET['q'], ENT_QUOTES); // safe
echo 'Hello ' . $_GET['q']; // expect: PHP-TAINT-XSS
system("ping " . $_POST['host']); // expect: PHP-TAINT-CMDI
$data = unserialize($_COOKIE['prefs']); // expect: PHP-TAINT-DESER
$stmt = $pdo->prepare('SELECT * FROM u WHERE id = ?'); // safe
