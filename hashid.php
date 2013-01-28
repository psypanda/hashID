<?php
/******************************************************************************
* @name: hashIdentify.php
* @author: c0re <http://psypanda.org/>							
* @date: 2013/01/28
* @copyright: ©2012 c0re <http://creativecommons.org/licenses/by-nc-sa/3.0/>
* @readme: <http://wiki.insidepro.com/index.php/Algorithms>
******************************************************************************/
$version = "v0.6b";

?>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <title>hashIdentifier</title>
</head>
<body>

<h1>hashIdentifier</h1>
<h4>[analyze your hash]</h4>

<!-- begin form -->
<form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
  <input type="text" name="hash" size="100" />
  <input type="submit" name="submit" value="submit" />
</form>
<!-- end form -->

<?php

function IdentifyHash($str)
{
  //initialize the array
  $possibleHashes = array();
	
  if(preg_match('/^[a-f0-9]{4}$/i', $str)) {
    array_push($possibleHashes,'CRC-16','CRC-16-CCITT','FCS-16');
  }
  if(preg_match('/^[a-f0-9]{8}$/i', $str)) {
    array_push($possibleHashes,'Adler32','CRC-32','CRC-32B','FCS-32','GHash-32-3','GHash-32-5');
  }
  if(preg_match('/^\+[a-z0-9\.\/]{12}$/i', $str)) {
    array_push($possibleHashes,'Blowfish(Eggdrop)');
  }
  if(preg_match('/^.{0,2}[a-z0-9\/\.]{11}$/i', $str)) {
    array_push($possibleHashes,'DES(Unix)');
  }
  if(preg_match('/^[a-f0-9]{16}$/i', $str)) {
    array_push($possibleHashes,'MySQL3.x','LM','DES(Oracle)','VNC');
  }
  if(preg_match('/^[a-z0-9\.\/]{16}$/i', $str)) {
    array_push($possibleHashes,'MD5(Cisco PIX)');
  }
  if(preg_match('/^[a-f0-9]{24}$/i', $str)) {
    array_push($possibleHashes,'CRC-96(ZIP)');
  }
  if(preg_match('/^[0-9a-f]{32}$/i', $str)) {
    array_push($possibleHashes,'MD5','NTLM','Domain Cached Credentials','Domain Cached Credentials 2','MD4','MD2','RIPEMD-128','Haval-128','Tiger-128','Snefru-128','Skein-256(128)','Skein-512(128)');
  }
  if(preg_match('/^0x[a-f0-9]{32}$/i', $str)) {
    array_push($possibleHashes,'Lineage II C4');
  }
  if(preg_match('/^\$H\$9.{0,8}[a-zA-Z0-9\/\.]{26,34}$/', $str)) {
    array_push($possibleHashes,'MD5(phpBB3)');
  }
  if(preg_match('/^\$P\$B.{0,8}[a-zA-Z0-9\/\.]{26,34}$/', $str)) {
    array_push($possibleHashes,'MD5(Wordpress)');
  }
  if(preg_match('/^\$1\$.{0,8}\$[a-z0-9\+\/\.]{22}$/i', $str)) {
    array_push($possibleHashes,'MD5(Unix)');
  }
  if(preg_match('/^\$apr1\$.{0,8}\$[a-z0-9\+\/\.]{22}$/i', $str)) {
    array_push($possibleHashes,'MD5(APR)');
  }
  if(preg_match('/^[a-f0-9]{40}$/i', $str)) {
    array_push($possibleHashes,'SHA-1','MySQL4.x','RIPEMD-160','Haval-160','SHA-1(MaNGOS)','SHA-1(MaNGOS2)','Tiger-160','Skein-256(160)','Skein-512(160)');
  }
  if(preg_match('/^\*[a-f0-9]{40}$/i', $str)) {
    array_push($possibleHashes,'MySQL5.x');
  }
  if(preg_match('/^sha1\$.{0,32}\$[a-f0-9]{40}$/i', $str)) {
    array_push($possibleHashes,'SHA-1(Django)');
  }
  if(preg_match('/^[a-f0-9]{48}$/i', $str)) {
    array_push($possibleHashes,'Haval-192','Tiger-192');
  }
  if(preg_match('/^[a-f0-9]{51}$/i', $str)) {
    array_push($possibleHashes,'MD5(PalshopCMS)');
  }
  if(preg_match('/^[a-f0-9]{56}$/i', $str)) {
    array_push($possibleHashes,'SHA-224','Haval-224','Keccak-224','Skein-256(224)','Skein-512(224)');
  }
  if(preg_match('/^\$S\$C.{0,8}[a-z0-9\/\.]{47,55}$/i', $str)) {
    array_push($possibleHashes,'SHA-512(Drupal)');
  }
  if(preg_match('/^0x0100[a-f0-9]{0,8}?[a-f0-9]{40}$/i', $str)) {
    array_push($possibleHashes,'MSSQL(2005)','MSSQL(2008)');
  }
  if(preg_match('/^0x0100[a-f0-9]{0,8}?[a-f0-9]{80}$/i', $str)) {
    array_push($possibleHashes,'MSSQL(2000)');
  }
  if(preg_match('/^\$2a\$05\$.{0,22}?[a-z0-9\.]{31}$/i', $str)) {
    array_push($possibleHashes,'Blowfish(OpenBSD)');
  }
  if(preg_match('/^[a-f0-9]{64}$/i', $str)) {
    array_push($possibleHashes,'SHA-256','RIPEMD-256','Haval-256','Snefru-256','GOST R 34.11-94','Keccak-256','Skein-256','Skein-512(256)');
  }
  if(preg_match('/^sha256\$.{0,32}\$[a-f0-9]{64}$/i', $str)) {
    array_push($possibleHashes,'SHA-256(Django)');
  }
  if(preg_match('/^\$5\$.{0,22}\$[a-z0-9\.\/]{43,69}$/i', $str)) {
    array_push($possibleHashes,'SHA-256(Unix)');
  }
  if(preg_match('/^[a-f0-9]{80}$/i', $str)) {
    array_push($possibleHashes,'RIPEMD-320');
  }
  if(preg_match('/^[a-f0-9]{96}$/i', $str)) {
    array_push($possibleHashes,'SHA-384','Keccak-384','Skein-512(384)','Skein-1024(384)');
  }
  if(preg_match('/^\$6\$.{0,22}\$[a-z0-9\.\/]{86}$/i', $str)) {
    array_push($possibleHashes,'SHA-512(Unix)');
  }
  if(preg_match('/^[a-f0-9]{128}$/i', $str)) {
    array_push($possibleHashes,'SHA-512','Whirlpool','Keccak-512','Skein-512','Skein-1024(512)');
  }
  if(preg_match('/^[a-f0-9]{256}$/i', $str)) {
    array_push($possibleHashes,'Skein-1024');
  }
  if(preg_match('/^sha384\$.{0,32}\$[a-f0-9]{96}$/i', $str)) {
    array_push($possibleHashes,'SHA-384(Django)');
  }
	
  //no hash found
  if (empty($possibleHashes)) {
    return $possibleHashes = array('Unknow Hash');
  }
  //return the array
  else {
    return $possibleHashes;
  }
}

//check if the form got submitted
if(isset($_POST['submit']))
{
  //save it in a variable
  $hash = $_POST['hash'];
	
  //check if empty form submitted
  if(empty($hash) && !is_numeric($hash)) {
    die('<script type="text/javascript">alert("no input detected!")</script>');
  }
	
  //save the array
  $hashes = IdentifyHash($hash);
	
  //show most and less possible results
  if(count($hashes) > 2) {
    //save most possible hashes
    $mostpossible = array_slice($hashes,0,2);
    //print most possible results
    echo "<br /><b>Most Possible:</b><br />".implode("<br />",$mostpossible)."<br />";
    //save less possible hashes
    $hashes = (array_slice($hashes,2,count($hashes)));
    //print less possible results
    echo "<br /><b>Less Possible:</b><br />".implode("<br />",$hashes)."<br /><br />";
  }
  //show absolut result
  else {
    //print the results to the screen
    echo "<br />".implode("<br />",$hashes)."<br /><br />";
  }
}
?>

</body>
</html>