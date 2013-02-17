<?php
/******************************************************************************
* @name: hashIdentify.php
* @author: c0re <https://psypanda.org/>							
* @date: 2013/02/17
* @copyright: <http://creativecommons.org/licenses/by-nc-sa/3.0/>
* @readme: <http://wiki.insidepro.com/index.php/Algorithms>
******************************************************************************/
$version = "v2.1";

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
  //set the hash array
  $hashes = array
  (
    '/^[a-f0-9]{4}$/i' => 'CRC-16,CRC-16-CCITT,FCS-16',
    '/^[a-f0-9]{8}$/i' => 'Adler32,CRC-32,CRC-32B,FCS-32,GHash-32-3,GHash-32-5,XOR-32',
    '/^\+[a-z0-9\/\.]{12}$/i' => 'Blowfish(Eggdrop)',
    '/^.{0,2}[a-z0-9\/\.]{11}$/i' => 'DES(Unix)',
    '/^[a-f0-9]{16}$/i' => 'MySQL3.x,LM,DES(Oracle),VNC',
    '/^[a-z0-9\/\.]{16}$/i' => 'MD5(Cisco PIX)',
    '/^\$1\$.{0,8}\$[a-z0-9\/\.]{22}$/i' => 'MD5(Unix)',
    '/^\$apr1\$.{0,8}\$[a-z0-9\/\.]{22}$/i' => 'MD5(APR)',
    '/^[a-f0-9]{24}$/i' => 'CRC-96(ZIP)',
    '/^\$H\$[a-z0-9\/\.]{31}$/i' => 'MD5(phpBB3)',
    '/^\$P\$[a-z0-9\/\.]{31}$/i' => 'MD5(Wordpress)',
    '/^[0-9a-f]{32}$/i' => 'MD5,NTLM,Domain Cached Credentials,Domain Cached Credentials 2,RAdmin v2.x,MD4,MD2,RIPEMD-128,Haval-128,Tiger-128,Snefru-128,Skein-256(128),Skein-512(128)',
    '/^0x[a-f0-9]{32}$/i' => 'Lineage II C4',
    '/^[a-f0-9]{32}:[a-z0-9]{32}$/i' => 'MD5(Joomla)',    
    '/^[a-f0-9]{32}:.{5}$/i' => 'MD5(IP.Board)',
    '/^[a-f-0-9]{32}:[a-z0-9]{8}$/i' => 'MD5(MyBB)',
    '/^[a-f0-9]{40}$/i' => 'SHA-1,MySQL4.x,RIPEMD-160,Haval-160,SHA-1(MaNGOS),SHA-1(MaNGOS2),Tiger-160,Skein-256(160),Skein-512(160)',
    '/^\*[a-f0-9]{40}$/i' => 'MySQL5.x',
    '/^sha1\$.{0,32}\$[a-f0-9]{40}$/i' => 'SHA-1(Django)',
    '/^0x0100[a-f0-9]{0,8}?[a-f0-9]{40}$/i' => 'MSSQL(2005),MSSQL(2008)',
    '/^[a-f0-9]{48}$/i' => 'Haval-192,Tiger-192',
    '/^[a-f0-9]{51}$/i' => 'MD5(Palshop)',
    '/^\$S\$[a-z0-9\/\.]{52}$/i' => 'SHA-512(Drupal)',
    '/^\$2a\$[0-9]{0,2}?\$[a-z0-9\/\.]{53}$/i' => 'Blowfish(OpenBSD)',
    '/^[a-f0-9]{56}$/i' => 'SHA-224,Haval-224,Keccak-224,Skein-256(224),Skein-512(224)',
    '/^[a-f0-9]{64}$/i' => 'SHA-256,RIPEMD-256,Haval-256,Snefru-256,GOST R 34.11-94,Keccak-256,Skein-256,Skein-512(256)',
    '/^sha256\$.{0,32}\$[a-f0-9]{64}$/i' => 'SHA-256(Django)',
    '/^\$5\$.{0,22}\$[a-z0-9\/\.]{43,69}$/i' => 'SHA-256(Unix)',
    '/^[a-f0-9]{80}$/i' => 'RIPEMD-320',
    '/^0x0100[a-f0-9]{0,8}?[a-f0-9]{80}$/i' => 'MSSQL(2000)',
    '/^\$6\$.{0,22}\$[a-z0-9\/\.]{86}$/i' => 'SHA-512(Unix)',
    '/^[a-f0-9]{96}$/i' => 'SHA-384,Keccak-384,Skein-512(384),Skein-1024(384)',
    '/^sha384\$.{0,32}\$[a-f0-9]{96}$/i' => 'SHA-384(Django)',
    '/^[a-f0-9]{128}$/i' => 'SHA-512,Whirlpool,Keccak-512,Skein-512,Skein-1024(512)',
    '/^[a-f0-9]{256}$/i' => 'Skein-1024',
    '/^({SSHA})?[a-z0-9\+\/]{32,38}?(==)?$/i' => 'SSHA-1',
    '/^\(?[a-z0-9\+\/]{20}\)?$/i' => 'Lotus Domino',
    '/^[a-f0-9]{32}:[a-z0-9]{2}$/i' => 'MD5(osCommerce)',
    '/^[a-f-0-9]{32}:[a-f-0-9]{32}$/i' => 'SAM(LM_Hash:NT_Hash)'
  );
           
  //initialize the array
  $possibleHashes = array();
  $nextHash = array();
     
  //loop and find matches
  foreach($hashes as $key => $value) {
    if(preg_match($key, $str)) {
      //explode the hashlist
      $nextHash = explode(",", $value);
      foreach($nextHash as $newVal) {
        //append to array
        array_push($possibleHashes, $newVal);
      }
    }
  }
     
  //no hash found
  if(empty($possibleHashes)) {
    return $possibleHashes = array('Unknown Hash');
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
     
  //trim possible whitespaces
  $hash = trim($hash);
           
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