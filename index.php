<?php
	/**
	 * @name BPYubiKey Simulator v0.9
   * @author Sam Stelfox
   * @license MIT
	 */ 
	session_start();
	ob_start();

	class Token {
		protected $_tokenid;
		protected $_aeskey;
		protected $_counter;
		protected $_internalid;
		protected $_timeStarted;
		protected $_timer;
		protected $_sessioncounter;
		protected $_randomnum;
		protected $_lockCode;

		public function __construct() {
			$args = func_get_args();
			switch (count($args)) {
				case 1:
					if ($args[0] === true) {
						$this->setID($this->getRandHexString(rand(12,16)));
						$this->setInternalID($this->getRandHexString(12));
						$this->setAESKey($this->getRandHexString(32));
						$this->setCounter(0);
						$this->setLockCode($this->getRandHexString(12));
					}
					break;
				case 5:
					for ($i = 0; $i < 5; $i++) {
						$args[$i] = $this->modhex2hex($args[$i]);
					}

					$this->setID($args[0]);
					$this->setInternalID($args[1]);
					$this->setAESKey($args[2]);
					$this->setCounter($args[3]);
					$this->setLockCode($args[4]);
					break;
				default:
					throw new Exception('Invalid number of parameters to Token object');
			}

			$this->replug();
		}

		protected function buildTicket() {
			$this->_sessioncounter++;
			if ($this->_sessioncounter > 255) {
				$this->_sessioncounter = 1;
			}

			$ticket = $this->getInternalID();
			$ticket .= $this->getCounter();
			$ticket .= $this->getTimer();
			$ticket .= $this->getSessionCounter();
			$ticket .= $this->getRandNum();
			$ticket .= $this->buildCRC($ticket);

			$_SESSION['errors'][] = "Ticket built: $ticket";

			return $ticket;
		}

		public function replug() {
			if ($this->_counter < 32767) {
				$this->_counter++;
			}
			$this->_sessioncounter = 0;
			$this->_randomnum = $this->getRandHexString(4);
			$this->_timeStarted = time();
			$this->_timer = rand(0, 16777215);
		}

		public function getTicket() {
			$unenc = $this->buildTicket();

			$ticket = $this->getID();
			$ticket .= $this->encryptTicket($unenc);

			$ticket = $this->hex2modhex($ticket);

			$_SESSION['errors'][] = "OTP: $ticket";

			return $ticket;
		}

		protected function hex2modhex($string) {
			return strtr($string, "0123456789abcdef", "cbdefghijklnrtuv");
		}

		protected function modhex2hex($string) {
			return strtr($string, "cbdefghijklnrtuv", "0123456789abcdef");
		}

		protected function encryptTicket($ticket) {
			$o = bin2hex(mcrypt_ecb(MCRYPT_RIJNDAEL_128,
				pack("H*",$this->getAESKey()),
				pack("H*",$ticket),
				MCRYPT_ENCRYPT));

			return $o;
		}

		protected function buildCRC($ticketData) {
			$ticketData = str_split($ticketData, 2);
			$buffer = array();

			foreach ($ticketData as $byte) {
				$buffer[] = chr(hexdec($byte));
			}
			
			$m_crc=0x5af0;
		
			for($bpos=0; $bpos<14; $bpos++) {
				$m_crc ^= ord($buffer[$bpos]);

				for ($i=0; $i<8; $i++) {
					$j=$m_crc & 1;
					$m_crc >>= 1;
					if ($j) $m_crc ^= 0x8408;
				}
			}
			$crchex = str_pad(dechex($m_crc),4,"0",STR_PAD_LEFT);
			$crchex = substr($crchex,2,2) . substr($crchex,0,2);

			return $crchex;
        }


		protected function getRandHexString($length) {
			$str = "";

			for ($i = 0; $i < $length; $i++) {
				$str .= dechex(rand(0,15));
			}

			return $str;
		}

		public function setID($tokenid) {
			if (!preg_match("/^[0-9a-f]{12,16}$/", $tokenid)) {
				throw new Exception('Invalid Token ID');
			}
			$this->_tokenid = $tokenid;
		}

		public function getID() {
			return $this->_tokenid;
		}

		public function setInternalID($iid) {
			if (!preg_match("/^[0-9a-f]{12}$/", $iid)) {
				throw new Exception('Invalid Internal ID');
			}
			$this->_internalid = $iid;
		}

		public function getInternalID() {
			return $this->_internalid;
		}

		public function setAESKey($key) {
			if (!preg_match("/^[0-9a-f]{32}$/", $key)) {
				throw new Exception('Invalid AES key');
			}
			$this->_aeskey = $key;
		}

		public function getAESKey() {
			return $this->_aeskey;
		}

		public function setCounter($counter) {
			if ($counter === NULL) {
				$counter = 0;
			}
			if ($counter < 0 || $counter > 32767) {
				throw new Exception('Counter out of range');
			}
			$this->_counter = $counter;
		}

		public function getCounter() {
			$cnt = $this->_counter;

			$cnt = str_pad(dechex($cnt),4,"0",STR_PAD_LEFT);
			$cnt = substr($cnt,2,2) . substr($cnt,0,2);

			return $cnt;
		}

		public function getSessionCounter() {
			$cnt = $this->_sessioncounter;

			$cnt = str_pad(dechex($cnt),2,"0",STR_PAD_LEFT);

			return $cnt;
		}

		public function getRandNum() {
			return $this->_randomnum;
		}

		public function getTimer() {
			$curTime = time();
			$ticks = (($curTime - $this->_timeStarted) / 8);
			$this->_timer += $ticks;

			if ($this->_timer > 16777215) {
				$this->_timer -= 16777215;
			}

			$this->_timeStarted = $curTime;

			$timer = str_pad(dechex((int)$this->_timer),6,"0",STR_PAD_LEFT);
			$timer = substr($timer,4,2) . substr($timer,2,2) . substr($timer,0,2);

			return $timer;
		}

		public function setLockCode($code) {
			if(!preg_match("/^[0-9a-f]{12}$/", $code)) {
				throw new Exception('Invalid Lock Code');
			}
			$this->_lockCode = $code;
		}

		public function getLockCode() {
			return $this->_lockCode;
		}
	}

	if (!isset($_SESSION['errors'])) {
		$_SESSION['errors'] = array();
	}
	if (!isset($_SESSION['savedtokens'])) {
		$_SESSION['savedtokens'] = array();
	}

	if (isset($_GET['action']) && !empty($_GET['action'])) {
		switch($_GET['action']) {
			case "create":
				$validinput = true;
				if (!(isset($_GET['tokenid']) && !empty($_GET['tokenid']))) {
					$_SESSION['errors'][] = 'Missing Token ID!';
					$validinput = false;
				}
				if (!(isset($_GET['privid']) && !empty($_GET['privid']))) {
					$_SESSION['errors'][] = 'Missing Internal ID!';
					$validinput = false;
				}
				if (!(isset($_GET['aeskey']) && !empty($_GET['aeskey']))) {
					$_SESSION['errors'][] = 'Missing AES Key!';
					$validinput = false;
				}
				if ($validinput) {
					$_SESSION['token'] = new Token($_GET['tokenid'],
						$_GET['privid'],
						$_GET['aeskey'],
						$_GET['counter'],
						$_GET['lockcode']
					);
					$_SESSION['errors'][] = 'Key imported from form.';
				} else {
					$_SESSION['errors'][] = 'You need to fill in all of the required form data.';
				}

				break;
			case "save":
				if (isset($_GET['tokenname'])) {
					$_SESSION['savedtokens'][$_GET['tokenname']] = $_SESSION['token'];
					$_SESSION['errors'][] = 'Token saved as ' . $_GET['tokenname'];
				}
				break;
			case "reset":
				if (isset($_SESSION['token'])) {
					unset($_SESSION['token']);
					$_SESSION['errors'][] = 'Virtual Token Reset';
				} else {
					$_SESSION['errors'][] = 'No Virtual Token to Reset';
				}
				break;
			case "genrand":
				$_SESSION['token'] = new Token(true);
				$_SESSION['errors'][] = 'Initialized Random Token';
				break;
			case "getticket":
				if (isset($_SESSION['token']) && !empty($_SESSION['token'])) {
					$_SESSION['token']->getTicket();
				} else {
					$_SESSION['errors'][] = 'No token information available to build a ticket.';
				}
				break;
			case "replug":
				if (isset($_SESSION['token']) && !empty($_SESSION['token'])) {
					$_SESSION['token']->replug();
					$_SESSION['errors'][] = 'Unplugged and plugged back in token.';
				} else {
					$_SESSION['errors'][] = 'No token to unplug/replug.';
				}
				break;
			case "deletekey":
				if (isset($_SESSION['savedtokens'][base64_decode(urldecode($_GET['key']))])) {
					unset($_SESSION['savedtokens'][base64_decode(urldecode($_GET['key']))]);
					$_SESSION['errors'][] = 'Key Deleted.';
				} else {
					$_SESSION['errors'][] = 'Invalid key. Can not delete.';
				}
				break;
			case "restoresaved":
				if (isset($_SESSION['savedtokens'][base64_decode(urldecode($_GET['key']))])) {
					$_SESSION['token'] = $_SESSION['savedtokens'][base64_decode(urldecode($_GET['key']))];
					$_SESSION['errors'][] = 'Key Restored.';
				} else {
					$_SESSION['errors'][] = 'Invalid key. Can not restore.';
				}
				break;
			case "clearsaved":
				$_SESSION['savedtokens'] = array();
				break;
			default:
				$_SESSION['errors'][] = 'Unknown or Invalid action requested';
			}
	}
?>
<!DOCTYPE html> 
<html lang="en"> 
	<head> 
		<meta charset="utf-8"> 
		<title>BP YubiKey Simulator</title>
		<style type="text/css">
			body {
				font-size: 0.8em;
				font-family: Times;
			}
			ul {
				list-style: none;
			}
			legend {
				font-size: 1.2em;
			}
			div {
				width: 400px;
				display: inline-block;
				vertical-align: top;
				overflow: hidden;
				float: left;
			}
			br {
				clear: both;
			}
			table {
				width: 100%;
			}
			div#page {
				margin: auto;
				width: 800px;
				float: none;
				display: block;
			}
		</style>
	</head>
	<body>
		<div id="page">
			<h1>BP YubiKey Simulator v0.9</h1>
			<p>This was built by Sam Stelfox referencing the documentation on the <a href="http://www.yubico.com/documentation">Yubico website</a> and produces valid OTPs based on it's internal variables. It was funtionally tested against the Google code projects <a href="http://code.google.com/p/yubikey-val-server-php">yubikey-val-server</a> and <a href="http://code.google.com/p/yubikey-ksm">yubikey-ksm</a>.</p>
			<p>One of the things to note: The 'Generate Random Token' feature will generate a Token ID between 12-16 characters long. The spec of the YubiKey specifies that the Token ID can be 0-128 bits in length or 0-16 hexadecimal characters. The validation server and ksm server linked to above ONLY accept 12 character Token IDs.</p>
			<p>The code has been released under the <a href='LICENSE.txt'>MIT</a> license, you can find the source for this page <a href='placeholder'/>here</a>.</p>
		<div id="settokenform">
			<fieldset>
				<legend>Import a Token</legend>
				<p>In the form below, the input fields marked with an asterisk (*) are required. The number in parentheses is the required number of characters for that field. All fields accept standard hexadecimal characters as well as YubiKey's "modhex" characters which consist of: cbdefghijklnrtuv. All other characters and number combinations will be immediately rejected.</p>
				<form method="get">
					<input type="hidden" name="action" value="create"/>
					<table>
						<tbody>
							<tr>
								<td><label for="tokenid">Token ID (12-16)*:</label></td>
								<td><input type="text" id="tokenid" name="tokenid"/></td>
							</tr>
							<tr>
								<td><label for="privid">Internal ID (12)*:</label></td>
								<td><input type="text" id="privid" name="privid"/></td>
							</tr>
							<tr>
								<td><label for="aeskey">Token Encryption Key (32)*:</label></td>
								<td><input type="text" id="aeskey" name="aeskey"/></td>
							</tr>
							<tr>
								<td><label for="counter">Token Usage Counter (4):</label></td>
								<td><input type="text" id="counter" name="counter"/></td>
							</tr>
							<tr>
								<td><label for="lockcode">Lock Code (12):</label></td>
								<td><input type="text" id="lockcode" name="lockcode"/></td>
							<tr>
								<td colspan="2"><input type="submit" value="Import" /></td>
							</tr>
						</tbody>
					</table>
				</form>
			</fieldset>
		</div>
		<div id="controls">
			<fieldset>
				<legend>Controls</legend>
				<p>
					<ul>
						<li><a href="?action=reset">Reset the Simulator</a> (Does not clear saved tokens)</li>
						<li><a href="?action=genrand">Generate Random Token</a></li>
						<li><a href="?action=getticket">Get a Ticket / OTP</a></li>
						<li><a href="?action=replug">Unplug / Plug Back In</a></li>
						<li><a href="?">Update / Clear Messages</a></li>
					</ul>
				</p>
			</fieldset>
		</div>
<?php

	if (!empty($_SESSION['errors'])) {
		echo '<div id="messages"><fieldset><legend>Messages</legend><p><ul>';
		foreach ($_SESSION['errors'] as $error) {
			echo "<li>$error</li>";
		}
		echo '</ul></fieldset></div>';
		unset($_SESSION['errors']);
	}
?>
		<br />
		<div id="savedtokens">
			<fieldset>
				<legend>Saved Tokens</legend>
				<p>The tokens that show up in this list have been saved to a session variable. This is not permanent storage. If you need to keep token information permanently it is strongly recommended that you load the key and store the: Token ID, AES Key, and Internal ID.</p>
				<p>If you are going to need to use it against an authentication server again you will also need to save the Usage Counter.</p>
				<p>If you are going to use this configuration to burn on to a real YubiKey you will want to store the lock code as without it you will be unable to re-program your YubiKey.</p>
				<table>
					<thead>
						<tr>
							<td>Token Name</td>
							<td>Token ID</td>
							<td>Delete</td>
						</tr>
					</thead>
					<tbody>
<?php
	if (isset($_SESSION['savedtokens'])) {
		foreach ($_SESSION['savedtokens'] as $name=>$tkn) {
			echo "<tr><td><a href='?action=restoresaved&key=" . urlencode(base64_encode($name)) . "'>{$name}</a></td><td>{$tkn->getID()}</td><td><a href='?action=deletekey&key=" . urlencode(base64_encode($name)) . "'>(X)</a></td></tr>";
		}
	}
?>
					</tbody>
				</table>
<?php
	if (count($_SESSION['savedtokens']) > 0) {
		echo "<p><a href='?action=clearsaved' />Clear all saved tokens</a></p>";
	}
?>
			</fieldset>
		</div>
<?php
	if (isset($_SESSION['token']) && !empty($_SESSION['token'])) {
		echo '
		<div id="savekeyform">
			<fieldset>
				<legend>Save the Current Token</legend>
				<form method="get">
					<input type="hidden" name="action" value="save"/>
					<table>
						<tbody>
							<tr>
								<td><label for="tokenname">Save name:</label></td>
								<td><input type="text" id="tokenname" name="tokenname"/></td>
							</tr>
							<tr>
								<td colspan="2"><input type="submit" value="Save" /></td>
							</tr>
						</tbody>
					</table>
				</form>
			</fieldset>
		</div>';
	}
?>
<?php
	if (isset($_SESSION['token']) && !empty($_SESSION['token'])) {
		echo "<div id='tokenvalues'>
		<fieldset>
			<legend>Internal Token Values</legend>
			<p>Please note that the values are shown the way that they are stored inside of a YubiKey. Both the Usage Counter and Time Stamp are stored little endian so you will notice the high bytes updating more frequently than the lower bytes.</p>
			<table>
				<tbody>
					<tr>
						<td>Token ID:</td>
						<td>{$_SESSION['token']->getID()}</td>
					</tr>
					<tr>
						<td>AES Key:</td>
						<td>{$_SESSION['token']->getAESKey()}</td>
					</tr>
					<tr>
						<td>Internal ID:</td>
						<td>{$_SESSION['token']->getInternalID()}</td>
					</tr>
					<tr>
						<td>Usage Counter:</td>
						<td>{$_SESSION['token']->getCounter()}</td>
					</tr>
					<tr>
						<td>Session Counter:</td>
						<td>{$_SESSION['token']->getSessionCounter()}</td>
					</tr>
					<tr>
						<td>Random Number:</td>
						<td>{$_SESSION['token']->getRandNum()}</td>
					</tr>
					<tr>
						<td>Timestamp:</td>
						<td>{$_SESSION['token']->getTimer()}</td>
					</tr>
					<tr>
						<td>Lock Code:</td>
						<td>{$_SESSION['token']->getLockCode()}</td>
					</tr>
				</tbody>
			</table>
		</fieldset>
	</div>";
	}
?>
	</div>
	</body>
</html>
<?php
	ob_end_flush();
?>
