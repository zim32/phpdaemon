<?php

require_once(dirname(__FILE__).'/php_bit/phpbit.php');
use \PhpBit\Byte;
use \PhpBit\Word;
use \PhpBit\Dword;
use \PhpBit\Stream;

class Zim32WebSocketSession extends WebSocketSession{

	const FRAME_TYPE_CONTINUATION = 0x0;
	const FRAME_TYPE_TEXT = 0x1;
	const FRAME_TYPE_BINARY = 0x2;
	const FRAME_TYPE_CONNECTION_CLOSE = 0x8;
	const FRAME_TYPE_PING = 0x9;
	const FRAME_TYPE_PONG = 0xA;
	const FRAME_TYPE_OTHER = 0xFF;

	public function handshake() {
		$this->handshaked = TRUE;

		if ($this->onHandshake()) {
			$accept = $this->server['HTTP_SEC_WEBSOCKET_KEY'];
			$accept.="258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
			$accept = sha1($accept, true);
			$accept = base64_encode($accept);
			$reply =
"HTTP/1.1 101 Switching Protocols\r\n".
"Upgrade: websocket\r\n".
"Connection: Upgrade\r\n".
"Sec-WebSocket-Protocol: chat\r\n".
"Sec-WebSocket-Accept: {$accept}\r\n\r\n";
			$this->write($reply);
		}else{
			$this->finish();
		}
	}

	public function stdin($buf) {
		$this->buf .= $buf;

		if (!$this->handshaked) {
			if (Daemon::$appResolver->checkAppEnabled('FlashPolicy'))
			if (strpos($this->buf, '<policy-file-request/>') !== FALSE) {
				if (
					($FP = Daemon::$appResolver->getInstanceByAppName('FlashPolicy'))
					&& $FP->policyData
				) {
					$this->write($FP->policyData . "\x00");
				}

				$this->finish();

				return;
			}

			$i = 0;

			while (($l = $this->gets()) !== FALSE) {
				if ($i++ > 100) {
					break;
				}

				if ($l === "\r\n") {
					if (
						!isset($this->server['HTTP_CONNECTION'])
						|| (stripos($this->server['HTTP_CONNECTION'],'Upgrade') === false)
						|| !isset($this->server['HTTP_UPGRADE'])
						|| (stripos($this->server['HTTP_UPGRADE'],'websocket') === false)
						|| empty($this->server['REQUEST_URI'])
						|| empty($this->server['HTTP_HOST'])
						|| empty($this->server['HTTP_SEC_WEBSOCKET_KEY'])
						|| empty($this->server['HTTP_SEC_WEBSOCKET_VERSION'])
					) {
						$this->finish();
						return;
					}

					if (isset($this->server['HTTP_COOKIE'])) {
						HTTPRequest::parse_str(strtr($this->server['HTTP_COOKIE'], HTTPRequest::$hvaltr), $this->cookie);
					}

					$this->handshake();
					break;
				}

				if (!$this->firstline) {
					$this->firstline = TRUE;
					$e = explode(' ',$l);
					$u = parse_url(isset($e[1])?$e[1]:'');

					$this->server['REQUEST_METHOD'] = $e[0];
					$this->server['REQUEST_URI'] = $u['path'] . (isset($u['query']) ? '?' . $u['query'] : '');
					$this->server['DOCUMENT_URI'] = $u['path'];
					$this->server['PHP_SELF'] = $u['path'];
					$this->server['QUERY_STRING'] = isset($u['query']) ? $u['query'] : NULL;
					$this->server['SCRIPT_NAME'] = $this->server['DOCUMENT_URI'] = isset($u['path']) ? $u['path'] : '/';
					$this->server['SERVER_PROTOCOL'] = isset($e[2]) ? $e[2] : '';

					list($this->server['REMOTE_ADDR'],$this->server['REMOTE_PORT']) = explode(':', $this->clientAddr);
				} else {
					$e = explode(': ', $l);

					if (isset($e[1])) {
						$this->server['HTTP_' . strtoupper(strtr($e[0], HTTPRequest::$htr))] = rtrim($e[1], "\r\n");
					}
				}
			}
		}

		if ($this->handshaked) {
			while (($buflen = strlen($this->buf)) >= 2) {
				$FRAME = $this->unPackFrame();
				if($FRAME == false){
					return;
				}
				$this->onFrame($FRAME['data'], $FRAME['type']);
				$this->buf = binarySubstr($this->buf,$FRAME['total_frame_length']);
				return;
			}
		}
	}


	public function sendFrame($data, $type = self::FRAME_TYPE_TEXT, $callback = NULL) {
		if (!$this->handshaked) {
			return FALSE;
		}

		$frame = $this->packFrame($data, $type);
		$unpacked = unpack("H*", $frame);
		$this->write($frame);
		$this->writeReady = FALSE;

		if ($callback) {
			$this->callbacks[] = $callback;
		}
		
		return true;
	}

	protected function packFrame(&$data, $type){
		$FRAME = "";
		$octet1 = 0x00;
		// FIN
		if(true) $octet1|=0x80;
		// OPCODE
		$octet1|=$type;
		$FRAME.= pack("c", $octet1);

		$octet2 = 0x00;
		$data_length = strlen($data);
		if($data_length <= 125){
			$octet2|=$data_length;
			$FRAME.= pack("c", $octet2);
		}elseif($data_length < 0xffff){
			$octet2|=126;
			$FRAME.= pack("c", $octet2);
			$FRAME.= pack("n", $data_length);
		}else{
			Daemon::log("Unsupported frame length");
			$this->finish();
			return;
		}
		$FRAME.=$data;
		return $FRAME;
	}

	protected function unPackFrame(){
		$RESULT = array();
		$buff_length = strlen($this->buf);
		$TOTAL_FRAME_LENGTH = 2;
		$format = '1|1|*';
		$stream = Stream::createFrom($this->buf, $format);
		$OPCODE = $stream->get(1)->getRange(5,4);
		$FRAME_TYPE = $OPCODE;
		$MASKED = $stream->get(2)->getBit(1);
		if(!$MASKED) {
			$this->write("HTTP/1.1 1002");
			$this->finish();
			return;
		}
		$PLEN = $stream->get(2)->getRange(2,7);
		$DATA_LENGTH = 0;
		if($PLEN <=125){
			// move to mask
			$stream->next();
			$DATA_LENGTH = $PLEN;
			$MASK = array($stream->next(),$stream->next(),$stream->next(),$stream->next());
			$TOTAL_FRAME_LENGTH+=(4+$DATA_LENGTH);
		}elseif($PLEN == 126){
			$stream->next();
			$length = new Word($stream->next(),$stream->next());
			$DATA_LENGTH = $length->toN();
			$MASK = array($stream->next(),$stream->next(),$stream->next(),$stream->next());
			$TOTAL_FRAME_LENGTH+=(6+$DATA_LENGTH);
		}elseif($PLEN == 127){
			Daemon::log("Not supported frame format");
			$this->finish();
			return;
		}
		
		if($buff_length < ($TOTAL_FRAME_LENGTH)) return false;
		
		$DATA = '';
		for($i=0; $i<$DATA_LENGTH; $i++){
			$byte = $stream->next();
			$byte->makeXor($MASK[$i%4]);
			$DATA.= chr($byte->toN());
		}
		$RESULT['data'] = $DATA;
		$RESULT['type'] = $FRAME_TYPE;
		$RESULT['total_frame_length'] = $TOTAL_FRAME_LENGTH;
		return $RESULT;
	}
}
