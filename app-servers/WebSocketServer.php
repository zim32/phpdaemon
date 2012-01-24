<?php

/**
 * @package Applications
 * @subpackage WebSocketServer
 *
 * @author Zorin Vasily <kak.serpom.po.yaitsam@gmail.com>
 */
class WebSocketServer extends AsyncServer {

	public $sessions = array();
	public $routes = array();

	const BINARY = 0x80;
	const STRING = 0x00;

	/**
	 * Setting default config options
	 * Overriden from AppInstance::getConfigDefaults
	 * @return array|false
	 */
	protected function getConfigDefaults() {
		return array(
			// listen to
			'listen'     => 'tcp://0.0.0.0',
			// listen port
			'listenport' => 8047,
			// max allowed packet size
			'maxallowedpacket' => new Daemon_ConfigEntrySize('16k'),
			// disabled by default
			'enable'     => 0
		);
	}

	/**
	 * Event of appInstance. Adds default settings and binds sockets.
	 * @return void
	 */
	public function init() {
		$this->update();
		
		if ($this->config->enable->value) {
			$this->bindSockets(
				$this->config->listen->value,
				$this->config->listenport->value
			);
		}
	}
	
	/**
	 * Called when a request to HTTP-server looks like WebSocket handshake query.
	 * @return void
	 */
	public function inheritFromRequest($req, $appInstance) {
		$connId = $req->attrs->connId;
		
		unset(Daemon::$process->queue[$connId . '-' . $req->attrs->id]);
		
		$this->buf[$connId] = $appInstance->buf[$connId];
		
		unset($appInstance->buf[$connId]);
		unset($appInstance->poolState[$connId]);
		
		$set = event_buffer_set_callback(
			$this->buf[$connId], 
			$this->directReads ? NULL : array($this, 'onReadEvent'),
			array($this, 'onWriteEvent'),
			array($this, 'onFailureEvent'),
			array($connId)
		);
		
		unset(Daemon::$process->readPoolState[$connId]);
		
		$this->poolState[$connId] = array();
		
		$this->sessions[$connId] = new WebSocketSession($connId, $this);
		$this->sessions[$connId]->clientAddr = $req->attrs->server['REMOTE_ADDR'];
		$this->sessions[$connId]->server = $req->attrs->server;
		$this->sessions[$connId]->firstline = TRUE;
		$this->sessions[$connId]->stdin("\r\n" . $req->attrs->inbuf);
	}

	/**
	 * Adds a route if it doesn't exist already.
	 * @param string Route name.
	 * @param mixed Route's callback.
	 * @return boolean Success.
	 */
	public function addRoute($route, $cb) {
		if (isset($this->routes[$route])) {
			Daemon::log(__METHOD__ . ' Route \'' . $route . '\' is already taken.');
			return FALSE;
		}
		
		$this->routes[$route] = $cb;

		return TRUE;
	}
	
	/**
	 * Force add/replace a route.
	 * @param string Route name.
	 * @param mixed Route's callback.
	 * @return boolean Success.
	 */
	public function setRoute($route, $cb) {
		$this->routes[$route] = $cb;
	
		return TRUE;
	}
	
	/**
	 * Removes a route.
	 * @param string Route name.
	 * @return boolean Success.
	 */
	public function removeRoute($route) {
		if (!isset($this->routes[$route])) {
			return FALSE;
		}

		unset($this->routes[$route]);

		return TRUE;
	}
	
	/**
	 * Event of appInstance.
	 * @return void
	 */
	public function onReady() {
		if ($this->config->enable->value) {
			$this->enableSocketEvents();
		}
	}

	/**
	 * Event of asyncServer
	 * @param integer Connection's ID
	 * @param string Peer's address
	 * @return void
	 */
	protected function onAccepted($connId, $addr) {
		$this->sessions[$connId] = new Zim32WebSocketSession($connId, $this);
		$this->sessions[$connId]->clientAddr = $addr;
	}
	
}

class WebSocketSession extends SocketSession {
	
	public $secprotocol;
	public $resultKey;
	public $handshaked = FALSE;
	public $upstream;
	public $server = array();
	public $cookie = array();
	public $firstline = FALSE;
	public $writeReady = TRUE;
	public $callbacks = array();
	
	/**
	 * Sends a frame.
	 * @param string Frame's data.
	 * @param integer Frame's type. See the constants.
	 * @param callback Optional. Callback called when the frame is received by client.
	 * @return boolean Success.
	 */
	public function sendFrame($data, $type = 0x00, $callback = NULL) {
		if (!$this->handshaked) {
			return FALSE;
		}

		if (($type & 0x80) === 0x80) {
			$n = strlen($data);
			$len = '';
			$pos = 0;

			char:

			++$pos;
			$c = $n >> 0 & 0x7F;
			$n = $n >> 7;

			if ($pos != 1) {
				$c += 0x80;
			}
			
			if ($c != 0x80) {
				$len = chr($c) . $len;
				goto char;
			};
			
			$this->write("\x80" . $len . $data);
		} else {
			$this->write("\x00" . $data . "\xFF");
		}

		$this->writeReady = FALSE;

		if ($callback) {
			$this->callbacks[] = $callback;
		}

		return TRUE;
	}

	/**
	 * Event of SocketSession (asyncServer).
	 * @return void
	 */
	public function onFinish() {
		if (Daemon::$config->logevents->value) {
			Daemon::log(__METHOD__ . ' invoked');
		}
		
		if (isset($this->upstream)) {
			$this->upstream->onFinish();
		}
		
		unset($this->upstream);
		unset($this->appInstance->sessions[$this->connId]);
	}
	
	/**
	 * Called when new frame received.
	 * @param string Frame's data.
	 * @param integer Frame's type.
	 * @return boolean Success.
	 */
	public function onFrame($data, $type) {
		if (!isset($this->upstream)) {
			return FALSE;
		}

		$this->upstream->onFrame($data, $type);

		return TRUE;
	}
	
	/**
	 * Called when the connection is ready to accept new data.
	 * @return void
	 */
	public function onWrite() {
		$this->writeReady = TRUE;
		
		for ($i = 0, $s = sizeof($this->callbacks); $i < $s; ++$i) {
			call_user_func(array_shift($this->callbacks), $this);
		}
		
		if (is_callable(array($this->upstream, 'onWrite'))) {
			$this->upstream->onWrite();
		}
	}
	
	/**
	 * Called when the connection is handshaked.
	 * @return void
	 */
	public function onHandshake() {
		$e = explode('/', $this->server['DOCUMENT_URI']);
		$appName = isset($e[1])?$e[1]:'';

		if (!isset($this->appInstance->routes[$appName])) {
			if (Daemon::$config->logerrors->value) {
				Daemon::log(__METHOD__ . ': undefined route \'' . $appName . '\'.');
			}
		
			return FALSE;
		}
		
		if (!$this->upstream = call_user_func($this->appInstance->routes[$appName], $this)) {
			return FALSE;
		}
		
		return TRUE;
	}
	
	/**
	 * Event of SocketSession (AsyncServer). Called when the worker is going to shutdown.
	 * @return boolean Ready to shutdown?
	 */
	public function gracefulShutdown() {
		if (
			(!$this->upstream) 
			|| $this->upstream->gracefulShutdown()
		) {
			$this->finish();

			return TRUE;
		}

		return FALSE;
	}

	/**
	 * Called when we're going to handshake.
	 * @return void
	 */
	public function handshake() {
		$this->handshaked = TRUE;
		
		if ($this->onHandshake()) {
			if (!isset($this->server['HTTP_ORIGIN'])) {
				$this->server['HTTP_ORIGIN'] = '';
			}
			
			$reply = "HTTP/1.1 101 Web Socket Protocol Handshake\r\n"
				. "Upgrade: WebSocket\r\n"
				. "Connection: Upgrade\r\n"
				. ($this->secprotocol ? 'Sec-' : '') . 'WebSocket-Origin: ' . $this->server['HTTP_ORIGIN'] . "\r\n"
				. ($this->secprotocol ? 'Sec-' : '') . 'WebSocket-Location: ws://' . $this->server['HTTP_HOST'] . $this->server['REQUEST_URI'] . "\r\n";

			if (isset($this->server['HTTP_' . ($this->secprotocol ? 'SEC_' : '') . 'WEBSOCKET_PROTOCOL'])) {
				$reply .= ($this->secprotocol ? 'Sec-' : '') . 'WebSocket-Protocol: ' . $this->server['HTTP_' . ($this->secprotocol ? 'SEC_' : '') . 'WEBSOCKET_PROTOCOL'] . "\r\n";
			}

			$reply .= "\r\n";
			$reply .= $this->resultKey;
			$this->write($reply);

			if (is_callable(array($this->upstream, 'onHandshake'))) {
				$this->upstream->onHandshake();
			}
		} else {
			$this->finish();
		}
	}
	
	/**
	 * Computes key for Sec-WebSocket.
	 * @param string Key
	 * @return string Result
	 */
	public function computeKey($key) {
		$spaces = 0;
		$digits = '';
	
		for ($i = 0, $s = strlen($key); $i < $s; ++$i) {
			$c = binarySubstr($key, $i, 1);

			if ($c === "\x20") {
				++$spaces;
			}
			elseif (ctype_digit($c)) {
				$digits .= $c;
			}
		}
		
		if ($spaces > 0) {
			$result = (float) floor($digits / $spaces);
		} else {
			$result = (float) $digits;
		}
		
		return pack('N', $result);
	}
	
	/**
	 * Event of SocketSession (AsyncServer). Called when new data received.
	 * @param string New received data.
	 * @return void
	 */
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
						|| ($this->server['HTTP_CONNECTION'] !== 'Upgrade') 
						|| !isset($this->server['HTTP_UPGRADE']) 
						|| ($this->server['HTTP_UPGRADE'] !== 'WebSocket')
					) {
						$this->finish();
						return;
					}

					if (isset($this->server['HTTP_COOKIE'])) {
						HTTPRequest::parse_str(strtr($this->server['HTTP_COOKIE'], HTTPRequest::$hvaltr), $this->cookie);
					}

					if (!$this->secprotocol = (
						isset($this->server['HTTP_SEC_WEBSOCKET_KEY1']) 
						&& isset($this->server['HTTP_SEC_WEBSOCKET_KEY2']))
					) {
						$this->handshake();
					}

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
				$frametype = ord(binarySubstr($this->buf, 0, 1));

				if (($frametype & 0x80) === 0x80) {
					$len = 0;
					$i = 0;

					do {
						$b = ord(binarySubstr($this->buf, ++$i, 1));
						$n = $b & 0x7F;
						$len *= 0x80;
						$len += $n;
					} while ($b > 0x80);

					if ($this->appInstance->config->maxallowedpacket->value <= $len) {
						// Too big packet
						$this->finish();
						return;
					}

					if ($buflen < $len + 2) {
						// not enough data yet
						return;
					} 
					
					$data = binarySubstr($this->buf, 2, $len);
					$this->buf = binarySubstr($this->buf, 2 + $len);
					$this->onFrame($data, $frametype);
				} else {
					if (($p = strpos($this->buf, "\xFF")) !== FALSE) {
						if ($this->appInstance->config->maxallowedpacket->value <= $p - 1) {
							// Too big packet
							$this->finish();
							return;
						}
						
						$data = binarySubstr($this->buf,1,$p-1);
						$this->buf = binarySubstr($this->buf,$p+1);
						$this->onFrame($data,$frametype);
					} else {
						// not enough data yet
						if ($this->appInstance->config->maxallowedpacket->value <= strlen($this->buf)) {
							// Too big packet
							$this->finish();
						}

						return;
					}
				}
			}
		}
		elseif ($this->secprotocol) {
			if (strlen($this->buf) >= 8) {
				$bodyData = binarySubstr($this->buf, 0, 8);
			
				$this->resultKey = md5(
					$this->computeKey($this->server['HTTP_SEC_WEBSOCKET_KEY1'])
					. $this->computeKey($this->server['HTTP_SEC_WEBSOCKET_KEY2'])
					. $bodyData, TRUE
				);

				$this->buf = binarySubstr($this->buf,8);
				$this->handshake();
			}
		}
	}
	
}
