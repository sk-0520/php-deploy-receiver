<?php

declare(strict_types=1);

require __DIR__ . '/config.php';

define('HTTP_STATUS_NOT_FOUND', 404);
define('HTTP_STATUS_SERVER_ERROR', 500);
define('HTTP_STATUS_SERVICE_UNAVAIL', 503);

define('SEQUENCE_HELLO', 10);
define('SEQUENCE_INITIALIZE', 20);
define('SEQUENCE_RECEIVE', 30);
define('SEQUENCE_PREPARE', 40);
define('SEQUENCE_UPDATE', 50);

// 長いと暗号化時に死ぬけどチェックしないかんね
define('ACCESS_TOKEN_LENGTH', 48);
define('REQUEST_ID', bin2hex(openssl_random_pseudo_bytes(6)));

define('PARAM_SEQ', 'seq');
define('PARAM_KEY', 'key');
define('PARAM_PUBLIC_KEY', 'pub');
define('PARAM_UPLOAD_FILE', 'file');
define('PARAM_UPLOAD_NUMBER', 'number');
define('PARAM_ALGORITHM', 'algorithm');
define('PARAM_HASH', 'hash');

//###########################################################################
// 共通関数 -------------------------------

function isNullOrEmpty(?string $s): bool
{
	if (is_null($s)) {
		return true;
	}

	if ($s === '0') {
		return false;
	}

	return empty($s);
}

function isNullOrWhiteSpace(?string $s): bool
{
	if (isNullOrEmpty($s)) {
		return true;
	}

	return strlen(trim($s)) === 0;
}

function getAbsolutePath(string $path)
{
	$targetPath = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $path);
	$parts = array_filter(explode(DIRECTORY_SEPARATOR, $targetPath), 'mb_strlen');
	$absolutes = array();
	foreach ($parts as $part) {
		if ($part === '.') {
			continue;
		}
		if ($part === '..') {
			array_pop($absolutes);
		} else {
			$absolutes[] = $part;
		}
	}

	$result = implode(DIRECTORY_SEPARATOR, $absolutes);
	if (mb_strlen($targetPath) && $targetPath[0] === DIRECTORY_SEPARATOR) {
		$result = DIRECTORY_SEPARATOR . $result;
	}

	return $result;
}
/**
 * ファイルパス結合
 *
 * 別リポジトリの PeServer\FileUtility::join が正
 *
 * @param string $basePath ベースパス
 * @param string ...$addPaths 結合するパス
 * @return string 結合されたファイルパス
 */
function joinPath(string $basePath, string ...$addPaths): string
{
	$paths = array_merge([$basePath], array_map(function ($s) {
		return trim($s, '/\\');
	}, $addPaths));
	$paths = array_filter($paths, function ($v, $k) {
		return !isNullOrEmpty($v) && ($k === 0 ? true :  $v !== '/' && $v !== '\\');
	}, ARRAY_FILTER_USE_BOTH);


	$joinedPath = implode(DIRECTORY_SEPARATOR, $paths);
	return getAbsolutePath($joinedPath);
}

function getLogFilePath(): string
{
	$path = joinPath(__DIR__, 'deploy.log');
	return $path;
}

function getRunningFilePath(): string
{
	$path = joinPath(__DIR__, 'running.json');
	return $path;
}

function getReceiveDirectoryPath(): string
{
	$path = joinPath(__DIR__, 'recv');
	return $path;
}

function getExpandDirectoryPath(): string
{
	$path = joinPath(__DIR__, 'expand');
	return $path;
}

function getArchiveFilePath(): string
{
	$path = joinPath(getReceiveDirectoryPath(), '0.zip');
	return $path;
}

function clearLog()
{
	$logFilePath = getLogFilePath();
	if (file_exists($logFilePath)) {
		unlink($logFilePath);
	}
}

function outputLog($message)
{
	$backtrace = debug_backtrace(DEBUG_BACKTRACE_PROVIDE_OBJECT, 1)[0];

	if (is_string($message)) {
		$value = $message;
	} else {
		$value = print_r($message, true);
	}

	$path = getLogFilePath();
	$logItem = sprintf('%s [%s] <%s> %s %s (%d) %s', date('c'), $_SERVER['REMOTE_ADDR'], REQUEST_ID, $_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI'], $backtrace['line'], $value);
	file_put_contents($path, $logItem . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function loadRunningFile(string $filePath): ?array
{
	$content = file_get_contents($filePath);
	if ($content === false) {
		return null;
	}

	return json_decode($content, true);
}

function saveRunningFile(string $runningFilePath, array $runningData)
{
	$jsonString = json_encode($runningData);
	file_put_contents($runningFilePath, $jsonString, LOCK_EX);
}

function isEnabledLifeTime(string $tokenExpiration, array $runningData): bool
{
	$timestamp = new DateTime($runningData['TIMESTAMP']);
	$limitTimestamp = $timestamp->add(new DateInterval($tokenExpiration));
	$nowTimestamp = new DateTime();

	return $nowTimestamp <= $limitTimestamp;
}

function isEnabledToken(string $accessToken, array $runningData): bool
{
	return $accessToken === $runningData['ACCESS_TOKEN'];
}

function exitApp(int $httpStatusCode)
{
	outputLog($httpStatusCode);

	http_response_code($httpStatusCode);

	exit;
}

function exitAppWithMessage(int $httpStatusCode, ?string $content = null)
{
	if (is_null($content)) {
		outputLog($httpStatusCode);
	} else {
		outputLog($httpStatusCode . ': ' . $content);
	}

	http_response_code($httpStatusCode);

	if (!is_null($content)) {
		header('Content-Type: text/plain');
		echo $content;
	}

	exit;
}

function exitOutput(int $httpStatusCode, string $contentType, $content)
{
	outputLog($httpStatusCode);

	http_response_code($httpStatusCode);
	header('Content-Type: ' . $contentType);
	echo $content;
	exit;
}

function removeDirectory(string $directoryPath): void
{
	$files = getChildrenFiles($directoryPath, false);
	foreach ($files as $file) {
		if (is_dir($file)) {
			removeDirectory($file);
		} else {
			unlink($file);
		}
	}
	rmdir($directoryPath);
}

function cleanupDirectory(string $directoryPath): void
{
	if (is_dir($directoryPath)) {
		removeDirectory($directoryPath);
	}
	mkdir($directoryPath, 0777, true);
}

function getChildrenFiles(string $directoryPath, bool $recursive): array
{
	$files = [];
	$items = scandir($directoryPath);
	foreach ($items as $item) {
		if ($item === '.' || $item === '..') {
			continue;
		}
		$path = joinPath($directoryPath, $item);

		if ($recursive && is_dir($path)) {
			$files = array_merge($files, getChildrenFiles($path, $recursive));
		} else {
			$files[] = joinPath($directoryPath, $item);
		}
	}

	return $files;
}

/**
 * なくても動くやん！！
 *
 * xampp環境だと openssl.conf が読み込まれていないのでとりま読み込ます。レンタルサーバー環境では問題ないと思うし、二重に処理しても大丈夫でしょ(知らんけど)
 *
 * @param array $config
 */
function initializeOpenSsl(?array $config): void
{
	/*
	$openssl = openssl_pkey_new($config);
	outputLog($openssl);
	while (($e = openssl_error_string()) !== false) {
		outputLog($e);
	}
	*/
}

/**
 * 暗号化。
 *
 * クライアントの公開鍵を使用してクライアントに渡す暗号データを作成する。
 *
 * @return string 暗号化されたbase64文字列
 */
function encryptPublicKey(string $publicKey, string $source): string
{
	openssl_public_encrypt($source, $rawData, $publicKey);
	return base64_encode($rawData);
}

/**
 * 復号化。
 *
 * 本モジュールが作成した秘密鍵でクライアントから送られてきた暗号データを復号する。
 *
 * @param string $base64Value 暗号化されたbase64文字列
 *
 * @return string 復号された文字列
 */
function decryptPrivateKey(string $privateKey, string $base64Value): string
{
	$encValue = base64_decode($base64Value);
	if (!openssl_private_decrypt($encValue, $rawValue, $privateKey)) {
		throw new Exception(openssl_error_string());
	}
	return $rawValue;
}

// 共通データ -------------------------------
class ScriptArgument
{
	/**
	 * ルートディレクトリパス
	 *
	 * @var string
	 */
	public $rootDirectoryPath;
	/**
	 * 公開ディレクトリパス
	 *
	 * @var string
	 */
	public $publicDirectoryPath;
	/**
	 * 展開ディレクトリパス
	 *
	 * @var string
	 */
	public $expandDirectoryPath;

	public function __construct(string $rootDirectoryPath, string $publicDirectoryPath, string $expandDirectoryPath)
	{
		$this->rootDirectoryPath = $rootDirectoryPath;
		$this->publicDirectoryPath = $publicDirectoryPath;
		$this->expandDirectoryPath = $expandDirectoryPath;
	}

	/**
	 * ログ出力
	 *
	 * @param mixed $message
	 * @return void
	 */
	public function log($message): void
	{
		outputLog($message, 1);
	}

	/**
	 * ファイルパス結合
	 *
	 * @param string $basePath
	 * @param string ...$addPaths
	 * @return string
	 */
	public function joinPath(string $basePath, string ...$addPaths): string
	{
		return joinPath($basePath, ...$addPaths);
	}

	/**
	 * ディレクトリ削除
	 *
	 * @param string $directoryPath
	 * @return void
	 */
	public function removeDirectory(string $directoryPath): void
	{
		removeDirectory($directoryPath);
	}

	/**
	 * ディレクトリの掃除
	 *
	 * @param string $directoryPath
	 * @return void
	 */
	public function cleanupDirectory(string $directoryPath): void
	{
		cleanupDirectory($directoryPath);
	}

	public function backupFiles(string $archiveFilePath, array $paths) {
		$zip = new ZipArchive();
		try {
			$zip->open($archiveFilePath, ZipArchive::CREATE);
			foreach ($paths as $path) {
				$sourcePath = $this->joinPath($this->rootDirectoryPath, $path);
				if(file_exists($path)) {
					if(is_dir($path)) {
						$this->scriptArgument->log('backup: ' . $sourcePath . '/*');
						//TODO
					} else {
						$this->scriptArgument->log('backup: ' . $sourcePath);
						$zip->addFile($sourcePath, $path);
					}
				}
			}
		} finally {
			$zip->close();
		}
	}
}

//###########################################################################
// 各シーケンス -------------------------------
function sequenceHello(array $config)
{
	outputLog('SEQUENCE_HELLO');

	if (!isset($_FILES[PARAM_PUBLIC_KEY])) {
		exitApp(HTTP_STATUS_NOT_FOUND);
	}
	$clientPublicKey = file_get_contents($_FILES[PARAM_PUBLIC_KEY]['tmp_name']);

	initializeOpenSsl($config['OPENSSL']);
	$keyPair = openssl_pkey_new($config['OPENSSL']);
	openssl_pkey_export($keyPair, $selfPrivateKey, NULL, $config['OPENSSL']);
	$details = openssl_pkey_get_details($keyPair);
	$selfPublicKey = $details['key'];

	$runningFilePath = getRunningFilePath();
	$runningData = [
		'TIMESTAMP' => date('c'),
		'ACCESS_TOKEN' => bin2hex(openssl_random_pseudo_bytes(ACCESS_TOKEN_LENGTH)),
		'SEQUENCE' => SEQUENCE_HELLO,
		'KEYS' => [
			'SELF_PUBLIC' => $selfPublicKey,
			'SELF_PRIVATE' => $selfPrivateKey,
			'CLIENT_PUBLIC' => $clientPublicKey,
		],
	];
	saveRunningFile($runningFilePath, $runningData);

	clearLog();
	outputLog('RE:SEQUENCE_HELLO');
	outputLog($runningData);

	$result = implode("\n", [
		'token:' . encryptPublicKey($clientPublicKey, $runningData['ACCESS_TOKEN']),
		'public_key:' . base64_encode($runningData['KEYS']['SELF_PUBLIC']),
	]);

	exitOutput(200, 'text/plain', $result);
}

function sequenceInitialize(array $config, array $runningData)
{
	outputLog('SEQUENCE_INITIALIZE');

	if (!isset($_POST[PARAM_KEY])) {
		exitApp(HTTP_STATUS_NOT_FOUND);
	}
	$encAccessKey = $_POST[PARAM_KEY];

	initializeOpenSsl($config['OPENSSL']);
	$rawAccessKey = decryptPrivateKey($runningData['KEYS']['SELF_PRIVATE'], $encAccessKey);

	if ($config['ACCESS_KEY'] != $rawAccessKey) {
		exitApp(HTTP_STATUS_NOT_FOUND);
	}

	$dirs = [
		getReceiveDirectoryPath(),
		getExpandDirectoryPath(),
	];
	foreach ($dirs as $dir) {
		cleanupDirectory($dir);
	}

	exitOutput(200, 'text/plain', strval(SEQUENCE_INITIALIZE));
}

function sequenceReceive(array $config, array $runningData)
{
	outputLog('SEQUENCE_RECEIVE');

	if (!isset($_POST[PARAM_UPLOAD_NUMBER])) {
		exitAppWithMessage(HTTP_STATUS_SERVER_ERROR, 'ファイル順序未指定');
	}
	$rawNumber = $_POST[PARAM_UPLOAD_NUMBER];
	if (!preg_match('/^\d+$/', $rawNumber)) {
		exitAppWithMessage(HTTP_STATUS_SERVER_ERROR, PARAM_UPLOAD_NUMBER . " が数値ではない: $rawNumber");
	}
	$number = (int)$rawNumber;
	if ($number < 1) {
		exitAppWithMessage(HTTP_STATUS_SERVER_ERROR, PARAM_UPLOAD_NUMBER . " は1始まり: $number");
	}

	if (!isset($_FILES[PARAM_UPLOAD_FILE])) {
		exitAppWithMessage(HTTP_STATUS_SERVER_ERROR, 'ファイル未指定');
	}

	$recvDirPath = getReceiveDirectoryPath();
	$recvFilePath = joinPath($recvDirPath, sprintf('%08d.part', $number));
	$tempFilePath = $_FILES[PARAM_UPLOAD_FILE]['tmp_name'];

	outputLog('part: ' . $tempFilePath);
	outputLog('name: ' . $_FILES[PARAM_UPLOAD_FILE]['name']);
	outputLog('size: ' . $_FILES[PARAM_UPLOAD_FILE]['size']);
	outputLog('error: ' . $_FILES[PARAM_UPLOAD_FILE]['error']);

	copy($tempFilePath, $recvFilePath);
}

function sequencePrepare(array $config, array $runningData)
{
	outputLog('SEQUENCE_PREPARE');

	//TODO: ハッシュ突合確認
	if (!isset($_POST[PARAM_ALGORITHM])) {
		exitAppWithMessage(HTTP_STATUS_SERVER_ERROR, 'アルゴリズム未指定');
	}
	$algorithm = $_POST[PARAM_ALGORITHM];
	outputLog('algorithm: ' . $algorithm);

	if (!isset($_POST[PARAM_HASH])) {
		exitAppWithMessage(HTTP_STATUS_SERVER_ERROR, 'ハッシュ値未指定');
	}
	$hashValue = $_POST[PARAM_HASH];
	outputLog('hashValue: ' . $hashValue);

	outputLog('受信ファイル結合');

	$recvDirPath = getReceiveDirectoryPath();
	$pattern = joinPath($recvDirPath, '*.part');
	$recvFilePaths = glob($pattern);

	$archiveFilePath = getArchiveFilePath();
	$stream = fopen($archiveFilePath, "wb");
	foreach ($recvFilePaths as $recvFilePath) {
		outputLog('part: ' . $recvFilePath);
		$recvFileData = file_get_contents($recvFilePath);
		fwrite($stream, $recvFileData);
	}
	fclose($stream);

	outputLog('name: ' . $archiveFilePath);
	outputLog('size: ' . filesize($archiveFilePath));
	outputLog('size: ' . filesize($archiveFilePath));

	$fileHashValue = hash_file($algorithm, $archiveFilePath);
	outputLog('hash: ' . $fileHashValue);

	if (strcasecmp($hashValue, $fileHashValue)) {
		exitAppWithMessage(HTTP_STATUS_SERVER_ERROR, 'ハッシュ値が合わない');
	}

	outputLog('アーカイブ展開');

	$expandDirPath = getExpandDirectoryPath();
	$zip = new ZipArchive();
	$zip->open($archiveFilePath);
	$zip->extractTo($expandDirPath);
	$zip->close();

	$expandFilePaths = getChildrenFiles($expandDirPath, true);
	foreach ($expandFilePaths as $expandFilePath) {
		outputLog('path: ' . $expandFilePath);
		outputLog('size: ' . filesize($expandFilePath));
	}
}

function sequenceUpdate(array $config, array $runningData)
{
	outputLog('SEQUENCE_UPDATE');

	if (!isset($_POST[PARAM_KEY])) {
		exitAppWithMessage(HTTP_STATUS_SERVER_ERROR, 'アクセスキー未指定');
	}
	$encAccessKey = $_POST[PARAM_KEY];

	initializeOpenSsl($config['OPENSSL']);
	$rawAccessKey = decryptPrivateKey($runningData['KEYS']['SELF_PRIVATE'], $encAccessKey);

	if ($config['ACCESS_KEY'] != $rawAccessKey) {
		exitAppWithMessage(HTTP_STATUS_SERVER_ERROR, 'アクセスキー不正');
	}

	$expandDirPath = getExpandDirectoryPath();
	$expandFilePaths = getChildrenFiles($expandDirPath, true);
	$expandFileRelativePaths = array_map(function ($i) use ($expandDirPath) {
		outputLog('UPDATE: ' . $i);
		return mb_substr($i, mb_strlen($expandDirPath) + 1);
	}, $expandFilePaths);

	// ユーザースクリプト用データ
	$scriptArgument = new ScriptArgument($config['ROOT_DIR_PATH'], joinPath($config['ROOT_DIR_PATH'], $config['PUBLIC_DIR']), getExpandDirectoryPath());
	// 前処理スクリプトの実施
	$beforeScriptPath = joinPath(getExpandDirectoryPath(), $config['BEFORE_SCRIPT']);
	if (is_file($beforeScriptPath)) {
		outputLog('beforeScriptPath: ' . $beforeScriptPath);
		require_once $beforeScriptPath;
		call_user_func('before_update', $scriptArgument);
	}

	//TODO: .htaccess 制御

	$skipFiles = [];

	// ファイル置き換え
	foreach ($expandFileRelativePaths as $expandFileRelativePath) {
		if ($config['SERVER'] === 'apache') {
			$fileName = basename($expandFileRelativePath);
			if ($fileName === '.htaccess') {
				$skipFiles[] = $expandFileRelativePath;
				continue;
			}
		}
		$src = joinPath($expandDirPath, $expandFileRelativePath);
		if (is_dir($src)) {
			continue;
		}
		$dst = joinPath($config['ROOT_DIR_PATH'], $config['PUBLIC_DIR'], $expandFileRelativePath);
		$dir = dirname($dst);
		if (!is_dir($dir)) {
			mkdir($dir, 0777, true);
		}
		copy($src, $dst);
	}

	// 後処理スクリプトの実施
	$afterScriptPath = joinPath(getExpandDirectoryPath(), $config['AFTER_SCRIPT']);
	if (is_file($afterScriptPath)) {
		outputLog('afterScriptPath: ' . $afterScriptPath);
		require_once $afterScriptPath;
		call_user_func('after_update', $scriptArgument);
	}

	// 退避ファイル補正
	foreach ($skipFiles as $skipFile) {
		$src = joinPath($expandDirPath, $skipFile);
		$dst = joinPath($config['ROOT_DIR_PATH'], $config['PUBLIC_DIR'], $skipFile);
		copy($src, $dst);
	}

	// 実行ファイル破棄
	unlink(getRunningFilePath());
}

//###########################################################################
// こっから動くのだ -------------------------------
function main()
{
	outputLog('START');
	try {
		$config = getConfig();

		if (!isset($_POST[PARAM_SEQ])) {
			outputLog(PARAM_SEQ . ' 未設定');
			exitApp(HTTP_STATUS_NOT_FOUND);
		}

		$rawSeq = $_POST['seq'];
		if (!preg_match('/^\d+$/', $rawSeq)) {
			outputLog(PARAM_SEQ . " が数値ではない: $rawSeq");
			exitApp(HTTP_STATUS_NOT_FOUND);
		}
		$seq = (int)$rawSeq;
		if (!in_array($seq, [SEQUENCE_HELLO, SEQUENCE_INITIALIZE, SEQUENCE_RECEIVE, SEQUENCE_PREPARE, SEQUENCE_UPDATE])) {
			outputLog(PARAM_SEQ . " が定義済みシーケンス値ではない: $seq");
			exitApp(HTTP_STATUS_NOT_FOUND);
		}

		try {
			$runningFilePath = getRunningFilePath();

			if ($seq == SEQUENCE_HELLO) {
				if (file_exists($runningFilePath)) {
					$helloRunningData = loadRunningFile($runningFilePath);
					$enabledLifeTime = isEnabledLifeTime($config['TOKEN_EXPIRATION'], $helloRunningData);
					if ($enabledLifeTime) {
						outputLog('初回シーケンスだが有効な実行中ファイルが存在する');
						exitApp(HTTP_STATUS_NOT_FOUND);
					}
				}
				sequenceHello($config);
			}

			$runningData = loadRunningFile($runningFilePath);

			if (is_null($runningData)) {
				exitApp(HTTP_STATUS_NOT_FOUND);
			}

			if ($seq != SEQUENCE_INITIALIZE) {
				$authHeader = $config['AUTH_HEADER'];
				if (!isset($_SERVER[$authHeader])) {
					outputLog("トークンヘッダ($authHeader)未設定");
					exitApp(HTTP_STATUS_NOT_FOUND);
				}
				$enabledLifeTime = isEnabledLifeTime($config['TOKEN_EXPIRATION'], $runningData);
				if (!$enabledLifeTime) {
					outputLog('無効な実行中ファイルが存在する');
					exitApp(HTTP_STATUS_NOT_FOUND);
				}
				$enabledToken = isEnabledToken(trim($_SERVER[$authHeader]), $runningData);
				if (!$enabledToken) {
					outputLog("トークン無効($authHeader): $_SERVER[$authHeader]");
					exitApp(HTTP_STATUS_NOT_FOUND);
				}
			}

			switch ($seq) {
				case SEQUENCE_INITIALIZE:
					sequenceInitialize($config, $runningData);
					break;

				case SEQUENCE_RECEIVE:
					sequenceReceive($config, $runningData);
					break;

				case SEQUENCE_PREPARE:
					sequencePrepare($config, $runningData);
					break;

				case SEQUENCE_UPDATE:
					sequenceUpdate($config, $runningData);
					break;

				default:
					throw new Exception('謎シーケンス: ' . PARAM_SEQ);
			}
		} catch (Exception $ex) {
			outputLog($ex);
			exitApp(HTTP_STATUS_NOT_FOUND);
		}
	} finally {
		outputLog('END');
	}
}

main();
