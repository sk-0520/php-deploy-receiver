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

define('ACCESS_TOKEN_LENGTH', 128);
define('REQUEST_ID', bin2hex(openssl_random_pseudo_bytes(6)));

define('PARAM_SEQ', 'seq');
define('PARAM_PUBLIC_KEY', 'pub');
define('PARAM_UPLOAD_FILE', 'file');
define('PARAM_UPLOAD_NUMBER', 'number');
define('PARAM_ALGORITHM', 'algorithm');
define('PARAM_HASH', 'hash');

//###########################################################################
// 共通関数 -------------------------------
function joinPath(string $basePath, string ...$addPaths): string
{
	$paths = array_merge([$basePath], $addPaths);

	$joinedPath = implode(DIRECTORY_SEPARATOR, $paths);
	return $joinedPath;
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
	$logItem = sprintf('%s <%s> %s->%s [%s] (%d) %s', date('c'), REQUEST_ID, $_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI'], $_SERVER['REMOTE_ADDR'], $backtrace['line'], $value);
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
	if (mb_substr($directoryPath, mb_strlen($directoryPath) - 1, 1) != DIRECTORY_SEPARATOR) {
		$directoryPath .= DIRECTORY_SEPARATOR;
	}
	$files = glob($directoryPath . '*', GLOB_MARK);
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

function getChildrenFiles(string $directoryPath): array
{
	$files = [];
	$items = scandir($directoryPath);
	foreach ($items as $item) {
		if ($item === '.' || $item === '..') {
			continue;
		}
		$path = joinPath($directoryPath, $item);

		if (is_dir($path)) {
			$files = array_merge($files, getChildrenFiles($path));
		} else {
			$files[] = joinPath($directoryPath, $item);
		}
	}

	return $files;
}

//###########################################################################
// 各シーケンス -------------------------------
function sequenceHello(array $config)
{
	outputLog('SEQUENCE_HELLO');

	if (!isset($_FILES[PARAM_PUBLIC_KEY])) {
		exitApp(HTTP_STATUS_NOT_FOUND);
	}
	$client_public_key = file_get_contents($_FILES[PARAM_PUBLIC_KEY]['tmp_name']);

	$key_pair = is_null($config['OPENSSL'])
		? openssl_pkey_new()
		: openssl_pkey_new($config['OPENSSL']);
	openssl_pkey_export($key_pair, $self_private_key);
	$details = openssl_pkey_get_details($key_pair);
	$self_public_key = $details['key'];

	$runningFilePath = getRunningFilePath();
	$runningData = [
		'TIMESTAMP' => date('c'),
		//'ACCESS_TOKEN' => bin2hex(openssl_random_pseudo_bytes(ACCESS_TOKEN_LENGTH)),
		'ACCESS_TOKEN' => 'TEST',
		'SEQUENCE' => SEQUENCE_HELLO,
		'KEYS' => [
			'SELF_PUBLIC' => $self_public_key,
			'SELF_PRIVATE' => $self_private_key,
			'CLIENT_PUBLIC' => $client_public_key,
		],
	];
	saveRunningFile($runningFilePath, $runningData);

	clearLog();
	outputLog('RE:SEQUENCE_HELLO');
	outputLog($runningData);

	exitOutput(200, 'application/json', json_encode([
		'token' => $runningData['ACCESS_TOKEN'],
		'public_key' => $runningData['KEYS']['SELF_PUBLIC'],
	]));
}

function sequenceInitialize(array $config, array $runningData)
{
	outputLog('SEQUENCE_INITIALIZE');

	//TODO: アクセスキー確認

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

	outputLog('アーカイブ展開');

	$expandDirPath = getExpandDirectoryPath();
	$zip = new ZipArchive();
	$zip->open($archiveFilePath);
	$zip->extractTo($expandDirPath);
	$zip->close();

	$expandFilePaths = getChildrenFiles($expandDirPath);
	foreach ($expandFilePaths as $expandFilePath) {
		outputLog('path: ' . $expandFilePath);
		outputLog('size: ' . filesize($expandFilePath));
	}
}

function sequenceUpdate(array $config, array $runningData)
{
	outputLog('SEQUENCE_UPDATE');

	$expandDirPath = getExpandDirectoryPath();
	$expandFilePaths = getChildrenFiles($expandDirPath);
	$expandFileRelativePaths = array_map(function ($i) use ($expandDirPath) {
		outputLog('UPDATE: '. $i);
		return mb_substr($i, mb_strlen($expandDirPath) + 1);
	}, $expandFilePaths);

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
		$dst = joinPath($config['PUBLIC_DIR_PATH'], $expandFileRelativePath);
		$dir = dirname($dst);
		if (!is_dir($dir)) {
			mkdir($dir, 0777, true);
		}
		copy($src, $dst);
	}

	// 退避ファイル補正
	foreach ($skipFiles as $skipFile) {
		$src = joinPath($expandDirPath, $skipFile);
		$dst = joinPath($config['PUBLIC_DIR_PATH'], $skipFile);
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
