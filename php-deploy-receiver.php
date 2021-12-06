<?php

declare(strict_types=1);

require __DIR__ . '/config.php';

define('SEQUENCE_INITIALIZE', 10);
define('SEQUENCE_RECEIVE', 20);
define('SEQUENCE_PREPARE', 30);
define('SEQUENCE_UPDATE', 40);

define('REQUEST_ID', bin2hex(openssl_random_pseudo_bytes(6)));

define('PARAM_SEQ', 'seq');
define('PARAM_UPLOAD_FILE', 'file');
define('PARAM_UPLOAD_NUMBER', 'number');

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

function clearLog()
{
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

function isEnabledToken(string $accessToken, string $tokenExpiration, array $runningData): bool
{
	if ($accessToken != $runningData['ACCESS_TOKEN']) {
		return false;
	}

	$timestamp = new DateTime($runningData['TIMESTAMP']);
	$limitTimestamp = $timestamp->add(new DateInterval($tokenExpiration));
	$nowTimestamp = new DateTime();

	return $nowTimestamp <= $limitTimestamp;
}

function exitApp(int $httpStatusCode)
{
	outputLog($httpStatusCode);

	http_response_code($httpStatusCode);
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

function removeDirectory($directoryPath)
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

// 各シーケンス -------------------------------
function sequenceInitialize(array $config)
{
	outputLog('SEQUENCE_INITIALIZE');

	//TODO: アクセスキー確認

	$recvDirPath = getReceiveDirectoryPath();
	if (is_dir($recvDirPath)) {
		removeDirectory($recvDirPath);
	}
	mkdir($recvDirPath, 0777, true);

	$runningFilePath = getRunningFilePath();
	$runningData = [
		'TIMESTAMP' => date('c'),
		//'ACCESS_TOKEN' => bin2hex(openssl_random_pseudo_bytes(64)),
		'ACCESS_TOKEN' => 'TEST',
		'SEQUENCE' => SEQUENCE_INITIALIZE,
	];

	$jsonString = json_encode($runningData);
	file_put_contents($runningFilePath, $jsonString, LOCK_EX);

	exitOutput(200, 'application/json', $jsonString);
}

function sequenceReceive(array $config, array $runningData)
{
	outputLog('SEQUENCE_RECEIVE');

	if (!isset($_POST[PARAM_UPLOAD_NUMBER])) {
		outputLog('ファイル順序未指定');
		exitApp(400);
	}
	$rawNumber = $_POST[PARAM_UPLOAD_NUMBER];
	if (!preg_match('/^\d+$/', $rawNumber)) {
		outputLog(PARAM_UPLOAD_NUMBER . " が数値ではない: $rawNumber");
		exitApp(404);
	}
	$number = (int)$rawNumber;
	if($number < 1) {
		outputLog(PARAM_UPLOAD_NUMBER . " は1始まり: $number");
		exitApp(404);
	}

	if (!isset($_FILES[PARAM_UPLOAD_FILE])) {
		outputLog('ファイル未指定');
		exitApp(400);
	}

	$recvDirPath = getReceiveDirectoryPath();
	$recvFilePath = joinPath($recvDirPath, "$number.part");
	$tempFilePath = $_FILES[PARAM_UPLOAD_FILE]['tmp_name'];

	copy($tempFilePath, $recvFilePath);

}

function sequencePrepare(array $config, array $runningData)
{
	outputLog('SEQUENCE_PREPARE');
}

function sequenceUpdate(array $config, array $runningData)
{
	outputLog('SEQUENCE_UPDATE');
}

// こっから動くのだ -------------------------------
function main()
{
	outputLog('START');
	try {
		$config = getConfig();

		if (!isset($_POST[PARAM_SEQ])) {
			outputLog(PARAM_SEQ . ' 未設定');
			exitApp(404);
		}

		$rawSeq = $_POST['seq'];
		if (!preg_match('/^\d+$/', $rawSeq)) {
			outputLog(PARAM_SEQ . " が数値ではない: $rawSeq");
			exitApp(404);
		}
		$seq = (int)$rawSeq;
		if (!in_array($seq, [SEQUENCE_INITIALIZE, SEQUENCE_RECEIVE, SEQUENCE_PREPARE, SEQUENCE_UPDATE])) {
			outputLog(PARAM_SEQ . " が定義済みシーケンス値ではない: $seq");
			exitApp(404);
		}

		try {
			$runningFilePath = getRunningFilePath();

			if ($seq == SEQUENCE_INITIALIZE) {
				if (file_exists($runningFilePath)) {
					outputLog('初期化シーケンスだが実行中ファイルが存在する');
					exitApp(404);
				}
				sequenceInitialize($config);
			}

			$runningData = loadRunningFile($runningFilePath);
			if (is_null($runningData)) {
				exitApp(404);
			}

			$authHeader = 'HTTP_' . $config['AUTH_HEADER'];
			if (!isset($_SERVER[$authHeader])) {
				outputLog("トークンヘッダ($authHeader)未設定");
				exitApp(404);
			}
			$enabledToken = isEnabledToken(trim($_SERVER[$authHeader]), $config['TOKEN_EXPIRATION'], $runningData);
			if (!$enabledToken) {
				outputLog("トークン無効($authHeader): $_SERVER[$authHeader]");
				exitApp(404);
			}

			switch ($seq) {
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
					throw new Exception('謎' . PARAM_SEQ);
			}
		} catch (Exception $ex) {
			outputLog($ex);
			exitApp(404);
		}
	} finally {
		outputLog('END');
	}
}

main();
