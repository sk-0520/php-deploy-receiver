<?php

declare(strict_types=1);

require __DIR__ . '/config.php';

define('SEQUENCE_INITIALIZE', 10);
define('SEQUENCE_RECEIVE', 20);
define('SEQUENCE_PREPARE', 30);
define('SEQUENCE_UPDATE', 40);

define('REQUEST_ID', bin2hex(openssl_random_pseudo_bytes(6)));


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

function clearLog()
{

}

function outputLog($message)
{
	$backtrace = debug_backtrace(DEBUG_BACKTRACE_PROVIDE_OBJECT, 1)[0];

	if(is_string($message)) {
		$value = $message;
	} else {
		$value = print_r($message, true);
	}

	$path = getLogFilePath();
	$logItem = sprintf('%s <%s> %s->%s [%s] (%d) %s', date('c'), REQUEST_ID, $_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI'], $_SERVER['REMOTE_ADDR'], $backtrace['line'], $value);
	file_put_contents($path, $logItem . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function getRunningFilePath(): string
{
	$path = joinPath(__DIR__, 'running.json');
	return $path;
}

function loadRunningFile(string $filePath): ?array
{
	$content = file_get_contents($filePath);
	if ($content === false) {
		return null;
	}

	return json_decode($content, true);
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

// 各シーケンス -------------------------------
function sequenceInitialize()
{
	outputLog('SEQUENCE_INITIALIZE');

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

function sequenceReceive()
{
	outputLog('SEQUENCE_RECEIVE');
}

function sequencePrepare()
{
	outputLog('SEQUENCE_PREPARE');
}

function sequenceUpdate()
{
	outputLog('SEQUENCE_UPDATE');
}

// こっから動くのだ -------------------------------
function main()
{
	outputLog('START');

	if (!isset($_POST['seq'])) {
		exitApp(404);
	}

	$rawSeq = $_POST['seq'];
	if(!preg_match('/^\d+$/', $rawSeq)) {
		exitApp(404);
	}
	$seq = (int)$rawSeq;
	if(!in_array($seq, [SEQUENCE_INITIALIZE, SEQUENCE_RECEIVE, SEQUENCE_PREPARE, SEQUENCE_UPDATE])) {
		exitApp(404);
	}

	try {
		$runningFilePath = getRunningFilePath();

		if($seq == SEQUENCE_INITIALIZE) {
			if(file_exists($runningFilePath)) {
				exitApp(404);
			}
			sequenceInitialize();
		}

		$runningData = loadRunningFile($runningFilePath);


	} catch (Exception $ex) {
		exitApp(404);
	}
}

main();
