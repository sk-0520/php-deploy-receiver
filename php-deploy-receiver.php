<?php

declare(strict_types=1);

namespace Deploy;

use \DateTime;
use \DateInterval;
use \ZipArchive;
use \Exception;
use \Error;
use \Throwable;

require __DIR__ . '/config.php';

const HTTP_STATUS_NOT_FOUND = 404;
const HTTP_STATUS_SERVER_ERROR = 500;
const HTTP_STATUS_SERVICE_UNAVAIL = 503;

const SEQUENCE_HELLO = 10;
const SEQUENCE_INITIALIZE = 20;
const SEQUENCE_RECEIVE = 30;
const SEQUENCE_PREPARE = 40;
const SEQUENCE_UPDATE = 50;

// 長いと暗号化時に死ぬけどチェックしないかんね
const ACCESS_TOKEN_LENGTH = 48;
define('DEPLOY_REQUEST_ID', bin2hex(openssl_random_pseudo_bytes(6)));

const PARAM_SEQ = 'seq';
const PARAM_KEY = 'key';
const PARAM_PUBLIC_KEY = 'pub';
const PARAM_UPLOAD_FILE = 'file';
const PARAM_UPLOAD_NUMBER = 'number';
const PARAM_ALGORITHM = 'algorithm';
const PARAM_HASH = 'hash';

//###########################################################################

function getLogFilePath(): string
{
	$path = FileUtility::joinPath(__DIR__, 'deploy.log');
	return $path;
}

function getRunningFilePath(): string
{
	$path = FileUtility::joinPath(__DIR__, 'running.json');
	return $path;
}

function getReceiveDirectoryPath(): string
{
	$path = FileUtility::joinPath(__DIR__, 'recv');
	return $path;
}

function getExpandDirectoryPath(): string
{
	$path = FileUtility::joinPath(__DIR__, 'expand');
	return $path;
}

function getArchiveFilePath(): string
{
	$path = FileUtility::joinPath(getReceiveDirectoryPath(), '0.zip');
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
	$logItem = sprintf('%s [%s] <%s> %s %s (%d) %s', date('c'), $_SERVER['REMOTE_ADDR'], DEPLOY_REQUEST_ID, $_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI'], $backtrace['line'], $value);
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
	/**
	 * 設定
	 */
	public $config;

	public function __construct(string $rootDirectoryPath, string $publicDirectoryPath, string $expandDirectoryPath, array $config)
	{
		$this->rootDirectoryPath = $rootDirectoryPath;
		$this->publicDirectoryPath = $publicDirectoryPath;
		$this->expandDirectoryPath = $expandDirectoryPath;
		$this->config = $config;
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
		return FileUtility::joinPath($basePath, ...$addPaths);
	}

	/**
	 * ディレクトリ削除
	 *
	 * @param string $directoryPath
	 * @return void
	 */
	public function removeDirectory(string $directoryPath): void
	{
		FileUtility::removeDirectory($directoryPath);
	}

	/**
	 * ディレクトリの掃除
	 *
	 * @param string $directoryPath
	 * @return void
	 */
	public function cleanupDirectory(string $directoryPath): void
	{
		FileUtility::cleanupDirectory($directoryPath);
	}

	public function backupFiles(string $archiveFilePath, array $paths)
	{
		$this->log('backup archive path: ' . $archiveFilePath);

		FileUtility::backupItems($archiveFilePath, $this->joinPath($this->rootDirectoryPath, 'PeServer'), $paths);
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
		FileUtility::cleanupDirectory($dir);
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
	$recvFilePath = FileUtility::joinPath($recvDirPath, sprintf('%08d.part', $number));
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
	$pattern = FileUtility::joinPath($recvDirPath, '*.part');
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

	$expandFilePaths = FileUtility::getFiles($expandDirPath, true);
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

	try {
		$expandDirPath = getExpandDirectoryPath();
		$expandFilePaths = FileUtility::getFiles($expandDirPath, true);
		$expandFileRelativePaths = array_map(function ($i) use ($expandDirPath) {
			outputLog('UPDATE: ' . $i);
			return mb_substr($i, mb_strlen($expandDirPath) + 1);
		}, $expandFilePaths);

		outputLog('expandFileRelativePaths.count: ' . count($expandFileRelativePaths));
		foreach($expandFileRelativePaths as $expandFileRelativePath) {
			outputLog('expandFileRelativePath: ' . $expandFileRelativePath);
		}

		// ユーザースクリプト用データ
		$scriptArgument = new ScriptArgument($config['ROOT_DIR_PATH'], FileUtility::joinPath($config['ROOT_DIR_PATH'], $config['PUBLIC_DIR']), getExpandDirectoryPath(), $config);
		// 前処理スクリプトの実施
		$beforeScriptPath = FileUtility::joinPath(getExpandDirectoryPath(), $config['BEFORE_SCRIPT']);
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
			$src = FileUtility::joinPath($expandDirPath, $expandFileRelativePath);
			if (is_dir($src)) {
				continue;
			}
			$dst = FileUtility::joinPath($config['ROOT_DIR_PATH'], $config['PUBLIC_DIR'], $expandFileRelativePath);
			$dir = dirname($dst);
			if (!is_dir($dir)) {
				mkdir($dir, 0777, true);
			}

			outputLog("COPY: $src -> $dst");
			copy($src, $dst);
		}

		// 後処理スクリプトの実施
		$afterScriptPath = FileUtility::joinPath(getExpandDirectoryPath(), $config['AFTER_SCRIPT']);
		if (is_file($afterScriptPath)) {
			outputLog('afterScriptPath: ' . $afterScriptPath);
			require_once $afterScriptPath;
			call_user_func('after_update', $scriptArgument);
		}

		// 退避ファイル補正
		foreach ($skipFiles as $skipFile) {
			$src = FileUtility::joinPath($expandDirPath, $skipFile);
			$dst = FileUtility::joinPath($config['ROOT_DIR_PATH'], $config['PUBLIC_DIR'], $skipFile);
			copy($src, $dst);
		}
	} finally {
		// 実行ファイル破棄
		unlink(getRunningFilePath());
	}
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

if (!defined('NO_DEPLOY_START')) {
	main();
}









//AUTO-GEN------------------------------------------------------------------------
//AUTO-GEN-SETTING:FILE:PeServer/Core/Throws/CoreError.php
//AUTO-GEN-SETTING:FILE:PeServer/Core/Throws/CoreException.php
//AUTO-GEN-SETTING:FILE:PeServer/Core/Throws/FileNotFoundException.php
//AUTO-GEN-SETTING:FILE:PeServer/Core/Throws/ParseException.php
//AUTO-GEN-SETTING:FILE:PeServer/Core/StringUtility.php
//AUTO-GEN-SETTING:FILE:PeServer/Core/FileUtility.php





//AUTO-GEN-CODE
class CoreError extends Error
{
	public function __construct(string $message = "", int $code = 0, ?Throwable $previous = null)
	{
		parent::__construct($message, $code, $previous);
	}
}
class CoreException extends Exception
{
	public function __construct(string $message = "", int $code = 0, ?Throwable $previous = null)
	{
		parent::__construct($message, $code, $previous);
	}
}
class FileNotFoundException extends CoreException
{
	public function __construct(string $message = "", int $code = 0, ?Throwable $previous = null)
	{
		parent::__construct($message, $code, $previous);
	}
}
class ParseException extends CoreException
{
	public function __construct(string $message = "", int $code = 0, ?Throwable $previous = null)
	{
		parent::__construct($message, $code, $previous);
	}
}
class StringUtility
{
	/**
	 * 文字列がnullか空か
	 *
	 * @param string|null $s
	 * @return boolean
	 */
	public static function isNullOrEmpty(?string $s): bool
	{
		if (is_null($s)) {
			return true;
		}
		if ($s === '0') {
			return false;
		}
		return empty($s);
	}
	/**
	 * 文字列がnullかホワイトスペースのみで構築されているか
	 *
	 * @param string|null $s
	 * @return boolean
	 */
	public static function isNullOrWhiteSpace(?string $s): bool
	{
		if (self::isNullOrEmpty($s)) {
			return true;
		}
		return strlen(trim($s)) === 0;
	}
	/**
	 * プレースホルダー文字列置き換え処理
	 *
	 * @param string $source 元文字列
	 * @param array<string,string> $map 置き換え対象辞書
	 * @param string $head
	 * @param string $tail
	 * @return string 置き換え後文字列
	 */
	public static function replaceMap(string $source, array $map, string $head = '{', string $tail = '}'): string
	{
		$escHead = preg_quote($head);
		$escTail = preg_quote($tail);
		$pattern = "/$escHead(.+?)$escTail/";
		return preg_replace_callback(
			$pattern,
			function ($matches) use ($map) {
				if (isset($map[$matches[1]])) {
					return $map[$matches[1]];
				}
				return '';
			},
			$source
		);
	}
	public static function startsWith(string $haystack, string $needle, bool $ignoreCase): bool
	{
		//PHP8
		//str_starts_with($haystack, $needle);
		if (self::isNullOrEmpty($needle)) {
			return true;
		}
		if (strlen($haystack) < strlen($needle)) {
			return false;
		}
		$word = mb_substr($haystack, 0, mb_strlen($needle));
		if ($ignoreCase) {
			return !strcasecmp($needle, $word);
		}
		return $needle === $word;
	}
	public static function endsWith(string $haystack, string $needle, bool $ignoreCase): bool
	{
		//PHP8
		//str_ends_with($haystack, $needle);
		if (self::isNullOrEmpty($needle)) {
			return true;
		}
		if (strlen($haystack) < strlen($needle)) {
			return false;
		}
		$word = mb_substr($haystack, mb_strlen($haystack) - mb_strlen($needle));
		if ($ignoreCase) {
			return !strcasecmp($needle, $word);
		}
		return $needle === $word;
	}
	public static function contains(string $haystack, string $needle, bool $ignoreCase): bool
	{
		//PHP8
		//str_contains
		if (self::isNullOrEmpty($needle)) {
			return true;
		}
		if (strlen($haystack) < strlen($needle)) {
			return false;
		}
		if ($ignoreCase) {
			return stripos($haystack, $needle) !== false;
		}
		return strpos($haystack, $needle) !== false;
	}
}
class FileUtility
{
	/**
	 * 絶対パスへ変換。
	 *
	 * @param string $path パス。
	 * @return string 絶対パス。
	 */
	public static function toCanonicalize(string $path): string
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
	 * パスの結合。
	 *
	 * @param string $basePath ベースとなるパス。
	 * @param string ...$addPaths 連結していくパス。
	 * @return string 結合後のパス。正規化される。
	 */
	public static function joinPath(string $basePath, string ...$addPaths): string
	{
		$paths = array_merge([$basePath], array_map(function ($s) {
			return trim($s, '/\\');
		}, $addPaths));
		$paths = array_filter($paths, function ($v, $k) {
			return !StringUtility::isNullOrEmpty($v) && ($k === 0 ? true :  $v !== '/' && $v !== '\\');
		}, ARRAY_FILTER_USE_BOTH);
		$joinedPath = implode(DIRECTORY_SEPARATOR, $paths);
		return self::toCanonicalize($joinedPath);
	}
	/**
	 * JSONとしてファイル読み込み
	 *
	 * @param string $path パス
	 * @param boolean $associative 連想配列として扱うか
	 * @return array|\stdClass 応答JSON
	 */
	public static function readJsonFile(string $path, bool $associative = true) // @phpstan-ignore-line
	{
		$content = file_get_contents($path);
		if ($content === false) {
			throw new FileNotFoundException($path);
		}
		$json = json_decode($content, $associative);
		if (is_null($json)) {
			throw new ParseException($path);
		}
		return $json;
	}
	/**
	 * ディレクトリが存在しない場合に作成する。
	 *
	 * ディレクトリは再帰的に作成される。
	 *
	 * @param string $directoryPath ディレクトリパス
	 * @return void
	 */
	public static function createDirectoryIfNotExists(string $directoryPath)
	{
		if (!file_exists($directoryPath)) {
			mkdir($directoryPath, 0777, true);
		}
	}
	/**
	 * 対象パスの親ディレクトリが存在しない場合に親ディレクトリを作成する。
	 *
	 * ディレクトリは再帰的に作成される。
	 *
	 * @param string $path 対象パス（メソッド自体はファイルパスとして使用することを前提としている）
	 * @return void
	 */
	public static function createParentDirectoryIfNotExists(string $path)
	{
		self::createDirectoryIfNotExists(dirname($path));
	}
	/**
	 * ファイル/ディレクトリ一覧を取得する。
	 *
	 * @param string $directoryPath ディレクトリパス。
	 * @param boolean $recursive 再帰的に取得するか。
	 * @param boolean $directory
	 * @param boolean $file
	 * @return string[] ファイル一覧。
	 */
	private static function getChildrenCore(string $directoryPath, bool $directory, bool $file, bool $recursive): array
	{
		/** @var string[] */
		$files = [];
		$items = scandir($directoryPath);
		if ($items === false) {
			return $files;
		}
		foreach ($items as $item) {
			if ($item === '.' || $item === '..') {
				continue;
			}
			$path = self::joinPath($directoryPath, $item);
			$isDir = is_dir($path);
			if ($isDir && $directory) {
				$files[] = $path;
			} else if (!$isDir && $file) {
				$files[] = $path;
			}
			if ($isDir && $recursive) {
				$files = array_merge($files, self::getChildrenCore($path, $directory, $file, $recursive));
			}
		}
		return $files;
	}
	/**
	 * ファイル/ディレクトリ一覧を取得する。
	 *
	 * @param string $directoryPath ディレクトリパス。
	 * @param boolean $recursive 再帰的に取得するか。
	 * @return string[] ファイル一覧。
	 */
	public static function getChildren(string $directoryPath, bool $recursive): array
	{
		return self::getChildrenCore($directoryPath, true, true, $recursive);
	}
	/**
	 * ファイル一覧を取得する。
	 *
	 * @param string $directoryPath ディレクトリパス。
	 * @param boolean $recursive 再帰的に取得するか。
	 * @return string[] ファイル一覧。
	 */
	public static function getFiles(string $directoryPath, bool $recursive): array
	{
		return self::getChildrenCore($directoryPath, false, true, $recursive);
	}
	/**
	 * ディレクトリ一覧を取得する。
	 *
	 * @param string $directoryPath ディレクトリパス。
	 * @param boolean $recursive 再帰的に取得するか。
	 * @return string[] ファイル一覧。
	 */
	public static function getDirectories(string $directoryPath, bool $recursive): array
	{
		return self::getChildrenCore($directoryPath, true, false, $recursive);
	}
	/**
	 * ディレクトリを削除する。
	 * ファイル・ディレクトリはすべて破棄される。
	 *
	 * @param string $directoryPath 削除ディレクトリ。
	 * @return void
	 */
	public static function removeDirectory(string $directoryPath): void
	{
		$files = self::getChildren($directoryPath, false);
		foreach ($files as $file) {
			if (is_dir($file)) {
				self::removeDirectory($file);
			} else {
				unlink($file);
			}
		}
		rmdir($directoryPath);
	}
	/**
	 * ディレクトリを破棄・作成する
	 *
	 * @param string $directoryPath 対象ディレクトリ。
	 * @return void
	 */
	public static function cleanupDirectory(string $directoryPath): void
	{
		if (is_dir($directoryPath)) {
			self::removeDirectory($directoryPath);
		}
		mkdir($directoryPath, 0777, true);
	}
	/**
	 * バックアップ。
	 *
	 * !!未実装!!
	 *
	 * @param string $backupItem 対象ディレクトリ。
	 * @param string $baseDirectoryPath 対象ディレクトリ。
	 * @param string[] $targetPaths 対象ディレクトリ。
	 *
	*/
	public static function backupItems(string $backupItem, string $baseDirectoryPath, array $targetPaths): void
	{
		// NONE
	}
}
