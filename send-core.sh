#!/bin/bash -ue

SETTING_LOG_LEVEL="${SETTING_LOG_LEVEL:=i}"

LOCAL_TEMP_DIR=local-temp
LOCAL_SELF_PRIVATE_KEY=${LOCAL_TEMP_DIR}/self-private-key.pem
LOCAL_SELF_PUBLIC_KEY=${LOCAL_TEMP_DIR}/self-public-key.pem
LOCAL_INIT_DATA=${LOCAL_TEMP_DIR}/init.dat
LOCAL_ENC_ACCESS_TOKEN=${LOCAL_TEMP_DIR}/access-token.enc
LOCAL_RAW_ACCESS_TOKEN=${LOCAL_TEMP_DIR}/access-token.raw
LOCAL_SERVER_PUBLIC_KEY=${LOCAL_TEMP_DIR}/server-public-key.dat
LOCAL_FILES_DIR=local-files

SEQUENCE_HELLO=10
SEQUENCE_INITIALIZE=20
SEQUENCE_RECEIVE=30
SEQUENCE_PREPARE=40
SEQUENCE_UPDATE=50

function getLogLevel()
{
	local LEVEL=$1 # T/D/I/W/E

	local RESULT=0
	case $LEVEL in
		[tT]|'trace' )
			RESULT=1
			;;
		[dD]|'debug' )
			RESULT=2
			;;
		[iI]|'info' )
			RESULT=3
			;;
		[wW]|'warn' )
			RESULT=4
			;;
		[eE]|'error' )
			RESULT=5
			;;
	esac

	echo $RESULT

	# return $RESULT
}

function msg()
{
	local LEVEL=$1 # T/D/I/W/E
	local MSG_LEVEL=$(getLogLevel ${LEVEL})
	local DEF_LEVEL=$(getLogLevel ${SETTING_LOG_LEVEL})

	# echo "!!!!!!!!!!: $LEVEL < $SETTING_LOG_LEVEL"
	# echo "XXXXXXXXXX: $MSG_LEVEL < $DEF_LEVEL"

	if [ "$MSG_LEVEL" -lt "$DEF_LEVEL" ] ; then
		# echo "byebye: $MSG_LEVEL < $DEF_LEVEL"
		return
	fi

	case $LEVEL in
		T ) echo -ne "" ;;
		D ) echo -ne "" ;;
		I ) echo -ne "" ;;
		W ) echo -ne "" ;;
		E ) echo -ne "" ;;
		* ) echo -ne "" ;;
	esac

	echo -n ${@:2:($#-1)}
	echo -e "\e[m"
}

function title()
{
	echo ''
	echo $*
	echo ''
}


function cleanupDir
{
	local DIR_PATH=$1
	if [ -d ${DIR_PATH} ] ; then
		rm -rf ${DIR_PATH}
		mkdir ${DIR_PATH}
	else
		mkdir ${DIR_PATH}
	fi
}

function saveData
{
	local KEY=$1
	local FILE=$2
	LINE=$(grep "^$KEY:" ${LOCAL_INIT_DATA})
	echo "${LINE#*:}" | base64 --decode > $FILE
	msg d "${KEY} -> ${LINE#*:}"
}

#-----------------------------------------------

msg i START

cleanupDir ${LOCAL_TEMP_DIR}
cleanupDir ${LOCAL_FILES_DIR}

# デバッグ用
rm -f running.json

title HELLO!

openssl genrsa 2048 > ${LOCAL_SELF_PRIVATE_KEY}
openssl rsa -in ${LOCAL_SELF_PRIVATE_KEY} -pubout -out ${LOCAL_SELF_PUBLIC_KEY}

curl --show-error -o ${LOCAL_INIT_DATA} -X POST -F seq=${SEQUENCE_HELLO} -F pub=@${LOCAL_SELF_PUBLIC_KEY} ${SETTING_URL}

msg t $(cat ${LOCAL_INIT_DATA})

msg t
msg t test!!
saveData 'token' ${LOCAL_ENC_ACCESS_TOKEN}
saveData 'public_key' ${LOCAL_SERVER_PUBLIC_KEY}

cat ${LOCAL_ENC_ACCESS_TOKEN} | openssl rsautl -decrypt -inkey ${LOCAL_SELF_PRIVATE_KEY} > ${LOCAL_RAW_ACCESS_TOKEN}

AUTH_HEADER_VALUE=$(cat ${LOCAL_RAW_ACCESS_TOKEN})
msg t "LOCAL_RAW_ACCESS_TOKEN: `cat $LOCAL_RAW_ACCESS_TOKEN`"

title init

msg t "SETTING_ACCESS_KEY: ${SETTING_ACCESS_KEY}"
ENC_ACCESS_KEY=$(echo -n ${SETTING_ACCESS_KEY} | openssl rsautl -encrypt -pubin -inkey ${LOCAL_SERVER_PUBLIC_KEY} | base64 --wrap=0)
msg t
msg t "ENC_ACCESS_KEY-> ${ENC_ACCESS_KEY}"
msg t
curl --show-error -X POST -d seq=${SEQUENCE_INITIALIZE} --data-urlencode key=${ENC_ACCESS_KEY} ${SETTING_URL}

title recv

split --bytes=${SETTING_SPLIT_SIZE} --numeric-suffixes=1 --suffix-length=8 ${SETTING_ARCHIVE_FILE_NAME} ${LOCAL_FILES_DIR}/
INDEX=1
for PART_FILE in `ls -1 -v ${LOCAL_FILES_DIR}/`; do
	curl --show-error -X POST -F seq=${SEQUENCE_RECEIVE} -F file=@${LOCAL_FILES_DIR}/${PART_FILE} -F number=$INDEX  -H "${SETTING_AUTH_HEADER_NAME}: ${AUTH_HEADER_VALUE}" ${SETTING_URL}
	let INDEX++
done

title prepare

HASH=$(sha512sum --binary ${SETTING_ARCHIVE_FILE_NAME} | cut -d ' ' -f 1)
msg t $HASH
curl --show-error -X POST -d seq=${SEQUENCE_PREPARE} -d algorithm=sha512 -d hash=${HASH} -H "${SETTING_AUTH_HEADER_NAME}: ${AUTH_HEADER_VALUE}" ${SETTING_URL}

title update

curl --show-error -X POST -d seq=${SEQUENCE_UPDATE} --data-urlencode key=${ENC_ACCESS_KEY} -H "${SETTING_AUTH_HEADER_NAME}: ${AUTH_HEADER_VALUE}" ${SETTING_URL}

title END
