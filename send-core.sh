#!/bin/bash -ue

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

function msg()
{
	local LEVEL=$1 # T/D/I/W/E

	echo ${@:2:($#-1)}
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
	echo "${KEY} -> ${LINE#*:}"
}

#-----------------------------------------------

msg I START

cleanupDir ${LOCAL_TEMP_DIR}
cleanupDir ${LOCAL_FILES_DIR}

# デバッグ用
rm -f running.json

echo HELLO!

openssl genrsa 1024 > ${LOCAL_SELF_PRIVATE_KEY}
openssl rsa -in ${LOCAL_SELF_PRIVATE_KEY} -pubout -out ${LOCAL_SELF_PUBLIC_KEY}

curl -s -o ${LOCAL_INIT_DATA} -X POST -F seq=${SEQUENCE_HELLO} -F pub=@${LOCAL_SELF_PUBLIC_KEY} ${SETTING_URL}

cat ${LOCAL_INIT_DATA}

echo
echo test!!
saveData 'token' ${LOCAL_ENC_ACCESS_TOKEN}
saveData 'public_key' ${LOCAL_SERVER_PUBLIC_KEY}

cat ${LOCAL_ENC_ACCESS_TOKEN} | openssl rsautl -decrypt -inkey ${LOCAL_SELF_PRIVATE_KEY} > ${LOCAL_RAW_ACCESS_TOKEN}

AUTH_HEADER_VALUE=$(cat ${LOCAL_RAW_ACCESS_TOKEN})
echo "LOCAL_RAW_ACCESS_TOKEN: `cat $LOCAL_RAW_ACCESS_TOKEN`"
echo init

echo "SETTING_ACCESS_KEY: ${SETTING_ACCESS_KEY}"
ENC_ACCESS_KEY=$(echo -n ${SETTING_ACCESS_KEY} | openssl rsautl -encrypt -pubin -inkey ${LOCAL_SERVER_PUBLIC_KEY} | base64 --wrap=0)
echo
echo "ENC_ACCESS_KEY-> ${ENC_ACCESS_KEY}"
echo
curl -v -X POST -d seq=${SEQUENCE_INITIALIZE} --data-urlencode key=${ENC_ACCESS_KEY} ${SETTING_URL}

echo recv

split --bytes=${SETTING_SPLIT_SIZE} --numeric-suffixes=1 --suffix-length=8 ${SETTING_ARCHIVE_FILE_NAME} ${LOCAL_FILES_DIR}/
INDEX=1
for PART_FILE in `ls -1 -v ${LOCAL_FILES_DIR}/`; do
	curl -v -X POST -F seq=${SEQUENCE_RECEIVE} -F file=@${LOCAL_FILES_DIR}/${PART_FILE} -F number=$INDEX  -H "${SETTING_AUTH_HEADER_NAME}: ${AUTH_HEADER_VALUE}" ${SETTING_URL}
	let INDEX++
done

echo prepare

HASH=$(sha512sum --binary ${SETTING_ARCHIVE_FILE_NAME})
curl -v -X POST -d seq=${SEQUENCE_PREPARE} -d algorithm=SHA512 -d hash=${HASH} -H "${SETTING_AUTH_HEADER_NAME}: ${AUTH_HEADER_VALUE}" ${SETTING_URL}

echo update

curl -v -X POST -d seq=${SEQUENCE_UPDATE} -H "${SETTING_AUTH_HEADER_NAME}: ${AUTH_HEADER_VALUE}" ${SETTING_URL}
