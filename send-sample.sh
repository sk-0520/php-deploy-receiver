#!/bin/bash -ue

URL=http://localhost/deploy/php-deploy-receiver.php
AUTH_HEADER_NAME=DEPLOY
AUTH_HEADER_VALUE=TEST
ARCHIVE_FILE_NAME=public_html.zip
SPLIT_SIZE=10MB

LOCAL_TEMP_DIR=local-temp
LOCAL_SELF_PRIVATE_KEY=${LOCAL_TEMP_DIR}/self-private-key.pem
LOCAL_SELF_PUBLIC_KEY=${LOCAL_TEMP_DIR}/self-public-key.pem
LOCAL_FILES_DIR=local-files

SEQUENCE_HELLO=10
SEQUENCE_INITIALIZE=20
SEQUENCE_RECEIVE=30
SEQUENCE_PREPARE=40
SEQUENCE_UPDATE=50

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
cleanupDir ${LOCAL_TEMP_DIR}
cleanupDir ${LOCAL_FILES_DIR}

# HELLO!

openssl genrsa 1024 > ${LOCAL_SELF_PRIVATE_KEY}
openssl rsa -in ${LOCAL_SELF_PRIVATE_KEY} -pubout -out ${LOCAL_SELF_PUBLIC_KEY}

curl -v -X POST -F seq=${SEQUENCE_HELLO} -F pub=@${LOCAL_SELF_PUBLIC_KEY} $URL

# init

curl -v -X POST -d seq=${SEQUENCE_INITIALIZE} -H "${AUTH_HEADER_NAME}: ${AUTH_HEADER_VALUE}" $URL

# recv

split --bytes=${SPLIT_SIZE} --numeric-suffixes=1 --suffix-length=8 ${ARCHIVE_FILE_NAME} ${LOCAL_FILES_DIR}/
INDEX=1
for PART_FILE in `ls -1 -v ${LOCAL_FILES_DIR}/`; do
	curl -v -X POST -F seq=${SEQUENCE_RECEIVE} -F file=@${LOCAL_FILES_DIR}/${PART_FILE} -F number=$INDEX  -H "${AUTH_HEADER_NAME}: ${AUTH_HEADER_VALUE}" $URL
	let INDEX++
done

# prepare

HASH=$(sha512sum --binary ${ARCHIVE_FILE_NAME})
curl -v -X POST -d seq=${SEQUENCE_PREPARE} -d algorithm=SHA512 -d hash=${HASH} -H "${AUTH_HEADER_NAME}: ${AUTH_HEADER_VALUE}" $URL

# update

curl -v -X POST -d seq=${SEQUENCE_UPDATE} -H "${AUTH_HEADER_NAME}: ${AUTH_HEADER_VALUE}" $URL
