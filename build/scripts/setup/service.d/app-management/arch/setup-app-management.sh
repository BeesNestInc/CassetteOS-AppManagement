#!/bin/bash

set -e

readonly APP_NAME="cassetteos-app-management"
readonly APP_NAME_SHORT="app-management"

# copy config files
readonly CONF_PATH=/etc/cassetteos
readonly CONF_FILE=${CONF_PATH}/${APP_NAME_SHORT}.conf
readonly CONF_FILE_SAMPLE=${CONF_PATH}/${APP_NAME_SHORT}.conf.sample
readonly ENV_FILE=${CONF_PATH}/env
readonly ENV_FILE_SAMPLE=${CONF_PATH}/env.sample

if [ ! -f "${CONF_FILE}" ]; then \
    echo "Initializing config file..."
    cp -v "${CONF_FILE_SAMPLE}" "${CONF_FILE}"; \
fi

if [ ! -f "${ENV_FILE}" ]; then \
    echo "Initializing env file..."
    cp -v "${ENV_FILE_SAMPLE}" "${ENV_FILE}"; \
fi

systemctl daemon-reload

# enable service (without starting)
echo "Enabling service..."
systemctl enable --force --no-ask-password "${APP_NAME}.service"
