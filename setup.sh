#!/bin/bash
source <(grep = controller.ini | sed 's/ *= */=/g')
sed -i "s/172.24.4.120/${Controller}/" ~/i2nsf-security-controller/react/src/pages_components/*.js
sed -i "s/172.24.4.120/${Controller}/" ~/i2nsf-security-controller/react/src/modals_components/*.js