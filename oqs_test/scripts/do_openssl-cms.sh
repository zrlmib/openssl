#!/bin/bash

###########
# Run CMS test in OpenSSL 1.1.1 (assume keys and certs have been generated before)
#
# Environment variables:
#  - SIGALG: signature algorithm to use
###########

set -x

if [[ ${SIGALG} == "rsa:3072" || ${SIGALG} == "ecdsa"* || ${SIGALG} == "dilithium"* || ${SIGALG} == "qteslapi"* ]]; then
   echo "Testdata" > input
   rm -f result
   apps/openssl cms -in input -sign -signer ${SIGALG}_srv.crt -inkey ${SIGALG}_srv.key  -nodetach -outform pem -binary -out output-${SIGALG}.p7s
   apps/openssl cms -verify -CAfile ${SIGALG}_CA.crt  -inform pem -in output-${SIGALG}.p7s -crlfeol -out result
   diff result input
else # No test
   exit 0
fi
