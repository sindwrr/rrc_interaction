rm -r request_src
rm -r setup_src
rm -r build
mkdir request_src
mkdir setup_src
mkdir build
asn1c -D request_src -no-gen-OER -no-gen-example rrc_connection_request.asn1
asn1c -D setup_src -no-gen-OER -no-gen-example rrc_connection_setup.asn1
gcc  -Irequest_src -Isetup_src -o build/client client.cpp request_src/*.c setup_src/RRCConnectionSetup.c setup_src/RRC-TransactionIdentifier.c setup_src/RRCConnectionSetup-r8-IEs.c -DASN_DISABLE_OER_SUPPORT
gcc -Irequest_src -Isetup_src -o build/server server.cpp request_src/*.c setup_src/RRCConnectionSetup.c setup_src/RRC-TransactionIdentifier.c setup_src/RRCConnectionSetup-r8-IEs.c -DASN_DISABLE_OER_SUPPORT