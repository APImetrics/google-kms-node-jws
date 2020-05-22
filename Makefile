ts := $(shell /bin/date "+%Y-%m-%d")
jobname := "rsa-private-job-${ts}"
keyring = "google-kms-node-jwa"
keyname = "ec256-private"

verbose: test/kms
	@node test/*.test.js

test: test/kms
	@./node_modules/.bin/tape test/*.test.js

test/keys:
	@openssl genrsa 2048 > test/rsa-private.pem
	@openssl genrsa 2048 > test/rsa-wrong-private.pem
	@openssl rsa -in test/rsa-private.pem -pubout > test/rsa-public.pem
	@openssl rsa -in test/rsa-wrong-private.pem -pubout > test/rsa-wrong-public.pem
	@openssl ecparam -out test/ec256-private.pem -name secp256r1 -genkey
	@openssl ecparam -out test/ec256-wrong-private.pem -name secp256k1 -genkey
	@openssl ecparam -out test/ec384-private.pem -name secp384r1 -genkey
	@openssl ecparam -out test/ec384-wrong-private.pem -name secp384r1 -genkey
	@openssl ecparam -out test/ec512-private.pem -name secp521r1 -genkey
	@openssl ecparam -out test/ec512-wrong-private.pem -name secp521r1 -genkey
	@openssl ec -in test/ec256-private.pem -pubout > test/ec256-public.pem
	@openssl ec -in test/ec256-wrong-private.pem -pubout > test/ec256-wrong-public.pem
	@openssl ec -in test/ec384-private.pem -pubout > test/ec384-public.pem
	@openssl ec -in test/ec384-wrong-private.pem -pubout > test/ec384-wrong-public.pem
	@openssl ec -in test/ec512-private.pem -pubout > test/ec512-public.pem
	@openssl ec -in test/ec512-wrong-private.pem -pubout > test/ec512-wrong-public.pem
	@echo foo > test/encrypted-key-passphrase
	@openssl rsa -passin file:test/encrypted-key-passphrase -in test/rsa-private.pem > test/rsa-private-encrypted.pem
	@openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in test/ec256-private.pem -out test/ec256-private.der
	@touch test/keys

test/kms: test/keys
	@gcloud kms keys versions import \
		--import-job ${jobname} \
		--location "us-central1" \
		--keyring ${keyring} \
		--key ${keyname} \
		--algorithm ec-sign-p256-sha256 \
		--target-key-file test/ec256-private.der
	@touch test/kms

clean:
	@rm test/*.pem
	@rm test/*.der
	@rm test/keys
	@rm test/kms

create-key:
	@gcloud kms keys create ${keyname} --location us-central1 --keyring ${keyring} --purpose asymmetric-signing --default-algorithm rsa-sign-pss-2048-sha256 --skip-initial-version-creation

create-upload-job:
	@gcloud kms import-jobs create ${jobname} --location us-central1 --keyring ${keyring} --import-method rsa-oaep-3072-sha1-aes-256 --protection-level software


.PHONY: test
