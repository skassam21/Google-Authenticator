#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#include "lib/sha1.h"

void convertStrToHex(char* inputStr, uint8_t*outputStr) {
	int i;
	int j;
	char subStr[2];
	for (i = 0, j = 0; i < strlen(inputStr); i+=2, j++) {
		subStr[0] = inputStr[i];
		subStr[1] = inputStr[i+1];
		outputStr[j] = strtol(subStr, NULL, 16);
	}
}

void hmac(const uint8_t *secret, int secretLength,
          const uint8_t *message, int messageLength,
          uint8_t *result, int resultLength) {
	SHA1_INFO ctx;

	uint8_t tmp_secret[64];
	for (int i = 0; i < secretLength; ++i) {
	tmp_secret[i] = secret[i] ^ 0x36;
	}

	memset(tmp_secret + secretLength, 0x36, 64 - secretLength);

	sha1_init(&ctx);
	sha1_update(&ctx, tmp_secret, 64);
	sha1_update(&ctx, message, messageLength);
	uint8_t sha[SHA1_DIGEST_LENGTH];
	sha1_final(&ctx, sha);

	for (int i = 0; i < secretLength; ++i) {
	tmp_secret[i] = secret[i] ^ 0x5C;
	}
	memset(tmp_secret + secretLength, 0x5C, 64 - secretLength);

	sha1_init(&ctx);
	sha1_update(&ctx, tmp_secret, 64);
	sha1_update(&ctx, sha, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, sha);

	// Copy result to output buffer and truncate or pad as necessary
	memset(result, 0, resultLength);
	memcpy(result, sha, resultLength);
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{

	// Convert secret_hex from string to binary representation
	uint8_t data[10];
	convertStrToHex(secret_hex, data);

	uint8_t hmac_result[SHA1_DIGEST_LENGTH];

	uint8_t counter[8];

	int i;
	int j;
	for (i = 1; i <= 5; i++) {

		// Set the counter to the value if i
		for (j = 0; j < 8; j++) {
			counter[j] = 0x00;
		}
		counter[7] = i; // highest bit is hashed first

		printf ("Counter: ");
		for (j = 0; j < 8; j++)
		  printf ("%02x ", counter[j] & 0xFF);
		printf ("\n");

		printf ("Hex: ");
		for (j = 0; j < 10; j++)
		  printf ("%02x ", data[j] & 0xFF);
		printf ("\n");

		hmac(data, 10, counter, 8, hmac_result, SHA1_DIGEST_LENGTH);
		printf ("HMAC: ");
		for (j = 0; j < 20; j++)
		  printf ("%02x ", hmac_result[j] & 0xFF);
		printf ("\n");

		// offset is the byte that represents the 4 lower bits of last part
		uint8_t offset = hmac_result[19] & 0x0f;
		printf ("offset: %02x", offset & 0xFF);
		printf ("\n");

		long S;
		S = (((hmac_result[offset] & 0x7f) << 24)
		 | ((hmac_result[offset + 1] & 0xff) << 16)
		 | ((hmac_result[offset + 2] & 0xff) << 8) | ((hmac_result[offset + 3] & 0xff)));

		printf ("value: %ld\n", S);

		long result = S % (long) pow(10.0, 6.0);

		printf ("result: %ld\n", result);
		printf ("HOTP: %ld\n", strtol(HOTP_string, NULL, 10));

		// Compare HOTP_string with result
		if (strtol(HOTP_string, NULL, 10) == result) {
			return(1);
		}

	}
	return (0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	return (0);
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
