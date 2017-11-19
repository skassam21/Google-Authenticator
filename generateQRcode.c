#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

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

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	// Convert secret_hex from string to hex representation
	uint8_t buf[10];
	convertStrToHex(secret_hex, buf);

	// Base32 encode the secret
	uint8_t secretHexEncoded[17];
	base32_encode((const uint8_t *) buf, 10, secretHexEncoded, 16);
	
	// Set end of encoded hex as null byte
	secretHexEncoded[16] = '\0';

	// URL encode account Name and issuer
	const char* accountNameEncoded = urlEncode(accountName);
	const char* issuerEncoded = urlEncode(issuer);

	// Generate the HOTP URI
	char *hotpURI = malloc(14 + strlen(accountNameEncoded) + 8 + strlen(issuerEncoded) + 8 + 16 + 10);
	sprintf(hotpURI, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", accountNameEncoded, issuerEncoded, secretHexEncoded);

	displayQRcode(hotpURI);

	// Generate the TOTP URL
	char *totpURI = malloc(14 + strlen(accountNameEncoded) + 8 + strlen(issuerEncoded) + 8 + 16 + 10);
	sprintf(totpURI, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accountNameEncoded, issuerEncoded, secretHexEncoded);

	displayQRcode(totpURI);

	return (0);
}
