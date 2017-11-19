## Generating QR Code: 

The process for generating the QR code involves the following steps:
- Convert the secret value into an array of binary values by looping through every two hex digits and converting them to a binary value using `strtol(subStr, NULL, 16)`
- base32 encode the secret value (in its binary form)
- URL encode the account name + the issuer 
- combine the account name, issuer, and secret into the correct formats (`otpauth://hotp/%s?issuer=%s&secret=%s&counter=1` for HOTP and `otpauth://totp/%s?issuer=%s&secret=%s&period=30` for TOTP)

## Validating QR Code:

The first step for validating the QR code for both HOTP and TOTP is to convert the secret into its binary representation. This is done in the same way for generating the QR code. 

### HOTP

The following are the steps for validating HOTP:

For each value of the counter (in the range of 1 to 5 for this lab):
- store the value of the counter in the form of a 8 byte array, where the highest byte is the value of the count
- compute the HMAC where the key is the secret (in binary form), and the message is the counter
- let the offset = byte that represents the 4 lower bits of last byte of the computed HMAC (`uint8_t offset = hmac_result[19] & 0x0f;`)
- compute the bin code as the last 31 bits of `hmac_result[offset]...hmac_result[offset+3]` in long format
- lastly, the HOTP 6 digit value is equal to the previous result `mod 10^6`
- if the result is the same as the code provided by the user, then the code is valid

The code is invalid if the result is wrong for each counter value.

### TOTP

The following are the steps for validating TOTP:

- compute T as `time(NULL) / 30`
- for [T-2, T+2] (in case the clocks are not synchronized):
	- store T in its binary representation as 8 bytes (highest byte first)
	- compute the HOTP value where the counter = T (in binary format)
	- if the result is the same as the code provided by the user, then the code is valid

The code is invalid if the result is wrong for the different values of T.
