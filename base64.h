/* base64.h for QLDAP checkpassword.c */

/*        */
/* BASE64 */
/*        */

int b64_ntop(u_char const *, size_t, char *, size_t);
int b64_pton(char const *, u_char *, size_t);

