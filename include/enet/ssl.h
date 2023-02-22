#ifndef __ENET_SSL_H__
#define __ENET_SSL_H__

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <openssl/x509v3.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef SSL ENetSsl;
typedef SSL_CTX ENetSslCtx;
typedef BIO ENetSslBio;

// Define a custom BIO so we can use a single socket for DTLS
int BIO_s_enet_write_ex (BIO * b, const char * data, size_t dlen, size_t * written);
int BIO_s_enet_write (BIO * b, const char * data, int dlen);
int BIO_s_enet_read_ex (BIO * b, char * data, size_t dlen, size_t * readbytes);
int BIO_s_enet_read (BIO * b, char * data, int dlen);
long BIO_s_enet_ctrl (BIO * b, int cmd, long larg, void * pargs);
int BIO_s_enet_create (BIO * b);
int BIO_s_enet_destroy (BIO * b);

BIO_METHOD* BIO_s_enet (void);
void BIO_s_enet_meth_free (void);

#define ENET_SSL_SOCKET_HEADER_SIZE 13

#ifdef __cplusplus
}
#endif

#endif /* __ENET_SSL_H__ */