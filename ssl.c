
#include "enet/enet.h"
#include "enet/ssl.h"
#include <string.h>

#define COOKIE_COUNT 2
#define COOKIE_SECRET_LENGTH 16
// use a 5 minute window for cookie rotation
#define COOKIE_ROTATION_INTERVAL 300000

typedef struct _ENetCookie {
   unsigned char secret [COOKIE_SECRET_LENGTH];
   enet_uint32 init_time;
} ENetCookie;

static ENetCookie cookies[COOKIE_COUNT];
static int cookies_initialized = 0;
static int cookie_index = 0;

int
enet_init_cookie (int i)
{
   if (!RAND_bytes (cookies [i].secret, COOKIE_SECRET_LENGTH))
   {
#ifdef ENET_DEBUG
      perror ("error setting random cookie secret");
#endif
      return 0;
   }
   cookies [i].init_time = enet_time_get ();
   return 1;
}

int 
enet_generate_cookie (SSL * ssl, unsigned char * cookie, unsigned int * cookie_len)
{
   // Initialize our cookie secrets
   if (!cookies_initialized)
   {
      for (int i = 0; i < COOKIE_COUNT; i++) 
      {
         if (!enet_init_cookie (i)) 
            return 0;
      }
      cookies_initialized = 1;
   }

   // Try Rotating Cookies if necessary
   if (cookies [cookie_index].init_time + COOKIE_ROTATION_INTERVAL < enet_time_get ()) 
   {
      cookie_index = (cookie_index + 1) % COOKIE_COUNT;
      if (!enet_init_cookie (cookie_index))
         return 0;
   }

   // read the incoming address
   ENetAddress address;
   BIO_dgram_get_peer (SSL_get_rbio (ssl), & address);

   // Calculate HMAC of buffer using the secret
   unsigned int resultLength = 0;
   unsigned char result [EVP_MAX_MD_SIZE];
   HMAC (EVP_sha1 (), 
         (const void *) cookies [cookie_index].secret, 
         COOKIE_SECRET_LENGTH,
         (const unsigned char *) & address, 
         sizeof (ENetAddress), 
         result, 
         & resultLength);
  
   memcpy (cookie, result, resultLength);
   * cookie_len = resultLength;

   return 1;
}

int 
enet_verify_cookie (SSL * ssl, const unsigned char * cookie, unsigned int cookie_len)
{
   // If secret isn't initialized yet, the cookie can't be valid
   if (!cookies_initialized)
      return 0;

   // read the incoming address
   ENetAddress address;
   BIO_dgram_get_peer (SSL_get_rbio (ssl), & address);

   unsigned int resultLength = 0;
   unsigned char result [EVP_MAX_MD_SIZE];

   // Calculate HMAC of buffer using all of our secrets (it's possible the secret was used just prior to rotation)
   for (int i = 0; i < COOKIE_COUNT; i++)
   {
      // check the most recent cookie first, then work backwards through the list
      int ci = (cookie_index + COOKIE_COUNT - i) % COOKIE_COUNT;

      // don't compare with very old secrets (we only generate new secrets in enet_generate_cookie)
      if (cookies [ci].init_time + COOKIE_ROTATION_INTERVAL * COOKIE_COUNT < enet_time_get ())
         continue;

      HMAC (EVP_sha1 (),
            (const void *) cookies [ci].secret,
            COOKIE_SECRET_LENGTH,
            (const unsigned char *) & address,
            sizeof (ENetAddress),
            result,
            & resultLength);

     if (cookie_len == resultLength && CRYPTO_memcmp (result, cookie, resultLength) == 0)
        return 1;
   }

  return 0;
}

static int 
enet_verify_server (int preverify_ok, X509_STORE_CTX* ctx)
{
   int err = X509_STORE_CTX_get_error (ctx);
   if (err != X509_V_OK)
     fprintf (stderr, "Verify Server Certificate failed with error %s\n", X509_verify_cert_error_string (err));
   // return the result of preverfication
   return preverify_ok;
}

static int 
enet_allow_all_certificates (X509_STORE_CTX * ctx, void * arg)
{
   return 1;
};

static void
enet_ssl_print_error (const char * func, int sslError)
{
#ifdef ENET_DEBUG
   const char * errorString = "unknown error";
   switch (sslError)
   {
   case SSL_ERROR_ZERO_RETURN: 
      errorString = "SSL_ERROR_ZERO_RETURN";
      break;
   case SSL_ERROR_WANT_READ:
      errorString = "SSL_ERROR_WANT_READ";
      break;
   case SSL_ERROR_WANT_WRITE:
      errorString = "SSL_ERROR_WANT_WRITE";
      break;
   case SSL_ERROR_WANT_CONNECT:
      errorString = "SSL_ERROR_WANT_CONNECT";
      break;
   case SSL_ERROR_WANT_ACCEPT:
      errorString = "SSL_ERROR_WANT_ACCEPT";
      break;
   case SSL_ERROR_WANT_X509_LOOKUP:
      errorString = "SSL_ERROR_WANT_X509_LOOKUP";
      break;
   case SSL_ERROR_SYSCALL:
      errorString = "SSL_ERROR_SYSCALL";
      break;
   case SSL_ERROR_SSL:
      errorString = "SSL_ERROR_SSL";
      break;
   }

   fprintf (stderr, "%s resulted in %s\n", func, errorString);
   fprintf (stderr, "%s\n", ERR_error_string (ERR_get_error (), NULL));
#endif
}

static int 
enet_ssl_filter_result (ENetSslSocketConnection * connection, const char* func, int result)
{
  int sslError = SSL_get_error (connection -> ssl, result);
  switch (sslError)
  {
  case SSL_ERROR_NONE:
  case SSL_ERROR_ZERO_RETURN:
    // return result directly
    break;
    
  case SSL_ERROR_WANT_READ:
    if (connection -> lastReadTime + connection -> timeout.tv_sec * 1000 + connection -> timeout.tv_usec / 1000 < enet_time_get())
    {
       // Connection timed out, return our original result
#ifdef ENET_DEBUG
       perror("ssl connection timed out!");
#endif
    }
    else
      // we are still waiting for results from the remote end, keep trying
      result = 0;
    break;

  case SSL_ERROR_WANT_WRITE:
    // set the result to 0 so we know to keep trying
    result = 0;
    break;

  default:
    enet_ssl_print_error(func, sslError);
    break;
  }
  return result;
}

// Wrap SSL methods with error filtering/logging
static int 
enet_ssl_connect (ENetSslSocketConnection * connection)
{
   return enet_ssl_filter_result (connection, "SSL_connect", SSL_connect (connection -> ssl));
}
static int
enet_ssl_accept (ENetSslSocketConnection * connection)
{
   return enet_ssl_filter_result (connection, "SSL_accept", SSL_accept (connection -> ssl));
}

static int
enet_ssl_read (ENetSslSocketConnection * connection, void * buf, int len)
{
   return enet_ssl_filter_result (connection, "SSL_read", SSL_read (connection -> ssl, buf, len));
}

static int
enet_ssl_write (ENetSslSocketConnection * connection, void * buf, int len)
{
   return enet_ssl_filter_result (connection, "SSL_write", SSL_write (connection -> ssl, buf, len));
}

static ENetSslSocketConnection *
enet_ssl_socket_connection_create (ENetSslSocket * ssl)
{
   ENetSslSocketConnection * connection = (ENetSslSocketConnection *)enet_malloc (sizeof (ENetSslSocketConnection));

   connection -> state = ENET_SSL_SOCKET_CONNECTION_STATE_NONE;
   connection -> socket = ssl -> socket;

   // initialize our bio for our socket
   connection -> bio = BIO_new (BIO_s_enet ());
   BIO_set_data (connection -> bio, connection);
   BIO_set_init (connection -> bio, 1);

   // initialize the ssl for our connection
   connection -> ssl = SSL_new (ssl -> ctx);
   // set the bio for our ssl
   SSL_set_bio (connection -> ssl, connection -> bio, connection -> bio);

   // set our initial mtu to minimum
   SSL_set_mtu (connection -> ssl, ENET_PROTOCOL_MINIMUM_MTU - enet_socket_get_header_size (connection -> socket));

   // set connection timeout to 5 seconds
   connection -> timeout.tv_sec = 5;
   connection -> timeout.tv_usec = 0;
   connection -> lastReadTime = enet_time_get ();
   memset (& connection -> address, 0, sizeof (ENetAddress));

   enet_list_insert (enet_list_end (& ssl -> connectionList), connection);

   return connection;
}

static ENetSslSocketConnection *
enet_ssl_socket_connection_create_listener (ENetSslSocket * ssl)
{
   ENetSslSocketConnection * connection = enet_ssl_socket_connection_create (ssl);

   // set the ssl to use cookie exchange to prevent DoS attacks
   SSL_set_options (connection -> ssl, SSL_OP_COOKIE_EXCHANGE);

   // mark the connection as listening
   connection -> state = ENET_SSL_SOCKET_CONNECTION_STATE_LISTENING;

   return connection;
}

static int
enet_ssl_socket_connection_accept (ENetSslSocketConnection * connection, const ENetAddress * address)
{
   if (connection -> state != ENET_SSL_SOCKET_CONNECTION_STATE_LISTENING)
      // we can only accept if we are listening
      return -1;

   // set our address to prepare to listen
   connection -> address = * address;

   ENetAddress tmpAddress;
   if (DTLSv1_listen (connection -> ssl, (BIO_ADDR *)& tmpAddress) <= 0)
      return 0;

   // verify our listen address matches the passed in address
   if (!enet_address_equal (address, & tmpAddress))
      return -1;

   // set the last read time for our manual timeout
   connection -> lastReadTime = enet_time_get ();

   // transition our state to accepting
   connection -> state = ENET_SSL_SOCKET_CONNECTION_STATE_ACCEPTING;

   return 1;
}

static ENetSslSocketConnection *
enet_ssl_socket_connection_create_connect (ENetSslSocket * ssl, const ENetAddress * address)
{  
   ENetSslSocketConnection * connection = enet_ssl_socket_connection_create (ssl);
   
   // set the address for this connection
   connection -> address = * address;

   // set the last read time for our manual timeout
   connection -> lastReadTime = enet_time_get ();
   
   // Set hostname validation for this connection
   if (ssl -> hostName != NULL) 
   {
      SSL_set1_host (connection -> ssl, ssl -> hostName);
      SSL_set_hostflags (connection -> ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
   }

   // transition our state to connecting
   connection -> state = ENET_SSL_SOCKET_CONNECTION_STATE_CONNECTING;

   return connection;
}

static int
enet_ssl_socket_connection_update_connection_state (ENetSslSocketConnection * connection)
{
   // If this connection is connecting or accepting, try to update the state.
   // Otherwise return 0.
   int result;
   switch (connection -> state)
   {
   case ENET_SSL_SOCKET_CONNECTION_STATE_CONNECTING:
      result = enet_ssl_connect (connection);
      break;

   case ENET_SSL_SOCKET_CONNECTION_STATE_ACCEPTING:
      result = enet_ssl_accept (connection);
      break;

   default:
      result = 0;
      break;
   }

   if (result <= 0)
      return result;

   // Connected successfully!
   connection -> state = ENET_SSL_SOCKET_CONNECTION_STATE_CONNECTED;

   // increase our mtu to maximum (data size will still be limited)
   SSL_set_mtu (connection -> ssl, ENET_PROTOCOL_MAXIMUM_MTU - enet_socket_get_header_size (connection -> socket));

   // mark the last read time for our manual timeout
   connection -> lastReadTime = enet_time_get ();

   return result;
}

static void
enet_ssl_socket_connection_destroy (ENetSslSocketConnection * connection)
{
   SSL_free (connection -> ssl);

   enet_list_remove (& connection -> connectionList);
   enet_free (connection);
}

int BIO_s_enet_write_ex (BIO * b, const char * data, size_t dlen, size_t * written)
{
   ENetSslSocketConnection * connection = (ENetSslSocketConnection *)BIO_get_data (b);
   ENetBuffer buffer;
   buffer.data = (void *)data;
   buffer.dataLength = dlen;

   BIO_clear_retry_flags (b);
   int result = enet_socket_send (connection -> socket, & connection -> address, & buffer, 1);
   if (result < 0)
      return 0;

   if (written)
      *written = result;
   return 1;
}

int BIO_s_enet_write (BIO * b, const char * data, int dlen)
{
   size_t written;
   if (BIO_s_enet_write_ex (b, data, dlen, & written))
     return (int)written;
   return -1;
}

int BIO_s_enet_read_ex (BIO * b, char * data, size_t dlen, size_t * readbytes)
{
   ENetSslSocketConnection * connection = (ENetSslSocketConnection *)BIO_get_data (b);
   ENetBuffer buffer;
   buffer.data = data;
   buffer.dataLength = dlen;
   ENetAddress address;

   BIO_clear_retry_flags (b);
   int peek = enet_socket_peek_address (connection -> socket, & address);
   if (peek < 0)
      return 0;
   
    // tried to read data but the latest incoming was for a different connection.
    // return success with 0 bytes read
   if (peek == 0 || !enet_address_equal(& address, & connection -> address))
   {
      BIO_set_retry_read (b);
      if (readbytes)
         *readbytes = 0;
      return 1;
   }

   int result = enet_socket_receive (connection -> socket, & address, & buffer, 1);
   if (result < 0)
     return 0;
   if (readbytes)
     *readbytes = result;
   return 1;
}

int BIO_s_enet_read (BIO * b, char * data, int dlen)
{
   size_t bytesread;
   if (BIO_s_enet_read_ex (b, data, dlen, & bytesread))
      return (int)bytesread;
   return -1;
}

long BIO_s_enet_ctrl (BIO * b, int cmd, long larg, void * pargs)
{
   long ret = 0;
  
   ENetSslSocketConnection * connection = (ENetSslSocketConnection *)BIO_get_data (b);
   switch (cmd)
   {
   case BIO_CTRL_FLUSH:
      ret = 1;
      break;
   case BIO_CTRL_DGRAM_SET_CONNECTED:
   case BIO_CTRL_DGRAM_SET_PEER:
      if (pargs != NULL)
         connection -> address = * (ENetAddress *)pargs;
      else
      {
         connection -> address.host = INADDR_ANY;
         connection -> address.port = 0;
      }
      ret = 0;
      break;
   case BIO_CTRL_DGRAM_GET_PEER:
     if (pargs == NULL)
        ret = 0;
     else
     {
        * (ENetAddress *)pargs = connection -> address;
        ret = 1;
      }
      break;
   case BIO_CTRL_WPENDING:
      ret = 0;
      break;
   case BIO_CTRL_DGRAM_QUERY_MTU:
      ret = ENET_PROTOCOL_MAXIMUM_MTU - enet_socket_get_header_size (connection -> socket);
      break;
   case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
      ret = ENET_PROTOCOL_MINIMUM_MTU - enet_socket_get_header_size (connection -> socket);
      break;
   case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
      ret = enet_socket_get_header_size (connection -> socket);
    break;
   case BIO_CTRL_EOF:
   case BIO_CTRL_PUSH:
   case BIO_CTRL_POP:
      ret = 0;
      break;
   case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
      ret = 0;
      break;
   case BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP:
      ret = 0;
      break;
   case BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP:
      ret = 0;
      break;
   default:
      fprintf (stderr, "BIO_s_enet_ctrl(BIO[%p], cmd[%d], larg[%ld], pargs[%p])\n", b, cmd, larg, pargs);
      fprintf (stderr, "  unknown cmd: %d\n", cmd);
      fflush (stderr);
      ret = 0;
      break;
   }

   return ret;
}

int BIO_s_enet_create (BIO * b)
{
   fprintf (stderr, "BIO_s_enet_create(BIO[%p])\n", b);
   fflush (stderr);

   return 1;
}

int BIO_s_enet_destroy (BIO * b)
{
   fprintf(stderr, "BIO_s_enet_destroy(BIO[%p])\n", b);
   fflush(stderr);

   return 1;
}

BIO_METHOD * _BIO_s_enet = NULL;
BIO_METHOD * BIO_s_enet (void)
{
   if (_BIO_s_enet)
      return _BIO_s_enet;

   _BIO_s_enet = BIO_meth_new (BIO_get_new_index () | BIO_TYPE_SOURCE_SINK, "BIO_s_enet");

   BIO_meth_set_write_ex (_BIO_s_enet, BIO_s_enet_write_ex);
   BIO_meth_set_write (_BIO_s_enet, BIO_s_enet_write);
   BIO_meth_set_read_ex (_BIO_s_enet, BIO_s_enet_read_ex);
   BIO_meth_set_read (_BIO_s_enet, BIO_s_enet_read);
   BIO_meth_set_ctrl (_BIO_s_enet, BIO_s_enet_ctrl);
   BIO_meth_set_create (_BIO_s_enet, BIO_s_enet_create);
   BIO_meth_set_destroy (_BIO_s_enet, BIO_s_enet_destroy);

   return _BIO_s_enet;
}

void BIO_s_enet_meth_free(void)
{
   if (_BIO_s_enet)
      BIO_meth_free (_BIO_s_enet);

   _BIO_s_enet = NULL;
}

static int SSL_CTX_use_certificate_chain_data (SSL_CTX * ctx, const char * data)
{
   BIO * in;
   int ret = 0;
   X509 * x = NULL;
   pem_password_cb * passwd_callback;
   void * passwd_callback_userdata;

   if (ctx == NULL)
      return 0;

   ERR_clear_error (); //clear error stack for SSL_CTX_use_certificate()

   passwd_callback = SSL_CTX_get_default_passwd_cb (ctx);
   passwd_callback_userdata = SSL_CTX_get_default_passwd_cb_userdata (ctx);

   in = BIO_new_mem_buf ((void *)data, -1);
   if (in == NULL) 
      return 0;

   if ((x = PEM_read_bio_X509_AUX (in, NULL, passwd_callback,
                                   passwd_callback_userdata)) == NULL) 
      goto end;

   ret = SSL_CTX_use_certificate (ctx, x);
    
   if (ERR_peek_error() != 0)
      ret = 0; // Key/certificate mismatch doesn't imply ret==0 ...

   if (ret) 
   {
      // If we could set up our certificate, now proceed to the CA certificates.
      X509 *ca;
      unsigned long err;

      if (SSL_CTX_clear_chain_certs (ctx) == 0) 
      {
         ret = 0;
         goto end;
      }

      while ((ca = PEM_read_bio_X509(in, NULL, passwd_callback,
                                     passwd_callback_userdata)) != NULL)
      {
         // Note that we must not free ca if it was successfully added to
         // the chain (while we must free the main certificate, since its
         // reference count is increased by SSL_CTX_use_certificate).
         if (!SSL_CTX_add0_chain_cert (ctx, ca)) 
         {
            X509_free (ca);
            ret = 0;
            goto end;
         }
      }
      // When the while loop ends, it's usually just EOF.
      err = ERR_peek_last_error ();
      if (ERR_GET_LIB (err) == ERR_LIB_PEM
          && ERR_GET_REASON (err) == PEM_R_NO_START_LINE)
         ERR_clear_error();
      else
         ret = 0; // some real error
   }

end:
   X509_free(x);
   BIO_free(in);
   return ret;
}

static int SSL_CTX_use_PrivateKey_data (SSL_CTX * ctx, const char * data, int type)
{
   int ret = 0;
   BIO * in;
   EVP_PKEY * pkey = NULL;
   pem_password_cb* passwd_callback;
   void* passwd_callback_userdata;

   if (ctx == NULL)
     return 0;

   ERR_clear_error(); //clear error stack for SSL_CTX_use_PrivateKey ()

   passwd_callback = SSL_CTX_get_default_passwd_cb (ctx);
   passwd_callback_userdata = SSL_CTX_get_default_passwd_cb_userdata (ctx);

   in = BIO_new_mem_buf ((void *)data, -1);
   if (in == NULL) 
      return 0;

   if (type == SSL_FILETYPE_PEM) 
   {
      pkey = PEM_read_bio_PrivateKey (in, NULL,
                                      passwd_callback,
                                      passwd_callback_userdata);
   } else
      goto end;

   if (pkey == NULL) 
      goto end;

   ret = SSL_CTX_use_PrivateKey (ctx, pkey);
   EVP_PKEY_free (pkey);
end:
   BIO_free (in);
   return ret;
}

static int SSL_CTX_load_verify_data (SSL_CTX * ctx, const char * data)
{
   BIO * in;
   int ret = 0;
   X509_STORE * cert_store = NULL;
   pem_password_cb* passwd_callback;
   void* passwd_callback_userdata;

   if (ctx == NULL)
      return 0;

   ERR_clear_error (); //clear error stack for SSL_CTX_get_cert_store ()

   passwd_callback = SSL_CTX_get_default_passwd_cb (ctx);
   passwd_callback_userdata = SSL_CTX_get_default_passwd_cb_userdata (ctx);

   cert_store = SSL_CTX_get_cert_store (ctx);
   if (cert_store == NULL)
      return 0;

   in = BIO_new_mem_buf ((void *)data, -1);
   if (in == NULL) 
      return 0;

   X509 *ca;
   int r;
   unsigned long err;

   while ((ca = PEM_read_bio_X509 (in, NULL, passwd_callback,
                                   passwd_callback_userdata)) != NULL)
   {
      r = X509_STORE_add_cert (cert_store, ca);
      X509_free (ca);
      if (!r)
      {
         ret = 0;
         goto end;
      }
   }
   // When the while loop ends, it's usually just EOF.
   err = ERR_peek_last_error ();
   if (ERR_GET_LIB (err) == ERR_LIB_PEM
       && ERR_GET_REASON (err) == PEM_R_NO_START_LINE)
      ERR_clear_error();
   else
      ret = 0; // some real error

end:
   BIO_free(in);
   return ret;
}

ENetSslSocket *
enet_ssl_socket_create (const ENetSslConfiguration * sslConfiguration)
{
   ENetSslSocket * ssl = (ENetSslSocket *)enet_malloc (sizeof (ENetSslSocket));

   ssl -> mode = sslConfiguration == NULL ? ENET_SSL_MODE_NONE : sslConfiguration -> mode;
   ssl -> ctx = NULL;
   ssl -> hostName = NULL;
   enet_list_clear (& ssl -> connectionList);
   
   ssl -> socket = enet_socket_create (ENET_SOCKET_TYPE_DATAGRAM);
   if (ssl -> socket == ENET_SOCKET_NULL)
   {
      enet_ssl_socket_destroy (ssl);
      return NULL;
   }

   if (ssl -> mode == ENET_SSL_MODE_NONE)
     return ssl;

   ssl -> ctx = SSL_CTX_new (ssl -> mode == ENET_SSL_MODE_SERVER ? DTLS_server_method () : DTLS_client_method ());
  
   // Just use the default cipher list to give us the broadest compatibility
   SSL_CTX_set_cipher_list (ssl -> ctx, "DEFAULT");
   SSL_CTX_set_session_cache_mode (ssl -> ctx, SSL_SESS_CACHE_OFF);

   if (ssl -> mode == ENET_SSL_MODE_SERVER)
   {
      if (sslConfiguration -> certificatePath != NULL && sslConfiguration -> certificatePath [0] != '\0')
      {
         if (!SSL_CTX_use_certificate_chain_file (ssl -> ctx, sslConfiguration -> certificatePath))
         {
#ifdef ENET_DEBUG
            fprintf (stderr, "ERROR: failed to load certificate file!\n");
#endif
            enet_ssl_socket_destroy (ssl);
            return NULL;
         }
      }
      else if (sslConfiguration -> certificate != NULL && sslConfiguration -> certificate [0] != '\0')
      {
         if (!SSL_CTX_use_certificate_chain_data (ssl -> ctx, sslConfiguration -> certificate))
         {
#ifdef ENET_DEBUG
            fprintf (stderr, "ERROR: failed to load certificate data!\n");
#endif
            enet_ssl_socket_destroy (ssl);
            return NULL;
         }
      }
      else {
#ifdef ENET_DEBUG
            fprintf (stderr, "ERROR: no certificate provided!\n");
#endif
            enet_ssl_socket_destroy (ssl);
            return NULL;
      }

      if (sslConfiguration -> privateKeyPath != NULL && sslConfiguration -> privateKeyPath [0] != '\0')
      {
         if (!SSL_CTX_use_PrivateKey_file (ssl -> ctx, sslConfiguration -> privateKeyPath, SSL_FILETYPE_PEM))
         {
#ifdef ENET_DEBUG
            fprintf (stderr, "ERROR: failed to load private key file!\n");
#endif
            enet_ssl_socket_destroy (ssl);
            return NULL;
         }
      }
      if (sslConfiguration -> privateKey != NULL && sslConfiguration -> privateKey [0] != '\0')
      {
         if (!SSL_CTX_use_PrivateKey_data (ssl -> ctx, sslConfiguration -> privateKey, SSL_FILETYPE_PEM))
         {
#ifdef ENET_DEBUG
            fprintf (stderr, "ERROR: failed to load private key data!\n");
#endif
            enet_ssl_socket_destroy (ssl);
            return NULL;
         }
      }
      else {
#ifdef ENET_DEBUG
            fprintf (stderr, "ERROR: no private key provided!\n");
#endif
            enet_ssl_socket_destroy (ssl);
            return NULL;         
      }

      if (!SSL_CTX_check_private_key (ssl -> ctx))
      {
#ifdef ENET_DEBUG
         fprintf (stderr, "ERROR: invalid private key!\n");
#endif
         enet_ssl_socket_destroy (ssl);
         return NULL;
      }
      SSL_CTX_set_cookie_generate_cb (ssl -> ctx, & enet_generate_cookie);
      SSL_CTX_set_cookie_verify_cb (ssl -> ctx, & enet_verify_cookie);
      SSL_CTX_set_verify (ssl -> ctx, SSL_VERIFY_NONE, NULL);
   }
   else
   {
      SSL_CTX_set_verify (ssl -> ctx, SSL_VERIFY_PEER, enet_verify_server);
      SSL_CTX_set_default_verify_paths (ssl -> ctx);

      if (sslConfiguration -> rootCertificatePath != NULL && sslConfiguration -> rootCertificatePath [0] != '\0')
      {
         SSL_CTX_load_verify_locations (ssl -> ctx, sslConfiguration -> rootCertificatePath, NULL);
      }
      if (sslConfiguration -> rootCertificate != NULL && sslConfiguration -> rootCertificate [0] != '\0')
      {
         SSL_CTX_load_verify_data (ssl -> ctx, sslConfiguration -> rootCertificate);
      }

      if (sslConfiguration -> validateCertificate == 0)
      {
         SSL_CTX_set_cert_verify_callback (ssl -> ctx, enet_allow_all_certificates, NULL);
      }
      else if (sslConfiguration -> hostName == NULL)
      {
#ifdef ENET_DEBUG
         fprintf (stderr, "ERROR: hostName not specified!\n");
#endif
         enet_ssl_socket_destroy (ssl);
         return NULL;
      }
      else 
      {
         ssl -> hostName = OPENSSL_strdup (sslConfiguration -> hostName);
      }
   }

   SSL_CTX_set_verify_depth (ssl -> ctx, 3);
   SSL_CTX_set_read_ahead (ssl -> ctx, 1);
   SSL_CTX_set_options (ssl -> ctx, SSL_OP_NO_QUERY_MTU);

   return ssl;
}

int 
enet_address_equal(const ENetAddress * lAddress, const ENetAddress * rAddress)
{
   if (lAddress == NULL && rAddress == NULL)
      return 1;

   if (lAddress == NULL || rAddress == NULL)
      return 0;

   return lAddress -> host == rAddress -> host && lAddress -> port == rAddress -> port;
}

int
enet_ssl_socket_get_address (const ENetSslSocket * ssl, ENetAddress * address)
{
   return enet_socket_get_address (ssl -> socket, address);
}

int
enet_ssl_socket_bind (ENetSslSocket * ssl, const ENetAddress * address)
{
   return enet_socket_bind (ssl -> socket, address);
}

int
enet_ssl_socket_receive (ENetSslSocket * ssl, ENetAddress * address, ENetBuffer * buffer, size_t bufferCount)
{
   if (ssl -> mode == ENET_SSL_MODE_NONE)
     // if ssl is disabled, pass through to the socket
     return enet_socket_receive (ssl -> socket, address, buffer, bufferCount);

   int result = 0;
   while (result == 0)
   {
      int peek = enet_socket_peek_address (ssl -> socket, address);
      if (peek <= 0)
         return peek;

      // verify we have a connection to send to
      ENetSslSocketConnection * connection = NULL;
      ENetSslSocketConnection * listenerConnection = NULL;

      for (ENetListIterator currentConnection = enet_list_begin (& ssl -> connectionList); 
           currentConnection != enet_list_end (& ssl -> connectionList); 
           currentConnection = enet_list_next (currentConnection)) 
      {
         ENetSslSocketConnection * con = (ENetSslSocketConnection *)currentConnection;
         if (con -> state != ENET_SSL_SOCKET_CONNECTION_STATE_NONE &&
             con -> state != ENET_SSL_SOCKET_CONNECTION_STATE_LISTENING &&
             enet_address_equal(& con -> address, address))
         {
            connection = con;
            break;
         }

         if (con -> state == ENET_SSL_SOCKET_CONNECTION_STATE_LISTENING)
            listenerConnection = con;
      }

      if (connection == NULL && ssl -> mode == ENET_SSL_MODE_SERVER)
      {
         if (listenerConnection == NULL)
            // start listening now
            listenerConnection = enet_ssl_socket_connection_create_listener (ssl);
         connection = listenerConnection;
      }

      if (connection == NULL)
      {
         // read the data from the socket, then discard (it's not encrypted)
         enet_socket_receive (ssl -> socket, address, buffer, bufferCount);
         continue;
      }
      
      if (connection -> state == ENET_SSL_SOCKET_CONNECTION_STATE_LISTENING)
      {
         if (enet_ssl_socket_connection_accept (connection, address) > 0)
            // create a new connection to server as the listener for new connections
            listenerConnection = enet_ssl_socket_connection_create_listener (ssl);
      }

      if (enet_ssl_socket_connection_update_connection_state (connection) < 0)
      {
         enet_ssl_socket_connection_destroy (connection);
         continue;
      }

      if (connection -> state != ENET_SSL_SOCKET_CONNECTION_STATE_CONNECTED)
         continue;

      if (SSL_get_shutdown (connection -> ssl) & SSL_RECEIVED_SHUTDOWN) 
      {
         SSL_shutdown (connection -> ssl);
         enet_ssl_socket_connection_destroy (connection);            
         continue;
      }

      result = enet_ssl_read (connection, buffer -> data, (int)buffer -> dataLength);      
      if (result > 0)
         connection -> lastReadTime = enet_time_get ();

      if (result < 0)
         enet_ssl_socket_connection_destroy (connection);
   }

   return result;
}



static int
enet_ssl_merge_buffers (ENetSslSocket * ssl, const ENetBuffer * buffer, const size_t bufferCount, ENetBuffer * result)
{
   if (result == NULL)
      return -1;
  
   if (bufferCount == 1)
   {
      // if there is only one buffer, no need to merge, just use it as is
      result -> data = buffer -> data;
      result -> dataLength = buffer -> dataLength;
      return 0;
   }

   result -> data = ssl -> sendBuffer;
   result -> dataLength = 0;

   // copy data to send buffer
   for (int i = 0; i < bufferCount; i++)
   {
      if (result -> dataLength + buffer [i].dataLength > sizeof (ssl -> sendBuffer))
         // trying to send too much data!
         return -1;

      memcpy (ssl -> sendBuffer + result -> dataLength, buffer [i].data, buffer [i].dataLength);
      result -> dataLength += buffer [i].dataLength;
   }

   return 0;
}

int
enet_ssl_socket_send (ENetSslSocket * ssl, const ENetAddress * address, const ENetBuffer * buffer, size_t bufferCount)
{
   if (ssl -> mode == ENET_SSL_MODE_NONE)
      // if ssl is disabled, pass through to the socket
      return enet_socket_send (ssl -> socket, address, buffer, bufferCount);

   // verify we have a connection to send to
   ENetSslSocketConnection * connection = NULL;
   for (ENetListIterator currentConnection = enet_list_begin (& ssl -> connectionList); 
           currentConnection != enet_list_end (& ssl -> connectionList); 
           currentConnection = enet_list_next (currentConnection)) 
   {
      ENetSslSocketConnection * con = (ENetSslSocketConnection *)currentConnection;
      if (con -> state != ENET_SSL_SOCKET_CONNECTION_STATE_NONE &&
          con -> state != ENET_SSL_SOCKET_CONNECTION_STATE_LISTENING &&
          enet_address_equal(& con -> address, address))
      {
         connection = con;
         break;
      }
   }

   if (ssl -> mode == ENET_SSL_MODE_CLIENT && connection == NULL)
      connection = enet_ssl_socket_connection_create_connect (ssl, address);

   if (connection == NULL)
      return 0;

   if (enet_ssl_socket_connection_update_connection_state (connection) < 0)
   {
      enet_ssl_socket_connection_destroy (connection);
      return -1;
   }

   if (connection -> state != ENET_SSL_SOCKET_CONNECTION_STATE_CONNECTED)
      return 0;

   if (SSL_get_shutdown (connection -> ssl) & SSL_RECEIVED_SHUTDOWN) 
   {
      SSL_shutdown (connection -> ssl);
      enet_ssl_socket_connection_destroy (connection);
      return 0;
   }

   ENetBuffer sendBuffer;
   if (enet_ssl_merge_buffers (ssl, buffer, bufferCount, & sendBuffer) < 0)
      return -1;

   int result = enet_ssl_write (connection, sendBuffer.data, (int)sendBuffer.dataLength);
   
   if (result < 0)
      enet_ssl_socket_connection_destroy (connection);

   return result;
}

int
enet_ssl_socket_wait (ENetSslSocket * ssl, enet_uint32 * condition, enet_uint32 timeout)
{
   // this is a good place to clean up timed out/closed ssl sockets
   for (ENetListIterator currentConnection = enet_list_begin (& ssl -> connectionList);
        currentConnection != enet_list_end (& ssl -> connectionList);
        currentConnection = enet_list_next (currentConnection))
   {
      ENetSslSocketConnection * connection = (ENetSslSocketConnection *)currentConnection;

      if (connection -> state == ENET_SSL_SOCKET_CONNECTION_STATE_LISTENING)
         // listener always valid
         continue;

      if (enet_ssl_socket_connection_update_connection_state (connection) < 0)
      {
         currentConnection = enet_list_previous (currentConnection);
         enet_ssl_socket_connection_destroy (connection);
         continue;
      }

      if (connection -> state == ENET_SSL_SOCKET_CONNECTION_STATE_CONNECTED)
      {
         if (SSL_get_shutdown (connection -> ssl) & SSL_RECEIVED_SHUTDOWN)
         {
            SSL_shutdown (connection -> ssl);
            currentConnection = enet_list_previous (currentConnection);
            enet_ssl_socket_connection_destroy (connection);
            continue;
         }
      }

      if (connection -> lastReadTime + connection -> timeout.tv_sec * 1000 + connection -> timeout.tv_usec / 1000 < enet_time_get())
      {
         currentConnection = enet_list_previous (currentConnection);
         enet_ssl_socket_connection_destroy (connection);
      }
   }

   return enet_socket_wait(ssl -> socket, condition, timeout);
}

int
enet_ssl_socket_set_option (ENetSslSocket * ssl, ENetSocketOption socketOption, int value)
{
   return enet_socket_set_option(ssl -> socket, socketOption, value);
}

int
enet_ssl_socket_get_option (const ENetSslSocket * ssl, ENetSocketOption socketOption, int * value)
{
   return enet_socket_get_option (ssl -> socket, socketOption, value);
}

int
enet_ssl_socket_get_header_size (const ENetSslSocket * ssl)
{
  return enet_socket_get_header_size (ssl -> socket) 
     + (ssl -> mode == ENET_SSL_MODE_NONE ? 0 : ENET_SSL_SOCKET_HEADER_SIZE);
}

void
enet_ssl_socket_destroy (ENetSslSocket * ssl)
{
   if (ssl == NULL)
      return;

   // clean up all of our connections
   while (enet_list_begin (& ssl -> connectionList) != enet_list_end (& ssl -> connectionList))
      enet_ssl_socket_connection_destroy (enet_list_front (& ssl -> connectionList));

   // destroy our ctx
   if (ssl -> ctx != NULL)
      SSL_CTX_free (ssl -> ctx);

   // close our socket
   if (ssl -> socket != ENET_SOCKET_NULL)
      enet_socket_destroy(ssl -> socket);

   // free hostname
   if (ssl -> hostName != NULL)
      OPENSSL_free (ssl -> hostName);

   // release the memory
   enet_free (ssl);
}