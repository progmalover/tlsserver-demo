#include <stdio.h>
#include  <windows.h>
#include <WinSock.h>
#include <stdio.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/dh.h"
#include "openssl/bn.h"
#include "openssl/ossl_typ.h"
#include <exception>
#include "pch.h"
#include <iostream>
#include <string>
#include <streambuf>
#include <map>
using namespace std;
#define READ_BUFF_SIZE 4096

int create_socket(int port)
{
	WORD wVersionRequested;
	WSADATA wsaData={0};
	int err;
	wVersionRequested = MAKEWORD( 1, 1 );
	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) {
               
                return -1;
    }

	SOCKET s;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port); 
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s== INVALID_SOCKET) {
		DWORD dw = GetLastError();
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}
	 
	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Unable to bind");
		exit(EXIT_FAILURE);
	}

	if (listen(s, 1) < 0) {
		perror("Unable to listen");
		exit(EXIT_FAILURE);
	}

	return s;
}

void init_openssl()
{
	ERR_load_ERR_strings();
	OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT,0);
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

unsigned char vector[] = {
	8, 'h', 't', 't', 'p','/', '1','.','1'
};
int alpn_cb(SSL *ssl,
	const unsigned char **out,
    unsigned char *outlen,
    const unsigned char *in,
    unsigned int inlen,
    void *arg)
{
	 
	*out = in + 3;
	*outlen =9;
	return 	(int)SSL_TLSEXT_ERR_OK;;
	 
}

void * extcallback(void)
{
	static char * serv_name="www.vesystem.com";
	 
	return serv_name;
}

void configure_context(SSL_CTX *ctx)
{
	//SSL_CTX_set_ecdh_auto(ctx, 1);

	/* Set the key and cert */
	FILE *file = fopen("E:\\workspace\\tlsserver\\tlsserver\\x64\\Debug\\domain.crt","r");
	if(file != 0)
	{
		fclose(file);
	} 
	if (SSL_CTX_use_certificate_file(ctx, "E:\\workspace\\tlsserver\\tlsserver\\x64\\Debug\\domain.crt", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	file = fopen("E:\\workspace\\tlsserver\\tlsserver\\x64\\Debug\\domain.key","r");
	if(file != 0)
	{
		fclose(file);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "E:\\workspace\\tlsserver\\tlsserver\\x64\\Debug\\domain.key", SSL_FILETYPE_PEM) <= 0) {
		int err = ERR_get_error();
		printf("SSL_CTX_use_PrivateKey_file err : %d\n" , err);
	}
	//检查key和证书
	if(!SSL_CTX_check_private_key(ctx))
	{
			throw ("Certificate and Private key don't match.");
	}
	//not support outdate sslv2
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_CTX_get_options(ctx));

	//alpn conf 
	unsigned int length = sizeof(vector);
	//调不调用，都可以
	SSL_CTX_set_alpn_protos(ctx,vector,length);
	//alpn application-layer protocal negotiation
	//比较复杂的协商，默认有封装，使用默认即可
	//SSL_CTX_set_alpn_select_cb(ctx,alpn_cb,0);
	 //调不调用，都可以
	SSL_CTX_set_tlsext_servername_callback(ctx,extcallback);
	//
	 
}

void  GetLastErrorAndThrow(  bool bSSL, int nError ,string &strErr)
{
	const char * err = ERR_reason_error_string(bSSL?nError:ERR_get_error());
	if(0 != err)
	{
		strErr = err;
		////
		BIO* membio = BIO_new(BIO_s_mem());
		ERR_print_errors(membio);
		BUF_MEM *pbuf;
		BIO_get_mem_ptr(membio, &pbuf);
		if(pbuf->length > 0)
		{
			pbuf->data[pbuf->length-1] =0;
			strErr = pbuf->data;
		}
		BIO_free(membio);
		////
	}
	 
}

int main(int argc, char **argv)
{
	int sock;
	SSL_CTX *ctx;

	init_openssl();
	ctx = create_context();

	configure_context(ctx);

	sock = create_socket(443);

	/* Handle connections */
	while (1) {
		struct sockaddr_in addr;
		int len = sizeof(addr);
	 
		int client = accept(sock, (struct sockaddr*)&addr, &len);
		if (client < 0) {
			perror("Unable to accept");
			exit(EXIT_FAILURE);
		}
		//创建ssl
		 
		//
		//set fd
		SSL *ssl= SSL_new(ctx);
		int err = SSL_set_fd(ssl, client);
		if(err != 1)
			perror("SSL_set_fd");
	
		string strerr;
		byte buf[READ_BUFF_SIZE]={0};
		while(true)
		{
			err = SSL_accept(ssl);
		
			printf("SSL_accept:%d\n",err);
			if(err == 1)
				break; //success

		 	int serr = SSL_get_error(ssl,err);
			if (err == -1) {
					 
					int nb = -1;
					BIO *p;
				 
					int nRead = 0;
					if(serr == SSL_ERROR_WANT_READ)
							nRead = SSL_read(ssl, buf, READ_BUFF_SIZE);
					else if(serr == SSL_ERROR_WANT_WRITE)
							nRead = SSL_write(ssl, buf, READ_BUFF_SIZE);
					else
						{
							GetLastErrorAndThrow(false,serr,strerr);
							printf("ssl_accept fail:%d,and ssl_get_error:%s",err,strerr.c_str());
							closesocket(client);
							SSL_free(ssl);

						}
 
					
			}else
			{
					int serr = SSL_get_error(ssl,err);
					printf("ssl_accept fail:%d,and ssl_get_error:%d",err,serr);
					closesocket(client);
					return -1;
			}
			
		}
		 

        char *reply="test";
		int nc = SSL_read(ssl, buf, READ_BUFF_SIZE);
		buf[nc]= 0;
		printf((char *)buf);
		if(nc > 0)
			SSL_write(ssl, reply, strlen(reply));

		SSL_free(ssl);
		closesocket(client);
 
	}

	closesocket(sock);
	SSL_CTX_SRP_CTX_free(ctx);
	//cleanup_openssl();
}
