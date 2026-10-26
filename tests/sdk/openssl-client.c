/* Independent OpenSSL 3 peer test of the *installed* public Crypto C11 API.
 * There is no GmSSL header, GmSSL static link, or OpenSSL library link.
 */
#define _POSIX_C_SOURCE 200809L
#include <crypto/tls.h>
#include <crypto/tls_ext.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum { MAX_RUN_MS = 15000 };
typedef struct transport {
    int fd;
    unsigned short writes;
    unsigned short reads;
} transport;

static int64_t socket_write(void *user,const uint8_t *bytes,size_t len)
{
    transport *t=(transport *)user;
    size_t offered=len<73?len:73;
    ssize_t n=send(t->fd,bytes,offered,0);
    t->writes++;
    if(n>0)return (int64_t)n;
    if(n==0)return 0;
    if(errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)
        return CRYPTO_TLS_IO_AGAIN;
    return CRYPTO_TLS_IO_ERROR;
}

static int64_t socket_read(void *user,uint8_t *bytes,size_t capacity)
{
    transport *t=(transport *)user;
    size_t limit=capacity<41?capacity:41;
    ssize_t n=recv(t->fd,bytes,limit,0);
    t->reads++;
    if(n>=0)return (int64_t)n;
    if(errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)
        return CRYPTO_TLS_IO_AGAIN;
    return CRYPTO_TLS_IO_ERROR;
}

static int64_t monotonic_ms(void)
{
    struct timespec ts;
    if(clock_gettime(CLOCK_MONOTONIC,&ts)!=0)return -1;
    return (int64_t)ts.tv_sec*1000+ts.tv_nsec/1000000;
}

static void short_pause(void)
{
    struct timespec ts={0,1000000};
    nanosleep(&ts,NULL);
}

static int connected_socket(int port)
{
    int fd, flags;
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_port=htons((uint16_t)port);
    /* AppleClang strict POSIX C11 headers may hide INADDR_LOOPBACK.
     * Parse the explicit IPv4 loopback literal instead of a platform macro. */
    if(inet_pton(AF_INET,"127.0.0.1",&addr.sin_addr)!=1)return -1;
    fd=socket(AF_INET,SOCK_STREAM,0);
    if(fd<0)return -1;
    if(connect(fd,(struct sockaddr *)&addr,sizeof(addr))!=0){
        close(fd);return -1;
    }
    flags=fcntl(fd,F_GETFL,0);
    if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)!=0){
        close(fd);return -1;
    }
    return fd;
}

int main(int argc,char **argv)
{
    crypto_tls_provider *provider=NULL;
    crypto_tls_session *session=NULL;
    crypto_tls_session_options options;
    crypto_tls_io io;
    static const char *alpn_names[] = {"http/1.1", "h2"};
    crypto_tls_session_info_v1_1 info;
    crypto_tls_result status=CRYPTO_TLS_INVALID_ARGUMENT;
    transport t={-1,0,0};
    int port,protocol,want_success,success=0,step,rc=1;
    int64_t deadline;
    static const uint8_t request[]="GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    uint8_t response[8192];
    size_t total=0,sent=0;
    int sending=1;
    if(argc!=6){fprintf(stderr,"usage: sdk-openssl-client 12|13 port ca-file hostname good|reject\n");return 2;}
    if(strcmp(argv[1],"12")==0)protocol=CRYPTO_TLS_1_2;
    else if(strcmp(argv[1],"13")==0)protocol=CRYPTO_TLS_1_3;
    else return 2;
    port=atoi(argv[2]);
    want_success=strcmp(argv[5],"good")==0;
    if(port<1||port>65535||!argv[3][0]||!argv[4][0]
       ||(!want_success&&strcmp(argv[5],"reject")!=0))return 2;
    signal(SIGPIPE,SIG_IGN);
    t.fd=connected_socket(port);
    if(t.fd<0){perror("OpenSSL peer connect");return 3;}

    memset(&options,0,sizeof(options));
    options.struct_size=sizeof(options);
    options.protocol=(uint32_t)protocol;
    options.role=CRYPTO_TLS_CLIENT;
    options.verify_depth=4;
    options.hostname=argv[4];
    options.ca_file=argv[3];
    memset(&io,0,sizeof(io));
    io.struct_size=sizeof(io);
    io.user=&t;
    io.write=socket_write;
    io.read=socket_read;
    if(crypto_tls_provider_create(CRYPTO_TLS_ABI_VERSION,&provider)!=CRYPTO_TLS_OK
       || crypto_tls_session_create(provider,&options,&io,&session)!=CRYPTO_TLS_OK
       || crypto_tls_extension_abi_version()!=CRYPTO_TLS_EXTENSION_ABI_VERSION
       || crypto_tls_session_set_alpn_v1_1(session,alpn_names,2)!=CRYPTO_TLS_OK)
        goto done;
    deadline=monotonic_ms()+MAX_RUN_MS;
    for(step=0;step<20000 && monotonic_ms()<deadline;step++){
        status=crypto_tls_session_handshake(session);
        if(status==CRYPTO_TLS_OK){success=1;break;}
        if(status!=CRYPTO_TLS_AGAIN)break;
        short_pause();
    }

    if(!want_success){
        /* Only an explicit failed handshake qualifies. Connection failure,
         * timeout or an unexpectedly successful handshake must fail the test. */
        if(!success && (status==CRYPTO_TLS_BACKEND_ERROR ||
                        status==CRYPTO_TLS_CLOSED) && t.writes && t.reads)
            rc=0;
        goto done;
    }
    if(!success){
        fprintf(stderr,"valid OpenSSL peer handshake failed: %d\n",(int)status);
        goto done;
    }

    memset(&info,0,sizeof(info));
    info.struct_size=sizeof(info);
    if(crypto_tls_session_get_info_v1_1(session,&info)!=CRYPTO_TLS_OK
        || info.protocol!=(uint32_t)protocol || info.cipher_suite==0u
        || !info.cipher_name[0] || info.alpn_size!=2u
        || strcmp(info.alpn,"h2")!=0) {
        fprintf(stderr,"OpenSSL ALPN/protocol inspection rejected or missing\n");
        goto done;
    }

    deadline=monotonic_ms()+MAX_RUN_MS;
    while(monotonic_ms()<deadline){
        if(sending){
            status=crypto_tls_session_send(session,request,sizeof(request)-1,&sent);
            if(status==CRYPTO_TLS_OK){
                if(sent!=sizeof(request)-1)goto done;
                sending=0;
            }else if(status!=CRYPTO_TLS_AGAIN)goto done;
        }
        if(!sending && total<sizeof(response)-1){
            size_t n=0;
            status=crypto_tls_session_receive(session,
                response+total,sizeof(response)-1-total,&n);
            if(status==CRYPTO_TLS_OK){
                if(!n||n>sizeof(response)-1-total)goto done;
                total+=n;
                response[total]=0;
                if(strstr((char *)response,"HTTP/1.0 200")){rc=0;break;}
            }else if(status!=CRYPTO_TLS_AGAIN)goto done;
        }
        short_pause();
    }
done:
    if(session && crypto_tls_session_destroy(&session)!=CRYPTO_TLS_OK)rc=1;
    if(provider && crypto_tls_provider_destroy(&provider)!=CRYPTO_TLS_OK)rc=1;
    if(t.fd>=0)close(t.fd);
    if(rc)fprintf(stderr,"facade OpenSSL %d %s failed handshake=%d status=%d records=%zu writes=%u reads=%u\n",
        protocol,argv[5],success,(int)status,total,t.writes,t.reads);
    else printf("Crypto installed C11 facade/OpenSSL 3 %d %s: PASS\n",protocol,argv[5]);
    return rc;
}
