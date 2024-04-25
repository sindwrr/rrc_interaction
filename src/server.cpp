#include <RRCConnectionRequest.h>
#include <RRCConnectionSetup.h>
#include <RRCConnectionSetupComplete.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main(void) 
{
    // создаем сокет
    int server_fd = 0;
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // информация об адресе и порте клента
    struct sockaddr_in cl_addr;
    cl_addr.sin_family = AF_INET;
    cl_addr.sin_addr.s_addr = INADDR_ANY;
    cl_addr.sin_port = htons(PORT);
    int addrlen = sizeof(cl_addr);

    // разрешаем повторное использование адреса сервера
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, 
                   &opt, sizeof(opt)) == -1) 
    {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // привязаем сокет к адресу и порту сервера
    if (bind(server_fd, (struct sockaddr *)&cl_addr, sizeof(cl_addr)) < 0) 
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // слушаем входящие соединения
    if (listen(server_fd, 3) < 0) 
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // принимаем соединение от клиента
    int sock = 0;
    if ((sock = accept(server_fd, (struct sockaddr *)&cl_addr, 
                             (socklen_t*)&addrlen)) < 0) 
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    // принимаем и записываем RRCConnectionRequest в буфер
    int request_read = 0;
    char request_buffer[BUFFER_SIZE];
    if ((request_read = read(sock, request_buffer, BUFFER_SIZE)) < 0) 
    {
        perror("read");
        exit(EXIT_FAILURE);
    }

    // декодируем сообщение, заносим в структуру
    RRCConnectionRequest_t* request = 0;
    asn_dec_rval_t request_rval;
    request_rval = ber_decode(0, &asn_DEF_RRCConnectionRequest, 
                              (void **)&request, request_buffer, 
                              sizeof(request_buffer));
    if (request_rval.code != RC_OK)
    {
        printf("Error decoding the message!");
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionRequest, request);
        return 0;
    }

    // выводим Request в XML-формате
    printf("\nRRC Connection Request, from client:\n");
    xer_fprint(stdout, &asn_DEF_RRCConnectionRequest, request);
    
    // проверяем корректность заполнения Request
    int request_bad = 0;
    if (request->criticalExtensions.choice.rrcConnectionRequest_r8.ue_Identity
                .choice.randomValue.buf == (uint8_t*)"" ||
        request->criticalExtensions.choice.rrcConnectionRequest_r8.ue_Identity
                .choice.randomValue.size <= 0 ||
        request->criticalExtensions.choice.rrcConnectionRequest_r8
                .establishmentCause < 0 ||
        request->criticalExtensions.choice.rrcConnectionRequest_r8
                .establishmentCause > 7)
            request_bad = 1;
    
    // инициализируем и формируем RRCConnectionSetup
    RRCConnectionSetup_t *setup;
    setup = (RRCConnectionSetup_t*)calloc(1, sizeof(RRCConnectionSetup_t));
    if (!setup) 
    {
        perror("calloc() failed");
        exit(1);
    }

    setup->rrcConnectionSetup_r8
          .lateNonCriticalExtension = (OCTET_STRING*)calloc(1, 16);
    setup->rrcConnectionSetup_r8.lateNonCriticalExtension->size = 10;
    if (request_bad == 0)
    {
        setup->rrc_TransactionIdentifier = 0;
        setup->rrcConnectionSetup_r8
              .lateNonCriticalExtension->buf = (uint8_t*)"REQUEST_GOOD";
    }
    else
    {
        setup->rrc_TransactionIdentifier = 1;
        setup->rrcConnectionSetup_r8
              .lateNonCriticalExtension->buf = (uint8_t*)"REQUEST_BAD";        
    }

    // кодируем в буфер
    asn_enc_rval_t setup_ec;
    uint8_t setup_buffer[sizeof(setup)*5];
    setup_ec = der_encode_to_buffer(&asn_DEF_RRCConnectionSetup, setup, 
                                    setup_buffer, sizeof(setup_buffer));

    if (setup_ec.encoded == -1) 
    {
        fprintf(stderr, "Could not encode RRCConnectionRequest(at %s)\n",
                setup_ec.failed_type ? setup_ec.failed_type->name : "unknown");
        exit(1);
    } 
    
    // отправляем буфер клиенту
    send(sock, setup_buffer, BUFFER_SIZE, 0);

    // принимаем и записываем RRCConnectionSetupComplete в буфер
    int setup_cmplt_read = 0;
    char setup_cmplt_buffer[BUFFER_SIZE];
    if ((setup_cmplt_read = read(sock, setup_cmplt_buffer, BUFFER_SIZE)) < 0) 
    {
        perror("read");
        exit(EXIT_FAILURE);
    }    
    
    // декодируем сообщение, заносим в структуру
    RRCConnectionSetupComplete_t* setup_cmplt = 0;
    asn_dec_rval_t setup_cmplt_rval;
    setup_cmplt_rval = ber_decode(0, &asn_DEF_RRCConnectionSetupComplete, 
                                  (void **)&setup_cmplt, setup_cmplt_buffer, 
                                  sizeof(setup_cmplt_buffer));

    if (setup_cmplt_rval.code != RC_OK)
    {
        printf("Error decoding the message!");
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionSetupComplete, setup_cmplt);
        return 0;
    }

    // выводим Setup Complete в XML-формате
    printf("\nRRC Connection Setup Complete, from client:\n");
    xer_fprint(stdout, &asn_DEF_RRCConnectionSetupComplete, setup_cmplt);

    // закрываем сокет
    close(sock);
    return 0;
}