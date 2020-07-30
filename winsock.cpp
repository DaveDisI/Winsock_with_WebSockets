#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#include "TinySHA1.h"

#define DEFAULT_PORT "8080"
#define DEFAULT_BUFLEN 512

char base64Chars[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

char convertHexCharToByte(char hex){
    if(hex > '9'){
        return hex - 'a' + 10;
    }
    return hex - '0';
}

void convertHexStringToByteArray(char* str, unsigned char* buffer){
    int bctr = 0;
    for(int i = 0; i < 40; i += 2){
        char b1 = convertHexCharToByte(str[i]);
        char b2 = convertHexCharToByte(str[i + 1]);
        buffer[bctr++] = b1 * 16 + b2;
    }
}

void convertByteArrayToBase64String(unsigned char* byteArray, char* b64Str){
    int bctr = 0;
    for(int i = 0; i < 18; i += 3){
        char b1 = byteArray[i] >> 2;
        char b2 = ((byteArray[i] & 3) << 4) | (byteArray[i + 1] >> 4);
        char b3 = ((byteArray[i + 1] & 15) << 2) | (byteArray[i + 2] >> 6);
        char b4 = byteArray[i + 2] & 63;
        b64Str[bctr++] = base64Chars[b1];
        b64Str[bctr++] = base64Chars[b2];
        b64Str[bctr++] = base64Chars[b3];
        b64Str[bctr++] = base64Chars[b4];
    }
    char b1 = byteArray[18] >> 2;
    char b2 = ((byteArray[18] & 3) << 4) | (byteArray[19] >> 4);
    char b3 = (byteArray[19] & 15) << 2;
    b64Str[bctr++] = base64Chars[b1];
    b64Str[bctr++] = base64Chars[b2];
    b64Str[bctr++] = base64Chars[b3];
    b64Str[bctr++] = '=';
    b64Str[bctr] = '\0';
}

void convertWebSocketKey(char* webSocketKey, char* webSocketAccept){
    char* magicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char wskWithMagicString[128];
    int cCtr = 0;
    char* c = webSocketKey;
    while(*c != '\0'){
        wskWithMagicString[cCtr++] = *c;
        c++;
    }
    c = magicString;
    while(*c != '\0'){
        wskWithMagicString[cCtr++] = *c;
        c++;
    }
    wskWithMagicString[cCtr] = '\0';

    sha1::SHA1 s;
    s.processBytes(wskWithMagicString, cCtr);
    uint32_t digest[5];
    s.getDigest(digest);	
    char sha1Encoding[41];
    snprintf(sha1Encoding, 41, "%08x%08x%08x%08x%08x", digest[0], digest[1], digest[2], digest[3], digest[4]);
    printf("Calculated : (\"%s\") = %s\n", wskWithMagicString, sha1Encoding);
    unsigned char byteArray[20];
    convertHexStringToByteArray(sha1Encoding, byteArray);

    convertByteArrayToBase64String(byteArray, webSocketAccept);
    printf("b64: %s\n", webSocketAccept);
}

void getWebSocketKeyFromString(char* str, char* wskBuffer){
    int kbctr = 0;
    char* c = str;
    while(*c != '\0'){
        if(*c != 'S'){
            while(*c != '\n') c++;
        }else{
            c += 17;
            if(*c == ':'){
                c += 2;
                while(*c != '\r'){
                    wskBuffer[kbctr++] = *c;
                    c++;
                }
                c += 2;
            }
        }
        c++;
    }
    wskBuffer[kbctr] = '\0';
}

long readBitsFromArray(char* array, long b2r, int* offset){
    int byteCt = *offset / 8;
    int bitCt = *offset % 8;

    char currentByte = array[byteCt];
    long result = 0;

    for(int i = 0; i < b2r; i++){
        result |= ((currentByte << bitCt) & 0b10000000) >> 7;
        bitCt++;
        if(bitCt == 8){
            bitCt = 0;
            byteCt++;
            currentByte = array[byteCt]; 
        }
        if(i < b2r - 1){
            result <<= 1;
        }
    }

    *offset += b2r;
    return result;
}

void processFrame(char* dat, int len){
    int offset = 0;
    char fin = readBitsFromArray(dat, 1, &offset);
    char rsv[3] = {
        (char)readBitsFromArray(dat, 1, &offset), 
        (char)readBitsFromArray(dat, 1, &offset), 
        (char)readBitsFromArray(dat, 1, &offset)
    };
    char opcode = readBitsFromArray(dat, 4, &offset);
    char mask = readBitsFromArray(dat, 1, &offset);
    long payloadLen = readBitsFromArray(dat, 7, &offset);

    if(payloadLen == 126){
        payloadLen = readBitsFromArray(dat, 16, &offset);
    }else if(payloadLen == 127){
        payloadLen = readBitsFromArray(dat, 64, &offset);
    }

    printf("fin: %u\n", fin);
    printf("rsv1: %u  rsv2: %u  rsv3: %u\n", rsv[0], rsv[1], rsv[2]);
    printf("opcode: %u\n", opcode);
    printf("mask: %u\n", mask);
    printf("payloadLen: %u\n", payloadLen);
    printf("\n");

    
    if(mask){
        char maskKey[4] = {
            (char)readBitsFromArray(dat, 8, &offset),
            (char)readBitsFromArray(dat, 8, &offset),
            (char)readBitsFromArray(dat, 8, &offset),
            (char)readBitsFromArray(dat, 8, &offset),
        };
        for(int i = 0; i < payloadLen; i++){
            char av = readBitsFromArray(dat, 8, &offset);
            av ^= maskKey[i % 4];
            printf("CHARACTER: %c\n", av);
        }
    }else{

    }
}

int main() {
    printf("Starting\n\n");
    WSADATA wsaData;
    int iResult;
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }

    addrinfo* result = 0; 
    addrinfo* ptr = 0; 
    addrinfo hints = {};

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if(iResult != 0){
        printf("getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    SOCKET ListenSocket = INVALID_SOCKET;
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if(ListenSocket == INVALID_SOCKET){
        printf("Error at socket(): %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    freeaddrinfo(result);

    if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR){
        printf( "Listen failed with error: %ld\n", WSAGetLastError() );
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    SOCKET ClientSocket = INVALID_SOCKET;

    ClientSocket = accept(ListenSocket, 0, 0);
    printf("client accepted\n");
    if(ClientSocket == INVALID_SOCKET){
        printf("accept failed: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    char* resp = "\
HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: \0";
    
    int resplen = 0;
    char* c = resp;
    while(*c != '\0'){
        resplen++;
        c++;
    }

    char* magicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11\0";
    char recvbuf[DEFAULT_BUFLEN];
    char responseBuffer[DEFAULT_BUFLEN];
    char keyBuffer[128];
    char base64Str[29];
    int iSendResult = 0;
    int recvbuflen = DEFAULT_BUFLEN;
    iResult = 1;

    bool keyExchanged = false;

    while(iResult > 0){
        iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
        if(iResult > 0){
            printf("Bytes received: %d\n", iResult);
            recvbuf[iResult] = '\0';
            if(!keyExchanged){
                getWebSocketKeyFromString(recvbuf, keyBuffer);
                convertWebSocketKey(keyBuffer, base64Str);
                c = resp;
                int rbctr = 0;
                while(*c != '\0'){
                    responseBuffer[rbctr++] = *c;
                    c++;
                }
                for(int i = 0; i < 28; i++){
                    responseBuffer[rbctr++] = base64Str[i];
                }
                responseBuffer[rbctr++] = '\r';
                responseBuffer[rbctr++] = '\n';
                responseBuffer[rbctr++] = '\r';
                responseBuffer[rbctr++] = '\n';

                iSendResult = send(ClientSocket, responseBuffer, rbctr, 0);
                keyExchanged = true;
                continue;
            }

            processFrame(recvbuf, iResult);

            int sendCode = 8454463;
            char sendVal[3] = {(char)129, 1, 63};
            iSendResult = send(ClientSocket, sendVal, 3, 0);
            if(iSendResult == SOCKET_ERROR){
                printf("send failed with error: %d\n", WSAGetLastError());
                closesocket(ClientSocket);
                WSACleanup();
                return 1;
            }
            printf("Bytes sent: %d\n", iSendResult);
        }
        else if (iResult == 0)
            printf("Connection closing...\n");
        else  {
            printf("recv failed with error: %d\n", WSAGetLastError());
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        }

    }

    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    printf("\n\nEnding\n");
    return 0;
}