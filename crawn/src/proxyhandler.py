import ssl
import asyncio
import aiohttp

""" this is a rudementary implementation of a proxyhandler similar to the burp proxy that basically intercepts
traffic on a certain port in thsi case we are using burps port 8080 since it has a signed certificate"""


class ProxyHandler:
    def __init__(self, host="127.0.0.1", port="8081"):
        self.host = host  # the default host(this computer)
        self.port = port  # the default
        self.certfile = "./proxycert/cert.pem"
        self.keyfile = "./proxycert/key.pem"
        # use the pass phrase you used while generating the pem files
        self.passPhrase = "11039202200105@T"

    def DissectPacket(self, packet: str):
        headersBodyDis = packet.split("\r\n")
        packetBody = headersBodyDis[-1]
        packetHeaders = headersBodyDis[:-1]

        packetHeadersDict = {}
        for packetHeader in packetHeaders:
            keyValue = packetHeader.split(":")
            key, value = keyValue[0], keyValue[1]
            packetHeadersDict[key] = value

        packetMethod = packetHeaders[0].split(" ")[0]
        host = packetHeadersDict["Host"]
        path = packetHeaders[0].split(" ")[1]
        packetUrl = host + path.split("?")[0]
        packetParams = path.split("?")[1]

        return packetMethod, packetUrl, packetHeaders, packetParams, packetBody

    async def HandleBrowserRequest(self, request: bytes):
        browserRequest = request.decode("utf-8")
        (
            requestMethod,
            requestUrl,
            requestHeaders,
            requestParams,
            requestBody,
        ) = self.DissectPacket(browserRequest)
        if requestBody is not None and requestParams is not None:
            async with aiohttp.request(
                method=requestMethod,
                url=requestUrl,
                headers=requestHeaders,
                allow_redirects=True,
                data=requestBody,
                params=requestParams,
            ) as response:
                responsePacket = await response.read()
        elif requestBody is None and requestParams is None:
            async with aiohttp.request(
                method=requestMethod,
                url=requestUrl,
                headers=requestHeaders,
                allow_redirects=True,
            ) as response:
                responsePacket = await response.read()
        elif requestBody is None and requestParams is not None:
            async with aiohttp.request(
                method=requestMethod,
                url=requestUrl,
                headers=requestHeaders,
                allow_redirects=True,
                params=requestParams,
            ) as response:
                responsePacket = await response.read()
        elif requestBody is not None and requestParams is None:
            async with aiohttp.request(
                method=requestMethod,
                url=requestUrl,
                headers=requestHeaders,
                allow_redirects=True,
                data=requestBody,
            ) as response:
                responsePacket = await response.read()

        return responsePacket

    async def HandleClient(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        browserRequest = reader.read(1600)
        print(browserRequest.decode("utf-8"))
        responsePacket = self.HandleBrowserRequest(browserRequest)
        print(responsePacket.decode("utf-8"))
        writer.write(responsePacket)
        await writer.drain()

    async def StartServer(self):
        self.sslcontext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.sslcontext.load_cert_chain(
            certfile=self.certfile, keyfile=self.keyfile, password=self.passPhrase
        )
        server = await asyncio.start_server(
            self.HandleClient, self.host, self.port, ssl=self.sslcontext
        )
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    proxy = ProxyHandler()
    asyncio.run(proxy.StartServer())
