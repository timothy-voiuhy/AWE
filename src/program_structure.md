### AtomCore:
    session(cookie support): aiohttp.ClientSession
    wrapper_methods_supported:
        get, post
    Functionalities:
        crawling:
            ->Fetching and saving all the html from all the html links in the page (depth depends on the recursiveness level)[Mirroring]
            ->Uses basic xml detection for each page loaded ie {.xml* regex}
                implications:
                    40% probability of false positives
            ->

### proxy_handler
    session: httpx._client.Client
    Functionalities:
        proxy support 
    problems:
        lack of websocket intergration support
            reason:
                during upgrading from http(s) to websockets the same encryption used in https is supposed to be used even to encrypt websocket messages however the program is sofar using httpx which handles https encryption in the background and providing no api.
            solution:
                1.Building a custom http(s) handler that allows direct websocket intergration incase of an upgrade.
                <!-- 2.library if any -->

### Atomgui
    Functionalities:
        basic gui support
        proxy-gui (api) incase of http(s) support

### program upgrades:
    1.Micro services:
        1.Session handler:
            details:
                a single module to handle sending and recieving http(s), websocket support to and from the application.
            use modules:
                crawler
                analysis engine
                proxy
        2.Analysis Engine:
            details:
                module to analyze any page(s) presented to it check for known vulnerabilities, DOM xss injection
            pages:
                html
                css
                java script
        3.Proxy
            details:
                basic proxy support to and from clients
            clients:
                browsers
                operating systems
                etc
        4.gui interface
        5.Testing(Attacking) Engine:
            details:
                launching tests(attacks) to the target endpoint
            Functionalities:
                intruder support
                use of thirdparty tools for some testing mechanisms
        6.Vpn servive
            details:
                use of specific vpn providers to change the ip of the machine periodically depending on what the application is doing
            providers:
                openvpn
                tor
                proton vpn
    2.Micro-services controller
        details:
            Does not directly control the microservices but just restarts one incase it had gone off(logs the event, if the gui service is up and running then it informs the user) since each microservice runs independently providing just an api(can be an IPC mechanism , etc) and may be also setting hyper-parameters for the program.

### micro-service Session Handler
    Running host:port
    data-type: json
    {
        method:
        url:
        params:
        headers:
    }
    basic functions:
        server_side:
            dataDeserializer()
            handleConnection()
            sendClient(response)
        client_side:
            dataSerialiazer()


proxy -> session_handler -> httpx_request ->response-> session_handler -> proxy

proxy connections
    sessionHandler handles all remote connections to remote servers
    only handles proxy-browser connection