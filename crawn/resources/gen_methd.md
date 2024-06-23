## general attack options:
1. Authentication["HTTP_headers, Authentication mechanisms, attacking JWT tokens for jwt basaed authentication and authorization"]
2. Authorization["IDORS(insecure direct object referencing) and ACCESS CONTROLS"]
3. Session Management["Ssession puzzling , how does the application handle cookies (what criteria does it follow while changing the cookies)"]
4. Attacking the client["xss, csrf, LFI, SQL Injection(reflected, stored, Blind, DOM based)">> {not forgetting the existing control mechanisms(COMPENSATING CONTROLS) ie WAF, Browser controls, http_headers, server side validation, output encoding , server side validation , cookie flags, client side validation, client side prototype pollution }]
5. Attacking the server["ssrf, webshells(php applications), XXE Injection, subdomain takeover, server side prototype pollution, os command injection, directory traversal"]
6.Attacking the network infrastructure ["HTTP request forgery, web cache poisoining"]
6. Functional Analysis[" Analyzing how different functionalities work at the client side and finding ways through"]

# Grouping of sudomains and urls depending on functionalities:
eg:
{
url: https://example.com/login/html?name=name&password=password
functionality: login_page
details: "after redirects to https://another.example.com/page"
note: session handling (transfer of session)
}

# while doing recon, these attack options must be looked at and points concerning them noted forexample {
url: https://example.com/login.html?name=matovu&password=timothy
line : 556
option : functional Analysis
details: {
  
  }
}

# in functional Analysis
{
url: https://example.com/page/
functionlity: 
line: 
function_name:
details:
steps(working_mechanisms):{

  }
}

