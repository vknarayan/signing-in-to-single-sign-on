# Single-sign-on with Keycloak IAM solution

### OAuth2 & OpenId Connect

OAuth 2.0 is a set of defined process flows for “delegated authorization”.
OpenId Connect is a set of defined process flows for “federated authentication”. OpenId Connect flows are built using the Oauth2.0 process flows
as the base and then adding a few additional steps over it to allow for “federated authentication”.

### Delegated Authorization

Let’s say Joe owns certain resources(eg. Joe’s contact list) that are hosted on some server (eg. google.contacts server). Now, Joe wants an
application that he is using (eg. Yelp), to be able to access his resources (i.e. his contact list) that is on the google.contacts server, and import it
into the Yelp App. Joe needs some mechanism by which he can “authorize”, the Yelp app to access his contacts on the google.contacts server.
Joe can do this by using the OAuth 2.0 flow and delegating the “authorization” to access the google.contacts resource, to another server (account
s.google.com). Thus, the Yelp app gets “authorized” to access Joe’s resources on the google.contacts server, only after the accounts.google.com
server has granted authorization to Yelp to do so.
Thus, in effect Joe has “delegated” the responsibility of authorizing access to his resources to the accounts.google.com server (Authorization
server). This is called “Delegated Authorization”.

### OAuth 2.0 Terminology

In the above example Joe is considered the “Resource Owner”, since Joe owns the resource (Joe’s contact list). The server on which the
resource resides(google.contacts server) is called the “Resource Server”. The Yelp App that is trying to access the resources on the resource
server is called the “Client”. The server that authorizes Yelp to access the resources (accounts.google.com) is called the “Authorization server”.
Resource: Joe’s contact list
Resource Owner: Joe
Client: Yelp App
Resource Server: google.contacts server
Authorization Server: accounts.google.com server
Thus, Joe (resource owner) is “delegating” the responsibility to “authorize” access to his resources(joe’s contact list ) hosted on the “resource
server” (contacts.google server), to the authorization server (accounts.google.com server).
OAuth 2.0 Process Flows
OAuth 2.0 consists of several different process flows to achieve this “delegated authorization”. The following are the two most commonly used,
Authorization code flow (front channel + back channel), most commonly used process flow.
Implicit code flow (front channel only) , used in pure JS applications (eg. Pure Angular or pure React, Single Page Applications, that do not have
a backend web server).

### OAuth 2.0 Authorization Code Flow

The “OAuth 2.0 Authorization code Flow” is the most commonly used flow in OAuth 2.0 to achieve “delegated authorization”.
Joe is on the Yelp App, and clicks on a button within the Yelp App which says “Import Contacts from Google”.
Note that Joe is not attempting to sign on to Yelp using his google account. Rather Joe is simply trying to import his contact list from Google
contacts into Yelp.
This distinction is important because OAuth 2.0 flow is designed to “grant authorization” and is not meant to be used to “authenticate” Joe
(enabling him to sign into Yelp using his google or facebook account).
The part where we give Joe the ability to sign on to Yelp account using his google login is part of the OpenId connect flow, and not the OAuth 2.0
flow. OpenId connect is used to “Authenticate” a user. The OAuth 2.0 flow is simply meant to grant “Authorization” to the users resources.
2. On clicking on this button, the Yelp App sends the following https request to accounts.google.com.
https://accounts.google.com/o/oauth2/v2/auth?
client_id=yelp123&
redirect_uri="https://yelp.com/callback"&
scope=contacts&
response_type=code&
state=foobar

Here we see some additional OAuth 2.0 terminology,
Redirect URI: The call back URI that the authorization server calls once it has finished processing.
Scope: This specifies at a granular level, the “scope” of the access to the resource i.e. are we requesting authorization to read the resources,
modify the resources etc.
Response Type: Which specifies that the Authorization server will provide the Client with an “Authorization Code” , which the Client will exchange 
for an access-token (using the back-channel). More on this later.
3. Joe is directed to the accounts.google.com page and prompted to login to accounts.google.com using his google credentials.
4. Based on the “Scope” parameters in the original request, the Authorization server (i.e. accounts.google.com) constructs a “Consent” page,
which describes to the “resource owner” what exactly the “Client” is wanting to access. At this point the “Client” can click Yes/No on the consent
page to grant consent to the appropriate resource.
In our example the Consent page will say “Yelp is requesting read access to your google.contacts, do you Consent (y/n)?”
5. Once the “resource owner” clicks on “yes” on the “Consent” page, the Authorization server returns an “Authorization Code” to the “Client” and
calls the “redirect URI” specified in the initial request.
6. The “Client” now uses the “authorization code” sent by the “Authorization server” and using a back-channel communication, exchanges the
“authorization code” for an “access token” from the “Authorization Server”.
The back-channel communication is communication sent out by web server to web server, (vs. front-end channel communication, which is
communication between a browser and a web server).
Thus, the “authorization code” is received on the front channel communication i.e. by the browser to web server. But to add that additional layer
of security the “authorization code” is then used by the “Client” web server, and exchanged for an “access-token” from the “authorization server”
by the “client” web server.
7. Once the “Client” has the “access token” from the “authorization server” the client can use this “access token” to access google.contacts.
This completes the “OAuth 2.0 Authorization Code” process flow, and the “Client” can now access the “resource owners” resources on the
“resource server”.

### OAuth 2.0 Implicit Code Flow

The other commonly used OAuth 2.0 process flow is called the “Implicit Code flow” process flow. This flow is used when the “Client” does not
have a web server (the client may be a pure javascript app, a pure Angular or a pure React App). In this flow the only difference is that the
“Authorization Server” returns the “access token” directly to the “client” (instead of first returning an authorization code, that must be exchanged
for an access token). This is done since a pure javascript app does not have a web server to make the back channel call to exchange the
“authorization code” for an “access token”. The “OAuth 2.0 Implicit Code flow” is some what less secure, since it does not involve the backchannel exchange, however is the only alternative in case of pure javascript apps (that do not have a web server).
OpenId Connect Process Flow
The OpenId Connect process flow is the same as the OAuth 2.0 authorization process flow with the following additions.
In addition to the access-token, an Id-token is returned by the authorization server.
Userinfo end point for getting more user information (if the Id token is not sufficient)
“openid” is passed as a parameter in the Scope during the initial call to the Authorization server.
So if an Authorization server is also set up for OpenId Connect, you can in addition to exchanging the authorization code for an access-token,
also get an id-token, which can be used for user “authentication”.
The id-token is the added piece in OpenId Connect, that allows the the OAuth 2.0 flow to be used for Federated Authentication.
The “id-token” is typically returned in JWT (JSON Web Token) format.

### OIDC Auth flows

OIDC has different ways for a client or application to authenticate a user and receive an identity and access token. Which path you use depends
greatly on the type of application or client requesting access. All of these flows are described in the OIDC and OAuth 2.0 specifications so only a
brief overview will be provided here.
Authorization Code Flow - This is a browser-based protocol and it is what we recommend you use to authenticate and authorize browser-based
applications. Also referred as 'standard flow' in keycloak
Implicit Flow - This is a browser-based protocol that is similar to Authorization Code Flow except there are fewer requests and no refresh tokens
involved. We do not recommend this flow as there remains the possibility of access tokens being leaked in the browser history as tokens are
transmitted via redirect URIs. By default turned off for a client in keycloak
Resource Owner Password Credentials Grant (Direct Access Grants) - This is used by REST clients that want to obtain a token on behalf of
a user. It is one HTTP POST request that contains the credentials of the user as well as the id of the client and the client’s secret (if it is a
confidential client). The user’s credentials are sent within form parameters. The HTTP response contains identity, access, and refresh tokens.
Eg., RESULT=`curl --data "grant_type=password&client_id=product-app&username=vasanth&password=vasanth" http://localhost:8180/auth
/realms/springboot/protocol/openid-connect/token`
curl -k -v -X POST -d 'grant_type=password' -d "client_id=product-app" -d "username=sudarshan" -d "password=sudarshan" "http://localhost:8180
/auth/realms/springboot/protocol/openid-connect/token"
Client Credentials Grant - This is also used by REST clients, but instead of obtaining a token that works on behalf of an external user, a token is
created based on the metadata and permissions of a service account that is associated with the client. Refer https://www.keycloak.org/docs/3.3
/server_admin/topics/clients/oidc/service-accounts.html#_service_accounts
curl -k -v -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'grant_type=client_credentials' -d "client_id=client_cred_test" -d
"client_secret=199c6bf4-4c51-4c90-92ed-0f2ebbb4a2ed" "http://localhost:8180/auth/realms/springboot/protocol/openid-connect/token"
OpenId Connect vs. SAML
There are two popular industry standards for Federated Authentication. SAML (or Security Assertion Markup Language) flow, and OpenId
Connect.
OpenId Connect is built on the process flows of OAuth 2.0 and typically uses JWT (JSON Web token) format for the id-token.
SAML flow is independent of OAuth 2.0, and relies on the exchange of messages for authentication in XML SAML format (instead of JWT format).
Both flows allow for SSO (Single Sign On), i.e. the ability to log into a website using your login credentials from a different site (eg. facebook login
or google login).
### Keycloak
Keycloak is an open source Identity and Access Management solution aimed at modern applications and services. It makes it easy to secure
applications and services with little to no code.

### Single-Sign On

Users authenticate with Keycloak rather than individual applications. This means that your applications don't have to deal with login forms,
authenticating users, and storing users. Once logged-in to Keycloak, users don't have to login again to access a different application.
This also applied to logout. Keycloak provides single-sign out, which means users only have to logout once to be logged-out of all applications
that use Keycloak.
Refer this link for further information. https://www.keycloak.org/
Note: Keycloak provides a convenient way for Single-Sign on. For example when the user need to be authenticated for K9, the user can be
redirected to keycloak server. The user enters userid and password in keycloak server. The keycloak server passes the information regarding
the user ( "name": "Sudarshan Navada", "preferred_username": "sudarshan", "given_name": "Sudarshan", "family_name": "Navada", "email":
"sudarshan.navada@gmail.com") and a host of other details such as role through a JSON Web Token (JWT). When we are using keycloak, this
is opaque to the developer, since we use keycloak client adaptor in the client application which talks to the keycloak server.

However, providing authorization using keycloak IAM is not practical. This will call for dynamic connectivity to keycloak ( or any other )
authorization server to create roles and authorizations on the fly. This may not be practical in most cases, since we may not have access to
client's IAM server for this purpose. Also, it calls for lot of calls to set precise permissions to each client url. However an intermediate approach
can be used. We can have the realm specific or client specific roles in the keycloak server ( or from LDAP) attached to the user. We can get this
user info in the access id JWT. We can make use of the role information to set permission in the client side. Again, this is practical only if the
existing roles defined in the IAM server matches the requirements on the client side.

### JWT format

JWT is just a string with the following format:
header.payload.signature
Header has typ key ( value specifies it as a JWT token) and alg key ( value specifies the algorithm used to create signature, eg., HMAC SHA256 )
payload has the claims ( iss, sub, exp etc.) - basically details such as who issued it, subject, expiratio time, authentication done for which
application, authentication time...
payload also contains the roles associated and the resources access; It also contains the scope eg., "openid email profile"

### How JWT works ?

User Sign-in -> to authentication server -> user authenticated, JWT created and returned to user -> User passes JWT when making API calls ->
application verifies and processes API call ( same usecase explained by Rajesh, 2nd use case)
In our simple 3 entity example, we are using a JWT that is signed by the HS256 algorithm where only the authentication server and the
application server know the secret key. The application server receives the secret key from the authentication server when the application sets up
its authentication process. Since the application knows the secret key, when the user makes a JWT-attached API call to the application, the
application can perform the same signature algorithm as in Step 3 on the JWT. The application can then verify that the signature obtained from it’
s own hashing operation matches the signature on the JWT itself (i.e. it matches the JWT signature created by the authentication server). If the
signatures match, then that means the JWT is valid which indicates that the API call is coming from an authentic source. Otherwise, if the
signatures don’t match, then it means that the received JWT is invalid, which may be an indicator of a potential attack on the application. So by
verifying the JWT, the application adds a layer of trust between itself and the user.
It is possible to read the JWT header and payload even without the secret, since there is no encryption involved. However the token is
cryptographically signed with the secret which is shared between the auth server and the client application. The signature only assures that the
token is from the source it is meant to be (authenticity of the source). The secret is shared to the client application while setting up the
authentication process. So by verifying the JWT, the application adds a layer of trust between itself and the user.
// signature algorithm
data = base64urlEncode( header ) + “.” + base64urlEncode( payload )
hashedData = hash( data, secret )
signature = base64urlEncode( hashedData )
If we are using third party IdP ( like google, facebook, etc.,) we don't need keycloak. The spring security support for this is explained here.
https://www.baeldung.com/spring-security-openid-connect

Example of id token payload:
{
"jti": "dcd640c9-72be-4fed-bde7-54bc8bb751b3",
"exp": 1548481447,
"nbf": 0,
"iat": 1548481147,
"iss": "http://localhost:8180/auth/realms/springboot",
"aud": "product-app",
"sub": "31d29036-d8f9-45bc-9f27-daa2f15b207e",
"typ": "ID",
"azp": "product-app",
"auth_time": 1548481147,
"session_state": "913d5c3a-e784-4c1b-a91e-e04d47505955",
"acr": "1",
"email_verified": false,
"name": "Sudarshan Navada",
"preferred_username": "sudarshan",
"given_name": "Sudarshan",
"family_name": "Navada",
"email": "sudarshan.navada@gmail.com"
}

Example of access token payload:
{
"jti": "3d5fd854-8e08-4452-9738-71c58df5a832",
"exp": 1548235955,
"nbf": 0,
"iat": 1548235655,
"iss": "http://localhost:8180/auth/realms/springboot",
"aud": "account",
"sub": "31d29036-d8f9-45bc-9f27-daa2f15b207e",
"typ": "Bearer",
"azp": "product-app",
"auth_time": 1548235655,
"session_state": "986a5781-dad6-480f-8019-0de7f88a490f",
"acr": "1",
"realm_access": {
"roles": [
"offline_access",
"admin",
"uma_authorization",
"user"
]
},
"resource_access": {
"account": {
"roles": [
"manage-account",
"manage-account-links",
"view-profile"
]
}
},
"scope": "openid email profile",
"email_verified": false,
"name": "Sudarshan Navada",
"preferred_username": "sudarshan",
"given_name": "Sudarshan",
"family_name": "Navada",
"email": "sudarshan.navada@gmail.com"
}

id token is the one which is used for authentication (OpenId Connect). Authorization code and access token are used for authorization (OAuth
2.0). Both id token and access token have the same format, which is JWT.

### keycloak server endpoints

http://localhost:8180/auth/realms/springboot/protocol/openid-connect/auth
http://localhost:8180/auth/realms/springboot/protocol/openid-connect/userinfo
http://localhost:8180/auth/realms/springboot/protocol/openid-connect/token
http://localhost:8180/auth/realms/springboot/tokens/access/codes
Visit http://localhost:8180/auth/realms/springboot/.well-known/openid-configuration to know all end points and configuration paramters

### How to use the end points ?

curl -k -v -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=sudarshan" -d "password=sudarshan" -d
'grant_type=password' -d "client_id=product-app" -d "client_secret=secret" "http://localhost:8180/auth/realms/springboot/protocol/openid-connect
/token"
curl -k -v -X POST -H "Content-Type: application/x-www-form-urlencoded" -d
"access_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJLRmkxdnBNdHNhckh0Z2FIbGRKQmRGZkdXbWRxblR3b29JWFEwNk1fNi1vIn0.eyJqdGkiOiIzNDMyYjU3NS00NmNkLTQ1ZWUtYmQ5Yi1iYjE0NzZhYTNkYTUiLCJleHAiOjE1NDg1MDIwNzEsIm5iZiI6MCwiaWF0IjoxNTQ4NTAxNzcxLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgxODAvYXV0aC9yZWFsbXMvc3ByaW5nYm9vdCIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIzMWQyOTAzNi1kOGY5LTQ1YmMtOWYyNy1kYWEyZjE1YjIwN2UiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJwcm9kdWN0LWFwcCIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6IjQyOWNlNDI5LTM5YjYtNDY5MC1iZTFjLTNmYjJiOTdhZDcwMyIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJhZG1pbiIsInVtYV9hdXRob3JpemF0aW9uIiwidXNlciJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6IlN1ZGFyc2hhbiBOYXZhZGEiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzdWRhcnNoYW4iLCJnaXZlbl9uYW1lIjoiU3VkYXJzaGFuIiwiZmFtaWx5X25hbWUiOiJOYXZhZGEiLCJlbWFpbCI6InN1ZGFyc2hhbi5uYXZhZGFAZ21haWwuY29tIn0.j0lKK7rfGWXOAp-5eMYURslQFsLD1RrlpLygavjoo0bV-HYYDcRAGRpbVmoE8niard0LDkGxrJaVIV5XVRAIffiuTtcCqQiYWDM6bJtXO4H03_KNcKpijc6a5qIjxXIknnxiMu87tiv8bsj2jV2ilGobouXO4GhHVvtfrpnNNYCeo69NcAqx8UXmBTM01uWGDflXSVEVP3xmxckD28TrHExwf7D7zHIRdKRv3pjM-2yuBsQoSJ9HvOQ85iF11kBT4QcsVpM_cGwEecqVEW-E3vv69z1r9Hv3cfNw5UxCxY_nra-O6ys8afjxEIlfZJMkqhNGiDO0-XvHVlrBXn2w" "http://localhost:8180/auth/realms/springboot/protocol/openid-connect/userinfo"

Authentication can in general be of two types.
web application or any application having a UI
headless application where authentication cannot automatically be diverted to server
How to perform authentication in a typical web application ?
You divert the authentication to the IAM or IdP server, which does the authentication. You get the user info to your web app through a JWT, as
described above. The token for authentication is id-token.
How to perform authentication for a headless client application ?
Here we describe the approach to getting tokens and authenticating for a headless application. This can either be done with curl or with a web
application. It is assumed that we already have one client with Access type "bearer only" which needs authentication; refer to http://blog.keycloak.
org/2015/10/getting-started-with-keycloak-securing.html.
Note that the first client also need to be prepared for SSO. A good existing example for this is kafka, which is security enabled for authentication.
(Not addressed here)

First we need to create a client that can be used to obtain the token. Go to the Keycloak admin console again and create a new client. This time
give it the Client ID curl and select public for access type. Under Valid Redirect URIs enter http://localhost.
As we are going to manually obtain a token and invoke the service let's increase the lifespan of tokens slightly. In production access tokens
should have a relatively low timeout, ideally less than 5 minutes. To increase the timeout go to the Keycloak admin console again. This time click
on Realm Settings then on Tokens. Change the value of Access Token Lifespan to 15 minutes. That should give us plenty of time to obtain a
token and invoke the service before it expires.

Now we're ready to get our first token using CURL. To do this run:
RESULT=`curl --data "grant_type=password&client_id=curl&username=user&password=password" http://localhost:8180/auth/realms/master
/protocol/openid-connect/token`

This is a bit cryptic and luckily this is not how you should really be obtaining tokens. Tokens should be obtained by web applications by
redirecting to the Keycloak login page. We're only doing this so we can test the service as we don't have an application that can invoke the
service yet. Basically what we are doing here is invoking Keycloaks OpenID Connect token endpoint with grant type set to password which is the
Resource Owner Credentials flow that allows swapping a username and a password for a token.

Take a look at the result by running:
echo $RESULT

The result is a JSON document that contains a number of properties. There's only one we need for now though so we need to parse this output 
to retrieve only the value we want. To do this run:
TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`
This command uses sed to strip out everything before and after the value of the access token property.
Now that we have the token we can invoke the secured service. To do this run:
curl http://localhost:8080/service/secured -H "Authorization: bearer $TOKEN"
OpenID connect process with google authentication as example
First we are going to send an authentication request.
https://accounts.google.com/o/oauth2/auth?
client_id=sampleClientID
response_type=code&
scope=openid%20email&
redirect_uri=http://localhost:8081/google-login&
state=abc
Next, we’re going to exchange the code for an Access Token and id_token:
POST https://www.googleapis.com/oauth2/v3/token
code=xyz&
client_id= sampleClientID&
client_secret= sampleClientSecret&
redirect_uri=http://localhost:8081/google-login&
grant_type=authorization_code
sample response from the auth. server
{
"access_token": "SampleAccessToken",
"id_token": "SampleIdToken",
"token_type": "bearer",
"expires_in": 3600,
"refresh_token": "SampleRefreshToken"
}

### LDAP server

It is a database of users and groups.
Use this link to create & browse an sample LDAP server using Apache Directory Studio. http://krams915.blogspot.com/2011/01/ldap-apachedirectory-studio-basic.html
In keycloak, click on "User federation" link to configure connection to ldap. Use "ldap://127.0.0.1:10389" for connection url.
Group names can also be synced with group names in keycloak. The group can be linked to a role. But currently there seem to be some
limitation in importing group members in to keycloak.
Exaple use case diagram
