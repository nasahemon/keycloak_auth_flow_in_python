import os
import re
import base64
import hashlib
import requests
import html
import urllib.parse
from bs4 import BeautifulSoup




base_url = "https://sso-dev.themaxlive.com"

def print_authentication_curl(username, password, form_action, cookies):
    # Prepare the data string
    data_string = f"username={username}&password={password}"
    
    # Prepare the headers string
    headers_string = f"'Cookie: {cookies}'"
    
    # Construct the curl command
    curl_command = f"curl -X POST '{form_action}' -d '{data_string}' -H {headers_string} -L"
    
    print(curl_command)

def print_get_login_ui_curl(provider, client_id, redirect_uri, code_challenge, state="fooobarbaz"):
    # Construct the curl command
    curl_command = f"curl -X GET '{provider}/protocol/openid-connect/auth?response_type=code&client_id={client_id}&scope=openid&redirect_uri={redirect_uri}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256' -i -L"
    
    print(curl_command)

def print_facebook_auth_curl(facebook_auth_url, cookies):
    # Prepare the headers string
    headers_string = f"'Cookie: {cookies}'"
    
    # Construct the curl command
    curl_command = f"curl -X POST '{facebook_auth_url}' -H {headers_string} -L"
    
    print(curl_command)

def print_google_auth_curl(google_auth_url, cookies):
    # Prepare the headers string
    headers_string = f"'Cookie: {cookies}'"
    
    # Construct the curl command
    curl_command = f"curl -X POST '{google_auth_url}' -H {headers_string} -L"
    
    print(curl_command)





# Step 1: Generate the code_verifier
def generate_code_verifier():
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
    code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)
    return code_verifier

# Step 2: Generate the code_challenge
def generate_code_challenge(code_verifier):
    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
    code_challenge = code_challenge.replace('=', '')
    return code_challenge

# Step 3: Perform the login UI request
def getLoginUI(provider, client_id, redirect_uri, code_challenge, state="fooobarbaz"):
    
    # print_get_login_ui_curl(provider, client_id, redirect_uri, code_challenge, state)
    resp = requests.get(
        url=f"{provider}/protocol/openid-connect/auth",
        params={
            "response_type": "code",
            "client_id": client_id,
            "scope": "openid",
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        allow_redirects=False  # Stops automatic redirection to capture response
    )
    
    # Extract 'Set-Cookie' header and format it
    cookie_header = resp.headers.get('Set-Cookie')
    if cookie_header:
        cookies = '; '.join(c.split(';')[0] for c in cookie_header.split(', '))
    else:
        cookies = None


    # Extract the form action URL
    page = resp.text
    form_action_match = re.search('<form\s+.*?\s+action="(.*?)"', page, re.DOTALL)
    if form_action_match:
        form_action = html.unescape(form_action_match.group(1))
    else:
        form_action = None
    return cookies, form_action

# Step 4: Perform the authentication request
def authenticate(username, password, form_action, cookies):
    resp = requests.post(
        url=form_action, 
        data={
            "username": username,
            "password": password,
        }, 
        headers={"Cookie": cookies},
        allow_redirects=False
    )

    return resp

# Step 5: Extract the authorization code
def getCode(resp):
    if 'Location' in resp.headers:
        redirect = resp.headers['Location']
        query = urllib.parse.urlparse(redirect).query
        redirect_params = urllib.parse.parse_qs(query)
        if 'code' in redirect_params:
            return redirect_params['code'][0]
    return None

# Step 6: Perform the token request
def getToken(provider, client_id, redirect_uri, auth_code, code_verifier, cookies):
    resp = requests.post(
        url=f"{provider}/protocol/openid-connect/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": auth_code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
        headers={"Cookie": cookies},
        allow_redirects=False
    )
    
    return resp

# Step 7: Call the UI login flow
def UI_login_flow(provider, client_id, redirect_uri, username, password):
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    cookies, form_action = getLoginUI(provider, client_id, redirect_uri, code_challenge)
    resp = authenticate(username, password, form_action, cookies)
    auth_code = getCode(resp)
    resp = getToken(provider, client_id, redirect_uri, auth_code, code_verifier, cookies)
    return resp



# Facebook login flow

def get_facebook_link(base_url,page):
    soup = BeautifulSoup(page, 'html.parser')
    facebook_link_tag = soup.find('a', id='social-facebook')
    
    if facebook_link_tag and 'href' in facebook_link_tag.attrs:
        facebook_link = facebook_link_tag['href']
        return base_url+html.unescape(facebook_link)
    else:
        return None

def get_facebook_auth_curl(facebook_auth_url, cookies):
    # Prepare the headers string
    headers_string = f"'Cookie: {cookies}'"
    
    # Construct the curl command
    curl_command = f"curl -X POST '{facebook_auth_url}' -H {headers_string} -L"
    
    return curl_command

def request_facebook_auth(facebook_auth_url, cookies):
    resp = requests.post(
        url=facebook_auth_url,
        headers={"Cookie": cookies},
        allow_redirects=False
    )
    return resp

def getFacebookUI(provider, client_id, redirect_uri, code_challenge, state="fooobarbaz"):
    
    # print_get_login_ui_curl(provider, client_id, redirect_uri, code_challenge, state)
    resp = requests.get(
        url=f"{provider}/protocol/openid-connect/auth",
        params={
            "response_type": "code",
            "client_id": client_id,
            "scope": "openid",
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        allow_redirects=False  # Stops automatic redirection to capture response
    )
    
    # Extract 'Set-Cookie' header and format it
    cookie_header = resp.headers.get('Set-Cookie')
    if cookie_header:
        cookies = '; '.join(c.split(';')[0] for c in cookie_header.split(', '))
    else:
        cookies = None

    # Extract the facebook link
    facebook_auth_url = get_facebook_link(base_url, resp.text)
    resp = request_facebook_auth(facebook_auth_url, cookies)
    if 'Location' in resp.headers:
        redirect = resp.headers['Location']
        return redirect
    return None

def facebook_login_flow(provider, client_id, redirect_uri):
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    return getFacebookUI(provider, client_id, redirect_uri, code_challenge)




# Google login flow

def get_google_link(base_url, page):
    soup = BeautifulSoup(page, 'html.parser')
    google_link_tag = soup.find('a', id='social-google')
    
    if google_link_tag and 'href' in google_link_tag.attrs:
        google_link = google_link_tag['href']
        return base_url+html.unescape(google_link)
    else:
        return None
    
def get_google_auth_curl(google_auth_url, cookies):
    # Prepare the headers string
    headers_string = f"'Cookie: {cookies}'"
    
    # Construct the curl command
    curl_command = f"curl -X POST '{google_auth_url}' -H {headers_string} -L"
    
    return curl_command

def request_google_auth(google_auth_url, cookies):
    resp = requests.post(
        url=google_auth_url,
        headers={"Cookie": cookies},
        allow_redirects=False
    )
    return resp

def getGoogleUI(provider, client_id, redirect_uri, code_challenge, state="fooobarbaz"):
    
    # print_get_login_ui_curl(provider, client_id, redirect_uri, code_challenge, state)
    resp = requests.get(
        url=f"{provider}/protocol/openid-connect/auth",
        params={
            "response_type": "code",
            "client_id": client_id,
            "scope": "openid",
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        allow_redirects=False  # Stops automatic redirection to capture response
    )
    # print("{provider}/protocol/openid-connect/auth?response_type=code&client_id={client_id}&scope=openid&redirect_uri={redirect_uri}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256")
    # Extract 'Set-Cookie' header and format it
    cookie_header = resp.headers.get('Set-Cookie')
    # print("Cookie header:",cookie_header)
    if cookie_header:
        cookies = '; '.join(c.split(';')[0] for c in cookie_header.split(', '))
    else:
        cookies = None
    # print("Cookies:",cookies)
    # Extract the google link
    google_auth_url = get_google_link(base_url, resp.text)
    print("Google Auth URL:",google_auth_url)
    resp = request_google_auth(google_auth_url, cookies)
    # print("Resp :",resp)
    # print("Responce body:",resp.text)
    if 'Location' in resp.headers:
        redirect = resp.headers['Location']
        return cookies, redirect
    return cookies,None

def google_login_flow(provider, client_id, redirect_uri):
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    return getGoogleUI(provider, client_id, redirect_uri, code_challenge)





def exchange_token_for_access_token(provider, client_id, client_secret, google_access_token):
    url = f"{provider}/protocol/openid-connect/token"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'subject_token': google_access_token,
        'subject_issuer': 'google',
        'audience': client_id
    }
    
    response = requests.post(url, headers=headers, data=data)
    return response.json()

def google_login_flow_end(provider, client_id, redirect_uri):
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    cookies,url= getGoogleUI(provider, client_id, redirect_uri, code_challenge)
    print("URL:",url)
    print("Curl of url adding cookies:",get_google_auth_curl(url, cookies))
    code = input("Please enter the code obtained after authentication: ")
    code =urllib.parse.unquote(code)
    resp=getToken(provider, client_id, redirect_uri, code, code_verifier, cookies)
    print('Token:',resp.json())




def get_user_info(provider, jwt_token):
    userinfo_endpoint = f"{provider}/protocol/openid-connect/userinfo"
    headers = {
        'Authorization': f'Bearer {jwt_token}'
    }

    response = requests.get(userinfo_endpoint, headers=headers)
    print(response.json())  # Print the userinfo response

def getEncodedCilentCredentials():
    client_id = "max-live-web"  # Replace with your client ID
    client_secret = "6sbc7HWBTzW3L6hRkUBiQHs0tNiMLw2m"  # Replace with your
    credentials = f"{client_id}:{client_secret}"
    encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    return encoded_credentials

def validateToken(provider, jwt_token):
    client_credentials_base64 = getEncodedCilentCredentials()
    url=f"{provider}/protocol/openid-connect/token/introspect"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {client_credentials_base64}'
    }

    # Data
    data = {
        'token': jwt_token
    }

    # Make the POST request
    response = requests.post(url, headers=headers, data=data)

    # Print the response
    print(response.json())


def goo(provider, client_id, redirect_uri):
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state="fooobarbaz"
    url = f"{provider}/auth?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope=openid&state={state}&code_challenge={code_challenge}&code_challenge_method=S256&kc_idp_hint=google"
    print(url)


# Example usage
if __name__ == "__main__":

    # provider = "http://localhost:8080/realms/MAX-LIVE"  # Replace with your provider URL
    # client_id = "account-console"  # Replace with your client ID
    # redirect_uri = "http://localhost:3000"  # Replace with your redirect URI


    provider = "https://sso-dev.themaxlive.com/realms/max-live"  # Replace with your provider URL
    client_id = "account-console"  # Replace with your client ID
    redirect_uri = "http://localhost:9090"  # Replace with your redirect URI
    # redirect_uri = "https://sso-dev.themaxlive.com/realms/max-live/account/"  # Replace with your redirect URI

    #Login flow
    token=UI_login_flow(provider, client_id, redirect_uri,"tanviruser", "asdf1234")
    print(token.json())

    # #Google login flow
    # url=google_login_flow(provider, client_id, redirect_uri)
    # print(url)
   

    # google_login_flow_end(provider, client_id, redirect_uri)

# 
    # goo(provider, client_id, redirect_uri)


    # # Facebook login flow
    # url=facebook_login_flow(provider, client_id, redirect_uri)
    # print(url)

    jwt_token = token.json().get('access_token')  # Assuming the token is in the 'access_token' field

    # # Now, call the Keycloak userinfo API
    get_user_info(provider, jwt_token)
    validateToken(provider, jwt_token)



