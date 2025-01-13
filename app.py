from flask import Flask, request, redirect, session
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# SAML settings - you'll need to adjust these based on your ADFS configuration
saml_settings = {
    "strict": True,
    "debug": True,
    "sp": {
        "entityId": "http://localhost:8000/metadata/",
        "assertionConsumerService": {
            "url": "http://localhost:8000/?acs",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        "singleLogoutService": {
            "url": "http://localhost:8000/?sls",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    },
    "idp": {
        "entityId": "https://app.onelogin.com/saml/metadata/8b14c274-4efc-4c83-bb8f-2b7f57330cb9",
        "singleSignOnService": {
            "url": "https://setup4u.onelogin.com/trust/saml2/http-post/sso/8b14c274-4efc-4c83-bb8f-2b7f57330cb9",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "singleLogoutService": {
            "url": "https://setup4u.onelogin.com/trust/saml2/http-redirect/slo/3671776",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": "give your certificate in string single line formate"  # Your ADFS certificate
    }
}

def init_saml_auth(req):
    return OneLogin_Saml2_Auth(req, saml_settings)

def prepare_flask_request(request):
    url_data = request.url.split('?')
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': request.environ.get('SERVER_PORT', '80'),
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy(),
        'query_string': url_data[1] if len(url_data) > 1 else ''
    }

@app.route('/login')
def login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    sso_built_url = auth.login()
    return redirect(sso_built_url)

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'acs' in request.args:
        return acs()
    elif 'sls' in request.args:
        return sls()
    elif 'samlUserdata' in session:
        return f"Logged in sk as: {session['samlUserdata'].get('Email', ['N/A'])[0]}"
    return "Not logged in. <a href='/login'>Login</a>"

def acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    print("SAML Errors:", errors)

    if not errors:
        if auth.is_authenticated():
            session['samlUserdata'] = auth.get_attributes()
            session['samlNameId'] = auth.get_nameid()
            session['samlSessionIndex'] = auth.get_session_index()
            self_url = OneLogin_Saml2_Utils.get_self_url(req)
            print("Authenticated as:", session['samlUserdata'])
            print("Self URL:", self_url)

            relay_state = request.form.get('RelayState', '/')
            if relay_state == 'http://localhost:8000/login':
                relay_state = '/'  # Avoid redirecting back to the login endpoint
            print("Redirecting to:", relay_state)

            if self_url != relay_state:
                return redirect(auth.redirect_to(relay_state))
            return redirect('/')
    print("Authentication failed")
    return "Authentication failed", 401


def sls():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    url = auth.process_slo(delete_session_cb=lambda: session.clear())
    errors = auth.get_errors()
    if len(errors) == 0:
        return redirect(url or '/')
    return "Logout failed", 500

@app.route('/metadata/')
def metadata():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
    else:
        resp = make_response(', '.join(errors), 500)
    return resp

if __name__ == '__main__':
    app.run(debug=True,port=8000)