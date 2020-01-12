from authlib.common.security import generate_token
from ._core import register_to
from marshmallow import Schema,fields


class AuthCodeSchema(Schema):
    code = fields.String(null=False)

class TokenSchema(Schema):
    token = fields.String(null=True)

def create_flask_smorest_blueprint(backend, oauth, handle_authorize):
    """Create a Flask blueprint that you can register it directly to Flask
    app. The blueprint contains two route: ``/auth`` and ``/login``::

        from flask import Flask
        from authlib.flask.client import OAuth
        from loginpass import create_flask_blueprint, GitHub

        app = Flask(__name__)
        oauth = OAuth(app)


        def handle_authorize(remote, token, user_info):
            if token:
                save_token(remote.name, token)
            if user_info:
                save_user(user_info)
                return user_page
            raise some_error

        github_bp = create_flask_blueprint(GitHub, oauth, handle_authorize)
        app.register_blueprint(github_bp, url_prefix='/github')

        # visit /github/login
        # callback /github/auth

    :param backend: An OAuthBackend
    :param oauth: Authlib Flask OAuth instance
    :param handle_authorize: A function to handle authorized response
    :return: Flask Blueprint instance
    """
    from flask import request, url_for, current_app, session
    from flask_smorest import Blueprint
    from authlib.flask.client import RemoteApp

    remote = register_to(backend, oauth, RemoteApp)
    nonce_key = '_{}:nonce'.format(backend.OAUTH_NAME)
    bp = Blueprint('loginpass_' + backend.OAUTH_NAME, __name__)

    #TODO marshmallow types for these two routes then fork this with _flask_smorest as import seperate file

    @bp.route('/auth')
    @bp.arguments(AuthCodeSchema, location='query')
    #TODO token schema maken
    # @placeBp.response(TokenSchema(many=False))
    #TODO other schemas after getting back flask code for non auth token based flows
    def auth():
        """ Authenticate given provider with oauth code """
        id_token = request.args.get('id_token')
        if request.args.get('code'):
            token = remote.authorize_access_token()
            if id_token:
                token['id_token'] = id_token
        else:
            # handle failed
            return handle_authorize(remote, None, None)
        if 'id_token' in token:
            nonce = session[nonce_key]
            user_info = remote.parse_openid(token, nonce)
        else:
            user_info = remote.profile(token=token)
        return handle_authorize(remote, token, user_info)

    @bp.route('/login')
    def login():
        if "OAUTH_REDIRECT_URL" in RemoteApp.config:
            redirect_uri = RemoteApp.config["OAUTH_REDIRECT_URL"]
            #TODO feedback if used and feedback if not found and fallback used
        else:
            redirect_uri = url_for('.auth', _external=True)
        conf_key = '{}_AUTHORIZE_PARAMS'.format(backend.OAUTH_NAME.upper())
        params = current_app.config.get(conf_key, {})
        if 'oidc' in backend.OAUTH_TYPE:
            nonce = generate_token(20)
            session[nonce_key] = nonce
            params['nonce'] = nonce
        return remote.authorize_redirect(redirect_uri, **params)

    return bp