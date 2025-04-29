import os
from flask import Flask, request, jsonify, render_template, make_response
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity,
    set_access_cookies, unset_jwt_cookies
)
import jwt as pyjwt

app = Flask(__name__, template_folder='templates')

# Flask session secret（不做主要認證用）
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_flask_secret_key')

# JWT 設定
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_SECURE'] = False  # HTTPS 時請改為 True

jwt = JWTManager(app)

# 模擬 in-memory 資料庫
users_db = {}

@app.route("/")
def home():
    return render_template("register.html")

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    credential = data.get("credential")
    users_db[username] = {
        "credential_id": credential["rawId"],
        "credential_data": credential
    }
    return jsonify({"message": "註冊成功"}), 200

@app.route("/check_account/<username>")
def check_account(username):
    exists = username in users_db
    credential_id = users_db.get(username, {}).get("credential_id")
    return jsonify({"exists": exists, "credential_id": credential_id}), 200

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    credential_id = data.get("rawId")

    for username, user_data in users_db.items():
        if user_data["credential_id"] == credential_id:
            # 模擬 WebAuthn 驗證
            if verify_webauthn_signature(user_data, data):
                # 建立 JWT，並加入 aud/iss
                access_token = create_access_token(
                    identity=username,
                    additional_claims={
                        "aud": "fido2-client",
                        "iss": "fido2-server"
                    }
                )
                resp = make_response(jsonify({
                    "success": True,
                    "message": "登入成功"
                }), 200)
                set_access_cookies(resp, access_token)
                return resp
            break

    return jsonify({"success": False, "message": "登入失敗或用戶不存在"}), 401

@app.route("/logout", methods=["POST"])
def logout():
    resp = make_response(jsonify({"message": "已登出"}), 200)
    unset_jwt_cookies(resp)
    return resp

@app.route("/welcome.html")
@jwt_required()
def serve_welcome():
    username = get_jwt_identity()
    raw_token = request.cookies.get('access_token_cookie')

    # 解 header（不驗證）
    decoded_header = pyjwt.get_unverified_header(raw_token)
    # 解 payload（驗證簽名，並檢查 aud）
    decoded_payload = pyjwt.decode(
        raw_token,
        app.config['JWT_SECRET_KEY'],
        algorithms=['HS256'],
        audience="fido2-client"
    )

    return render_template(
        "welcome.html",
        username=username,
        jwt_raw=raw_token,
        jwt_header=decoded_header,
        jwt_payload=decoded_payload,
        jwt_secret=app.config['JWT_SECRET_KEY']
    )

def verify_webauthn_signature(user, data):
    # TODO: 引入 fido2.server 做真實驗證
    return True

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5050))
    app.run(host="0.0.0.0", port=port)
