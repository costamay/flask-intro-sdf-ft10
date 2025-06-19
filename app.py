from flask import Flask, make_response, request
from flask_migrate import Migrate
from models import db, User, Post
from blueprints.posts import post_pb
from blueprints.users import user_bp
from flask_restful import Api, Resource
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required

# create the app
app = Flask(__name__)

# configure the SQLite database, relative to the app instance folder
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///school.db'
app.config['JWT_SECRET_KEY'] = '38e4274bfe7d72d49777d732'

migrate = Migrate(app, db)

# initialize the app with the extension
db.init_app(app)
api = Api(app)
CORS(app)
jwt = JWTManager(app)

# registering blueprint
# app.register_blueprint(user_bp, url_prefix='/api/v1')
# app.register_blueprint(post_pb, url_prefix='/api/v1')

@app.errorhandler(404)
def not_found(e):
    return make_response({"error" : "Resource not found"}, 404)

@app.errorhandler(405)
def not_found(e):
    return make_response({"error" : "Method not allowed"}, 405)

class RegisterUser(Resource):
    def post(self):
        data = request.get_json()

        user = User.get_user_by_username(username=data.get('username'))

        if user is not None:
            return make_response({'error' : "Username already in use"})

        new_user = User(first_name=data.get('first_name'), middle_name=data.get('middle_name'), last_name=data.get('last_name'), username=data.get('username'), email=data.get('email'))
        new_user.set_password(data.get('password'))

        db.session.add(new_user)
        db.session.commit()

        return make_response(
            {'messaga' : 'User created successfully'}, 201
        )




class LoginUser(Resource):
    def post(self):
        data = request.get_json()

        user = User.get_user_by_username(username=data.get('username'))

        if user and (user.check_password(password=data.get('password'))):
            access_token = create_access_token(identity=user.username)
            refresh_token = create_refresh_token(identity=user.username)

            return make_response(
                {
                    'message': "Login successful",
                    'token' : {
                        'access' : access_token,
                        'refresh' : refresh_token
                    }
                }
            )

        return make_response(
            {'error' : "Invalid username or password"}, 403
        )

class LogoutUser(Resource):
    pass

class PostEndpoint(Resource):
    @jwt_required()
    def get(self):
        posts = [post.to_dict() for post in Post.query.all()]
        return make_response(posts, 200)

    def post(self):
        data = request.get_json()
        new_post = Post(post_title=data['post_title'], post_content=data['post_content'], user_id=data['user_id'])
        db.session.add(new_post)
        db.session.commit()

        return make_response(new_post.to_dict(), 201)

class PostEndpointById(Resource):
    @jwt_required()
    def get(self, id):
        # post = db.get_or_404(Post, id)
        post = Post.query.filter(Post.id == id).first()
        return make_response(post.to_dict(), 200)
        
        # if post:
        #     # post = Post.query.filter_by(id = id).first()
        #     print(post)
        #     return make_response(post.to_dict(), 200)
        
        # return make_response({"Error": "Not found"})

    def patch(self, id):
        post = db.get_or_404(Post, id)
        data = request.get_json()

        for key, value in data.items():
            setattr(post, key, value)

            return make_response(post.to_dict(), 200)


    def delete(self, id):
        post = db.get_or_404(Post, id)
        db.session.delete(post)
        db.session.commit()

        return make_response({'message': 'Deleted Successfully'})



api.add_resource(PostEndpoint, '/posts')
api.add_resource(PostEndpointById, '/posts/<int:id>')
api.add_resource(RegisterUser, '/register')
api.add_resource(LoginUser, '/login')

    
if __name__ == '__main__':
    app.run(debug=True, port=4000)


















