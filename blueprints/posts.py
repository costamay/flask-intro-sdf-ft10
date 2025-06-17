from flask import Blueprint, request, make_response
from models import db, Post

post_pb = Blueprint('post_pb', __name__)

@post_pb.route('/posts', methods=['POST', 'GET'])
def posts():

    if request.method == 'GET':
        # list of python dictionary
        posts = [post.to_dict() for post in Post.query.all()]

        return make_response(posts, 200)

    if request.method == 'POST':
        data = request.get_json()
        
        new_post = Post(post_title=data['post_title'], post_content=data['post_content'], user_id=data['user_id'])
        db.session.add(new_post)
        db.session.commit()

        return make_response(new_post.to_dict(), 201)

@post_pb.route('/posts/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
def get_post_by_id(id):
    post = db.get_or_404(Post, id)

    if request.method == 'GET':
        return make_response(post.to_dict(), 200)

    if request.method == 'DELETE':
        db.session.delete(post)
        db.session.commit()

        return make_response({
            "message" : "post deleted successfully"
        }, 204)

    if request.method == 'PATCH':

        data = request.get_json()
        for key, value in data.items():
            setattr(post, key, value)

        db.session.add(post)
        db.session.commit()
        
        return make_response(
            post.to_dict(),
            200
        )

