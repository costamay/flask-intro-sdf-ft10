<!-- Querying database -->
<!-- sql => structured query language -->
insert => adding new record
update
delete
select => SELECT * FROM database_name

all = []

<!-- flask-sqlalchemy methods -->
all => to get all records
filter
filter_by
delete
order_by
get
update
add


<!-- db instance -->
sesssion
add => adding new record
commit => to save changes

<!-- class Post:
   def __init__(self, post_title, post_content, id = None):
       self.post_title = post_title
       self.post_content = post_content
       self.id = id

post1 = Post('Travel', "The dubai trip was interesting") -->

serialize our data => formating our data so that it can be tranfered over the internet
json => data format that makes it easy to be transered over the internet(make_response)

[<Post 1>] => we can not transfer this over the internet, what will is to convert it into a dictionary(serialize) then convert it into a json object

flask sqlalchemy relationship => one-to-one, one-to-many, many-to-many
<!-- foreignKey
relashionship
back_populates  -->
seed our database
create our first endpoint(API)

{
    "id" : 1,
    "post_title": "weather",
    "post_content": "It's rainy today"
}
<!-- SerializerMixin -->
to_dict() => convert into a dictionary => to_dict(rule=()), to_dict(only=())
serialize_rule => which fields to exempt
serialize_only => which fields to include

<!-- serializing relationship -->
user=> user-posts

user mode
id
posts = db.relationship('Post', back_populates="user")

post mode
id
user_id= foreignKey
user = db.relationship('User', back_populates="posts")

user1.posts
post1.user

<!-- main focus will be building apis -->
<!-- CRUD OPERATION -->
GET all
POST
GET ON -GET by id
PATCH
DELETE

get all and post => will use one url
get /users
post /users

<!-- get by id -->

get /users/<id>
delete /users/<id>
patch /users/<id>

<!-- recursion depth -->
{
    "id":
    "post_title":
    "post_content":
    user_id :3
   
}

<!-- modularising our code -->
blueprints

<!-- flask restful api -->
classes

<!-- constraints & validation -->
db.CheckConstraint()
contraints => this affect the columns
example => email => @, unique
            username => unique and of a given length

<!-- validation -->
doing a check to ensure data is valid

exception handlers
try:

except