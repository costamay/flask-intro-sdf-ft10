from models import db, User, Post
from app import app

with app.app_context():

    print("Seeding users...")

    christina = User(first_name="Christina", last_name="Max", middle_name="Mary", username="chris", email="chris@gmail.com", password="1234")
    nevil = User(first_name="Nevil", last_name="Brandon", middle_name="Lence", username="brandy", email="brandy@gmail.com", password="1234")
    alice = User(first_name="Alice", last_name="Chelsea", middle_name="Migan", username="rihanna", email="rihanna@gmail.com", password="1234")

    db.session.add_all([christina, nevil, alice])
    db.session.commit()

    print('Seeding posts...')
    p1 = Post(post_title="Adventure", post_content="I love adventure", user=alice)
    p2 = Post(post_title="Travelling", post_content="The Dubai trip was interesting", user=alice)
    p3 = Post(post_title="Banking", post_content="This sector is corrupt", user=nevil)
    p4 = Post(post_title="Education", post_content="Education is power", user=christina)
    p5 = Post(post_title="Economy", post_content="Our economy is doing bad", user=nevil)

    db.session.add_all([p1, p2, p3, p4, p5])
    db.session.commit()