from models import db, User, Post
from app import app

with app.app_context():
    Post.query.delete()
    User.query.delete()

    print("Seeding users...")

    christina = User(first_name="Christina", last_name="Max", middle_name="Mary", username="chris", email="chris@gmail.com")
    christina.set_password("1234")

    nevil = User(first_name="Nevil", last_name="Brandon", middle_name="Lence", username="brandy", email="brandy@gmail.com")
    nevil.set_password("1234")
    
    alice = User(first_name="Alice", last_name="Chelsea", middle_name="Migan", username="rihanna", email="rihanna@gmail.com")
    alice.set_password("1234")

    db.session.add_all([christina, nevil, alice])
    db.session.commit()

    print('Seeding posts...')
    p1 = Post(post_title="Adventure", post_content="I love adventure", user=alice, post_image="https://media.istockphoto.com/id/1971796553/photo/young-couple-is-standing-at-mountain-top-with-great-view.webp?a=1&b=1&s=612x612&w=0&k=20&c=lK66beyTW4uKW0S0Sg9g6cj1BnJA2jqS41Gc7LBDVRI=")
    p2 = Post(post_title="Travelling", post_content="The Dubai trip was interesting", user=alice, post_image="https://media.istockphoto.com/id/2155498743/photo/traveler-holding-orange-suitcase-on-city-street.webp?a=1&b=1&s=612x612&w=0&k=20&c=oa78h2rOsh0MW9pD4eCY7G-A-8EP47CdV801R-M7unI=")
    p3 = Post(post_title="Banking", post_content="This sector is corrupt", user=nevil, post_image="https://images.unsplash.com/photo-1553729459-efe14ef6055d?w=500&auto=format&fit=crop&q=60&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxzZWFyY2h8MTJ8fGJhbmtpbmd8ZW58MHx8MHx8fDA%3D")
    p4 = Post(post_title="Education", post_content="Education is power", user=christina, post_image="https://plus.unsplash.com/premium_photo-1682125773446-259ce64f9dd7?w=500&auto=format&fit=crop&q=60&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxzZWFyY2h8MTN8fGVkdWN0aW9ufGVufDB8fDB8fHww")
    p5 = Post(post_title="Economy", post_content="Our economy is doing bad", user=nevil, post_image="https://media.istockphoto.com/id/186245750/photo/times-complex-aka-new-central-bank-tower.webp?a=1&b=1&s=612x612&w=0&k=20&c=uDjyGP19LN3T-3nRbK5kSm3i3h1Ebj83Vu4AsJ3RJLA=")

    db.session.add_all([p1, p2, p3, p4, p5])
    db.session.commit()