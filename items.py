from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
import time

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()
# Create dummy user
#User0 = User(name="Robo Barista", email="tinnyTim@udacity.com",
            # picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
#session.add(User1)
#session.commit()

#User1 = User(name="Robo Einstein", email="einstein@udacity.com",
            # picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
#session.add(User2)
#session.commit()

# Menu for UrbanBurger
userName = "User_"
categoryName = "Category_"
itemName = "Item_"
description = "Description for Item_"





for i in range(10):

    user = User(name=userName+str(i), email="tinnyTim" + str(i) + "@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
    session.add(user)
    session.commit()
    #for j in range(10):
    print user.id
    category = Category( name=categoryName+str(i), user_id =user.id)
    session.add(category)
    session.commit()
    print category.id
#for k in range(5):
        #categoryN = categoryName + str(k)
        #cat = session.query(Category).filter_by(name = categoryN).one()
        #user = session.query(User).filter_by(user_id = i).one()
    for l in range(3):
            item = Item( name=itemName + str(l), description=description + str(l),
                      category_id = category.id, user_id = category.user_id)
            session.add(item)
            session.commit()
        #time.sleep(1)
