import os
import re
import webapp2
import jinja2
import random
from string import letters
import hashlib
import hmac
import time

from google.appengine.ext import db

# GLOBAL CONSTANTS
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
                               autoescape=True)
EMAIL_RE = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
USER_ID = 'user_id'
SECRET = 'cs9e3_JE!48b'

# GLOBAL FUNCTIONS
def get_user_id(self):
    # If logged in, returns user's cookie
    return self.read_secure_cookie(USER_ID)

def blog_key(name='default'):
    # Facilitiates multiple blogs
    return db.Key.from_path('Blog', name)

def render_str(template, **params):
    # Renders given template with given parameters
    tmp = JINJA_ENV.get_template(template)
    return tmp.render(params)

# DATA OBJECT DEFINITIONS
class User(db.Model):
    username = db.StringProperty(required=True)
    pass_hash = db.StringProperty(required=True)
    email = db.StringProperty()

class Post(db.Model):
    author_name = db.StringProperty(required=True)
    author_id = db.StringProperty(required=True)
    post_id = db.StringProperty()
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    modified = db.DateTimeProperty(auto_now=True)

class Comment(db.Model):
    author_name = db.StringProperty(required=True)
    author_id = db.StringProperty(required=True)
    comment_id = db.StringProperty()
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    modified = db.DateTimeProperty(auto_now=True)

class Like(db.Model):
    liker = db.StringProperty(required=True)

# ENGINES
class SecurityEngine(object):
    def make_secure_val(self, val):
        return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

    def set_secure_cookie(self, name, val, expires):
        cookie_val = self.make_secure_val(str(val))
        if expires:
            now = datetime.datetime.utcnow()
            expires = datetime.timedelta(seconds=COOKIE_LIFE)
            expires_on = (now + expires).strftime("%a, %d %b %Y %H:%M:%S GMT")
        else:
            expires_on = ''
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; expires=%s; Path=/' % (name, cookie_val, expires_on))

    def read_secure_cookie(self, cookie_name):
        if self.request.cookies.get(cookie_name):
            cookie = self.request.cookies.get(cookie_name)
            value = self.get_secure_val(cookie)
            return value
        else:
            return

    def make_salt(self, salt_length=5):
        return ''.join(random.choice(letters)
                       for x in xrange(salt_length))

    def hash_pass(self, username, password, salt=None):
        if not salt:
            salt = self.make_salt()
        hashed_pass = hashlib.sha256(username + password + salt).hexdigest()
        return '%s|%s' % (salt, hashed_pass)

    def valid_pass_hash(self, username, password, hashed_pass):
        salt = hashed_pass.split('|')[0]
        return hashed_pass == self.hash_pass(username, password, salt)

    def make_secure_val(self, val):
        return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

    def get_secure_val(self, secure_val):
        if secure_val:
            val = secure_val.split('|')[0]
        else:
            val = None
        if secure_val == self.make_secure_val(val):
            return val

    def get_user_by_uid(self):
        user_id = self.read_secure_cookie(USER_ID)
        if user_id:
            user_key = db.Key.from_path('User', int(user_id), parent=None)
            return db.get(user_key)
        else:
            return None

    def get_user(self, username):
        user = db.GqlQuery("SELECT * "
                          "FROM User "
                          "WHERE username = :un",
                          un=username).get()
        return user

    def user_auth(self, username, password):
        user = self.get_user(username)
        if user:
            return self.valid_pass_hash(user.username,
                                        password,
                                        user.pass_hash)

    def is_authorized(self):
        # to check if authorized, set user = is_authorized
        authorized = False
        username = self.read_secure_cookie(USER_ID)
        if username:
            authorized = True
        if self.get_user(username):
            authorized = True
        return authorized

class BlogEngine(webapp2.RequestHandler, SecurityEngine):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_tmp(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        user = None
        user = self.get_user_by_uid()
        if user:
            self.write(self.render_tmp(template, username=user.username, **kw))
        else:
            self.write(self.render_tmp(template, **kw))

    def save_entity(self, the_entity):
        entity_key = the_entity.put()
        return entity_key

    def get_entity(self, entity_key):
        return db.get(entity_key)

# HANDLERS
class LikeHandler(BlogEngine):
    def get(self):
        # if username != author_name & not is_liker
        user = self.get_user_by_uid()
        if user:
            likable_id = self.request.get("id")
            parent_key = db.Key(likable_id)
            #create new like as child to likable parent
            like = Like(parent=parent_key,
                        liker = user.username)
            like.put()
            self.redirect('/open?id=%s' % likable_id)
        else:
            self.redirect('/')

class CommentHandler(BlogEngine):
    def get(self):
        user = self.get_user_by_uid()
        if user:
            post_id = self.request.get("id")
            #self.write(post_id)
            self.render("new_comment.html", post_id=post_id)
        else:
            self.redirect('/')

    def post(self):
        user = self.get_user_by_uid()
        if user:
            post_id = self.request.get("id")
            content = self.request.get("content")

            if content.strip() != "":
                parent_key = db.Key(post_id)
                parent_post = self.get_entity(parent_key)
                comment = Comment(parent=parent_key,
                                author_id=self.read_secure_cookie(USER_ID),
                                author_name=user.username,
                                content=content)
                comment_key = self.save_entity(comment)
                comment.comment_id = str(comment_key)
                comment.post_id = post_id
                comment.put()
                time.sleep(.5)
                self.redirect('/open?id=%s' % post_id)
            else:
                error = "But you didn't type anything!"
                params = dict(error=error)
                self.render("new_comment.html", **params)
        else:
            self.redirect('/')

class EditHandler(BlogEngine):

    def get(self):
        the_id = self.request.get('id')
        user = self.get_user_by_uid()
        # self.write("here")
        #check is_authorized
        if user:
            if self.is_authorized():
                # get the entity and render it's params w/ correct form
                if the_id != "None":
                    the_key = db.Key(the_id)
                    the_entity = self.get_entity(the_key)
                    if the_entity:
                        # Check if is_editor
                        if the_entity.author_name == user.username:

                            # params common to all documents
                            content = the_entity.content
                            author_name = the_entity.author_name
                            created = the_entity.created
                            modified = the_entity.modified
                            params = dict(content=content,
                                            author_name=author_name,
                                            created=created,
                                            modified=modified)

                            # Edit a Post
                            if the_entity.kind() == "Post":
                                subject = the_entity.subject
                                params["subject"] = subject
                                form = "new_post.html"
                                # self.render("new_post.html", **params)

                            # Edit a Comment
                            elif the_entity.kind() == "Comment":
                                form = "new_comment.html"

                            else:
                                self.write("Entity kind needs handler")

                            self.render(form, **params)
                        else:
                            self.write("Not an editor.")
                    else:
                        self.write("Don't have the entity")
                else:
                    self.write("the_id = None")
            else:
                self.write("No authorized")
        else:
            # Error: No User
            self.redirect('/login')

    def post(self):
        the_id = self.request.get('id')
        user = self.get_user_by_uid()
        if user and self.is_authorized():
            if the_id != "None":
                the_key = db.Key(the_id)
                the_entity = self.get_entity(the_key)
                if the_entity:
                    # Check if is_editor
                    if the_entity.author_name == user.username:
                        validation_error = False

                        # get/set editable params common to all kinds
                        content = self.request.get("content")
                        the_entity.content = content
                        kind = the_entity.kind()
                        # handle Post
                        if kind == "Post":
                            subject = self.request.get("subject")
                            the_entity.subject = subject
                            # validate and save/error
                            if subject.strip() != "" and content.strip() != "":
                                the_entity.put()
                                time.sleep(.5)
                                self.redirect("/")
                            else:
                                error = "Please include both title and content."
                                params = dict(subject=subject, content=content, error=error)
                                self.render("new_post.html", **params)

                        # handle Comment
                        elif kind == "Comment":
                            if content.strip() != "":
                                the_entity.put()
                                post_id = the_entity.key().parent()
                                time.sleep(.5)
                                self.redirect("/open?id=%s" % str(post_id))
                            else:
                                error = "Please include content."
                                params = dict(content=content, error=error)
                                self.render("new_comment.html", **params)

                        else:
                            self.write("Entity kind needs a handler")
                    else:
                        self.write("Not an Editor.")
                else:
                    self.write("Don't have the entity")
            else:
                self.write("the_id = None")

class OpenHandler(BlogEngine):
    def get(self):
        user = self.get_user_by_uid()
        the_id = self.request.get("id")
        if the_id != "None":
            # get the entity and its author name
            the_key = db.Key(the_id)
            the_entity = db.get(the_key)
            author_name = the_entity.author_name

            params = dict()
            # set params common to all Models (so far)
            params['content'] = the_entity.content
            params['author_name'] = author_name
            params['created'] = the_entity.created
            params['modified'] = the_entity.modified

            # determine and set is_editor
            if user and (user.username == author_name):
                is_editor = True
            else:
                is_editor = False
            params['is_editor'] = is_editor

            # POST
            if the_entity.kind() == "Post":
                params['post_id'] = the_entity.post_id
                params['subject'] = the_entity.subject

                comments = Comment.all()
                comments.ancestor(the_key)
                comments.order('-created')
                params['comments'] = comments

                all_likes = Like.all()
                likes = all_likes.ancestor(db.Key(the_entity.post_id))
                like_count = likes.count()
                likers = []
                for like in likes:
                    likers.append(str(like.liker))
                params["likers"] = likers
                params["like_count"] = like_count

                form = "post.html"

            # COMMENT
            elif the_entity.kind() == "Comment":
                # self.write(the_entity.content)

                params["comment_id"] = the_entity.comment_id
                form = "comment.html"

            else:
                form = "blog_roll.html"

            self.render(form, **params)
        else:
            self.redirect('/')


    def post(self):
        #get the kind and redirect accordingly
        # self.write("Save edited post or comment")
        the_id = self.request.get("id")
        if the_id != "None":
            the_key = db.Key(the_id)
            the_entity = db.get(the_key)
            kind = the_entity.kind()
            self.write(kind)

class DeleteHandler(BlogEngine):
    def get(self):
        auth_error = True

        if self.read_secure_cookie(USER_ID):
            auth_error = False

        username = self.read_secure_cookie(USER_ID)
        if not self.get_user(username):
            auth_error = False

        if not auth_error:
            the_id = self.request.get('id')
            if the_id != "None":
                the_key = db.Key(the_id)
                db.delete(the_key)
                time.sleep(.5)
                self.redirect('/')
            else:
                self.redirect('/')
        else:
            self.redirect('/signup')

class NewPostHandler(BlogEngine):
    def get(self):
        if self.read_secure_cookie(USER_ID):
            self.render("new_post.html")
        else:
            self.redirect('/signup')

    def post(self):
        user = self.get_user_by_uid()
        if user:
            subject = self.request.get('subject')
            content = self.request.get('content')
            if subject and content:
                post = Post( parent=blog_key(),
                            author_id=self.read_secure_cookie(USER_ID),
                            author_name=user.username,
                            subject=subject,
                            content=content)
                post_key = self.save_entity(post)
                post.post_id = str(post_key)
                post.put()
                time.sleep(.5)
                self.redirect("/")
            else:
                error = "Please include both title and content."
                params = dict(subject=subject, content=content, error=error)
                self.render("new_post.html", **params)
        else:
            self.redirect('/')

class LoginHandler(BlogEngine):
    def get(self):
        self.render("login.html")

    def post(self):
        error = False
        username = self.request.get('username')
        password = self.request.get('password')

        params = dict()
        if self.get_user(username):
            # tests for valid password and password match
            if self.user_auth(username, password):
                auth_error = False
            else:
                auth_error = True
                params['error_password'] = 'Invalid Password'
        else:
            auth_error = True
            params['error_username'] = 'User Does Not Exist'

        # if there is an error re-render signup page
        # else render the welcome page
        if auth_error:
            self.render("login.html", **params)
        else:
            user = db.GqlQuery("SELECT * "
                               "FROM User "
                               "WHERE username = :username",
                               username=username).get()
            user_id = str(user.key().id())
            self.set_secure_cookie(USER_ID, user_id, None)
            posts = Post.all()
            posts.order('-created')
            params = dict(username=username, posts=posts)
            self.render('blog_roll.html', **params)

class LogoutHandler(BlogEngine):
    def get(self):
        self.set_secure_cookie(USER_ID, '', None)
        self.redirect('/login')

class SignupHandler(BlogEngine):

    def username_isValid(self, username):
        return username and USER_RE.match(username)

    def password_isValid(self, password):
        return password and PASS_RE.match(password)

    def email_isValid(self, email):
        if email:
            return EMAIL_RE.match(email)
        else:
            return True

    def get(self):
        #set current user context
        self.render('signup.html')

    def post(self):
        # initialize local variables
        error = False

        # get user input
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        #collect params to send with template
        params = dict(username=username, password=password, email=email)

        # validate user input
        if self.get_user(username):
            error = True
            params['error_username_exists'] = "User already exists."
        elif not self.username_isValid(username):
            error = True
            params['error_username'] = "Username is not valid"

        if not self.password_isValid(password):
            error = True
            params['error_password'] = "Password is not valid."
        elif password != verify:
            error = True
            params['error_verify'] = "Passwords do not match."

        if not self.email_isValid(email):
            error = True
            params['error_email'] = "Email is not valid."

        if error:
            self.render("signup.html", **params)
        else:
            hashed_pass = self.hash_pass(username, password)
            user = User(username=username,
                        pass_hash=hashed_pass,
                        email=email)
            user.put()
            user_id = str(user.key().id())
            self.set_secure_cookie(USER_ID, user_id, None)
            self.redirect('/')

class MainHandler(BlogEngine):
    def get(self):
        user = None
        if self.get_user_by_uid():
            user = self.get_user_by_uid()
        posts = Post.all()
        posts.order('-created')
        if user:
            params = dict(posts=posts)
            self.render("blog_roll.html", **params)
        else:
            msg = "Please Signup or Login to Post!"
            params = dict(posts=posts, msg=msg)
            self.render('blog_roll.html', **params)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', SignupHandler),
    ('/logout', LogoutHandler),
    ('/login', LoginHandler),
    ('/newpost', NewPostHandler),
    ('/delete', DeleteHandler),
    ('/open', OpenHandler),
    ('/edit', EditHandler),
    ('/comment', CommentHandler),
    ('/like', LikeHandler)
], debug=True)
