""" This is a multi-user blog.

    It allows many users to post blog entries. Users may post, comment,
    and like blog posts.
"""

# Copyright(c) 2016 Connie Skomra

import os
import re
import random
from string import letters
import hashlib
import hmac
import datetime
import time
import webapp2
import jinja2

from google.appengine.ext import db


# GLOBAL CONSTANTS
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
                               autoescape=True)
EMAIL_RE = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
USER_ID = "user_id"
SECRET = "cs9e3_JE!48b"
SALT_LENGTH = 5
COOKIE_LIFE = 0


# GLOBAL FUNCTIONS
def get_user_id(self):
    """Gets and returns the user's id."""

    return self.read_secure_cookie(USER_ID)


def blog_key(name="default"):
    """Gets and returns the key to the blog."""

    return db.Key.from_path("Blog", name)


def render_str(template, **params):
    """Renders a given template with given parameters.

    Args:
        template: The template to render.
        **params: One or more key pair parameters.

    Returns:
        A call to render the template with parameters.
    """

    tmp = JINJA_ENV.get_template(template)
    return tmp.render(params)


# DATA OBJECT DEFINITIONS
class User(db.Model):
    """Stores information about a user participating in the blog."""

    username = db.StringProperty(required=True)
    pass_hash = db.StringProperty(required=True)
    email = db.StringProperty()


class Post(db.Model):
    "Stores information about a blog post."

    author_name = db.StringProperty(required=True)
    author_id = db.StringProperty(required=True)
    post_id = db.StringProperty()
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    modified = db.DateTimeProperty(auto_now=True)


class Comment(db.Model):
    """Stores information about a comment to a blog post."""

    author_name = db.StringProperty(required=True)
    author_id = db.StringProperty(required=True)
    comment_id = db.StringProperty()
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    modified = db.DateTimeProperty(auto_now=True)


class Like(db.Model):
    """Stores the username who likes something that is likable."""

    liker = db.StringProperty(required=True)


# ENGINES
class SecurityEngine(object):
    """Performs functions relative to security."""

    @classmethod
    def make_secure_val(cls, val):
        """Create a secure value.

        Combines a given value with a secret string to produce a secure value.
        The secure value/string pair will be stored as a cookie and used later
        to authenticate the user.

        Args:
            val: The user's id obtained at login or signup. Set val to empty
                string to clear the cookie.

        Returns:
            A value/hash pair.
        """

        return "%s|%s" % (val, hmac.new(SECRET, val).hexdigest())

    def set_secure_cookie(self, name, val, expires):
        """Creates and sets cookie.

        Called during login, signup, and logout.

        Args:
            name: The 'user_id' (A global constant.).
            val: The user's id obtained at login or signup. Set val to empty
                string to clear the cookie.
            expires: When cookie expires. (Set to 0 for this blog).
        """

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
        """ Reads a cookie.

        Args:
            cookie_name: The name of the cookie to read.

        Returns:
            The cookie that was read.
        """

        if self.request.cookies.get(cookie_name):
            cookie = self.request.cookies.get(cookie_name)
            value = self.get_secure_val(cookie)
            return value
        else:
            return

    @classmethod
    def make_salt(cls):
        """ Creates a random string.

        Args:
            salt_length: The length of the random string.

        Returns:
            The random string.
        """

        return ''.join(random.choice(letters)
                       for x in xrange(SALT_LENGTH))

    def hash_pass(self, username, password, salt=None):
        """ Makes a hash from username, password, plus salt.

        Args:
            username: The user's username.
            password: The user's password.
            salt: A randomized string.

        Returns:
            The salt and hashed strings separated by a pipe ('|') symbol.
        """
        if not salt:
            salt = self.make_salt()
        hashed_pass = hashlib.sha256(username + password + salt).hexdigest()
        return '%s|%s' % (salt, hashed_pass)

    def valid_pass_hash(self, username, password, hashed_pass):
        """Uses the salt to test if the hash is valid.

        Args:
            username: The user's username.
            password: The user's password.
            hashed_pass: The user's hashed password.

        Returns:
            True if the given hash matches the user's hashed password.
        """
        salt = hashed_pass.split('|')[0]
        return hashed_pass == self.hash_pass(username, password, salt)

    def get_secure_val(self, secure_val):
        """Uses a secure value/string pair to get the value part.

        Args:
            secure_val: The secure value/string pair.

        Returns:
            The value that was used to make a secure value/string pair.
        """
        if secure_val:
            val = secure_val.split('|')[0]
        else:
            val = None
        if secure_val == self.make_secure_val(val):
            return val

    def get_user_by_uid(self):
        """Returns the user's id."""

        user_id = self.read_secure_cookie(USER_ID)
        if user_id:
            user_key = db.Key.from_path('User', int(user_id), parent=None)
            return db.get(user_key)
        else:
            return None

    @classmethod
    def get_user(cls, username):
        """Returns the user object."""

        return db.GqlQuery("SELECT * FROM User WHERE username = :un", un=username).get()

    def user_auth(self, username, password):
        """Returns T/F if the user is securely authorized."""

        user = self.get_user(username)
        if user:
            return self.valid_pass_hash(user.username,
                                        password,
                                        user.pass_hash)

    def is_registered(self):
        """Returns T/F if the username is a registered user."""

        authorized = False
        username = self.read_secure_cookie(USER_ID)
        if username:
            authorized = True
        if self.get_user(username):
            authorized = True
        return authorized


class BlogEngine(webapp2.RequestHandler, SecurityEngine):
    """Handles activities pertinent to rendering blog data."""

    def write(self, *a, **kw):
        """Writes to the browser."""

        self.response.out.write(*a, **kw)

    @classmethod
    def render_tmp(cls, template, **params):
        """Renders a template with one or more parameters."""

        return render_str(template, **params)

    def render(self, template, **kw):
        """Sends username and renders template with one or more keyword pairs."""

        user = None
        user = self.get_user_by_uid()
        if user:
            self.write(self.render_tmp(template, username=user.username, **kw))
        else:
            self.write(self.render_tmp(template, **kw))

    @classmethod
    def save_entity(cls, the_entity):
        """Saves and entity and returns its key."""

        entity_key = the_entity.put()
        return entity_key

    @classmethod
    def get_entity(cls, entity_key):
        """Given a key, gets its entity."""

        return db.get(entity_key)


# HANDLERS
class LikeHandler(BlogEngine):
    """Handles a Like."""

    def get(self):
        user = self.get_user_by_uid()
        if user:
            likable_id = self.request.get("id")
            parent_key = db.Key(likable_id)

            like = Like(parent=parent_key,
                        liker=user.username)
            like.put()
            self.redirect("/open?id=%s" % likable_id)
        else:
            self.redirect("/login")


class CommentHandler(BlogEngine):
    "Handles Comments."

    def get(self):
        user = self.get_user_by_uid()
        if user:
            post_id = self.request.get("id")
            self.render("new_comment.html", post_id=post_id)
        else:
            self.redirect('/login')

    def post(self):

        user = self.get_user_by_uid()
        if user:
            post_id = self.request.get("id")
            content = self.request.get("content")

            if content.strip() != "":
                parent_key = db.Key(post_id)
                comment = Comment(parent=parent_key,
                                  author_id=self.read_secure_cookie(USER_ID),
                                  author_name=user.username,
                                  content=content)
                comment_key = self.save_entity(comment)
                comment.comment_id = str(comment_key)
                comment.post_id = post_id
                comment.put()
                time.sleep(.5)
                self.redirect("/open?id=%s" % post_id)
            else:
                error = "You forgot to add your comment!"
                params = dict(error=error)
                self.render("new_comment.html", **params)
        else:
            self.redirect("/login")


class EditHandler(BlogEngine):
    """Handles edits."""

    def get(self):
        the_id = self.request.get("id")
        user = self.get_user_by_uid()

        if not user:
            self.redirect("/login")

        if self.is_registered():
            if the_id != "None":
                the_key = db.Key(the_id)
                the_entity = self.get_entity(the_key)
                if the_entity:

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

                        # Edit POST
                        if the_entity.kind() == "Post":
                            subject = the_entity.subject
                            params["subject"] = subject
                            form = "new_post.html"

                        # Edit COMMENT
                        elif the_entity.kind() == "Comment":
                            form = "new_comment.html"

                        else:
                            self.write("Error: Entity kind needs handler")

                        self.render(form, **params)
                    else:
                        self.write("Error: Not an editor.")
                else:
                    self.write("Error: Don't have the entity")
            else:
                self.write("Error: the_id = None")
        else:
            self.write("Error: Not authorized")

    def post(self):

        the_id = self.request.get("id")
        user = self.get_user_by_uid()
        if the_id == "None" or not user or not self.is_registered:
            self.redirect("/login")

        the_key = db.Key(the_id)
        the_entity = self.get_entity(the_key)

        if the_entity:
            # Check if is_editor
            if the_entity.author_name == user.username:

                # get/set editable params common to all kinds
                content = self.request.get("content")
                the_entity.content = content
                kind = the_entity.kind()

                # POST
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

                # COMMENT
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
                    self.write("Error: Entity kind needs a handler")
            else:
                self.write("Error: Not an Editor.")
        else:
            self.write("Error: Don't have the entity")


class OpenHandler(BlogEngine):
    "Handles opening (viewing) entities."

    def get(self):
        user = self.get_user_by_uid()
        the_id = self.request.get("id")
        if the_id != "None":
            the_key = db.Key(the_id)
            the_entity = db.get(the_key)
            author_name = the_entity.author_name

            params = dict()
            # get/set params common to all Models
            params["content"] = the_entity.content
            params["author_name"] = author_name
            params["created"] = the_entity.created
            params["modified"] = the_entity.modified

            is_editor = user and (user.username == author_name)
            params["is_editor"] = is_editor

            # Open POST
            if the_entity.kind() == "Post":
                params["post_id"] = the_entity.post_id
                params["subject"] = the_entity.subject

                comments = Comment.all()
                comments.ancestor(the_key)
                comments.order("-created")
                params["comments"] = comments

                all_likes = Like.all()
                likes = all_likes.ancestor(db.Key(the_entity.post_id))
                like_count = likes.count()
                likers = []
                for like in likes:
                    likers.append(str(like.liker))
                params["likers"] = likers
                params["like_count"] = like_count
                form = "post.html"
            # Open COMMENT
            elif the_entity.kind() == "Comment":
                params["comment_id"] = the_entity.comment_id
                form = "comment.html"
            else:
                form = "blog_roll.html"

            self.render(form, **params)
        else:
            self.redirect("/login")


class DeleteHandler(BlogEngine):
    """Handles deletes."""

    def get(self):
        auth_error = True
        if self.read_secure_cookie(USER_ID):
            auth_error = False

        username = self.read_secure_cookie(USER_ID)
        if not self.get_user(username):
            auth_error = False

        if not auth_error:
            the_id = self.request.get("id")
            if the_id != "None":
                the_key = db.Key(the_id)
                db.delete(the_key)
                time.sleep(.5)
                self.redirect("/")
            else:
                self.redirect("/login")
        else:
            self.redirect("/signup")


class NewPostHandler(BlogEngine):
    """Handles a new post."""

    def get(self):
        if self.read_secure_cookie(USER_ID):
            self.render("new_post.html")
        else:
            self.redirect("/signup")

    def post(self):
        user = self.get_user_by_uid()
        if user:
            subject = self.request.get("subject")
            content = self.request.get("content")
            if subject and content:
                post = Post(parent=blog_key(),
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
            self.redirect("/login")


class LoginHandler(BlogEngine):
    "Handles a login."

    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        params = dict()
        if self.get_user(username):
            if self.user_auth(username, password):
                auth_error = False
            else:
                auth_error = True
                params["error_password"] = "Invalid Password"
        else:
            auth_error = True
            params["error_username"] = "User Does Not Exist"

        if auth_error:
            self.render("login.html", **params)
        else:
            user = db.GqlQuery("SELECT * FROM User WHERE username = :username",
                               username=username).get()
            user_id = str(user.key().id())
            self.set_secure_cookie(USER_ID, user_id, None)
            self.redirect("/")


class LogoutHandler(BlogEngine):
    """Handles a logout."""

    def get(self):
        self.set_secure_cookie(USER_ID, "", None)
        self.redirect("/login")


class SignupHandler(BlogEngine):
    """Handles a signup."""

    @classmethod
    def username_isvalid(cls, username):
        return username and USER_RE.match(username)

    @classmethod
    def password_isvalid(cls, password):
        return password and PASS_RE.match(password)

    @classmethod
    def email_isvalid(cls, email):
        if email:
            return EMAIL_RE.match(email)
        else:
            return True

    def get(self):
        self.render("signup.html")

    def post(self):
        error = False
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        params = dict(username=username, password=password, email=email)

        if self.get_user(username):
            error = True
            params["error_username_exists"] = "User already exists."
        elif not self.username_isvalid(username):
            error = True
            params["error_username"] = "Username is not valid"

        if not self.password_isvalid(password):
            error = True
            params["error_password"] = "Password is not valid."
        elif password != verify:
            error = True
            params["error_verify"] = "Passwords do not match."

        if not self.email_isvalid(email):
            error = True
            params["error_email"] = "Email is not valid."

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
            self.redirect("/")


class MainHandler(BlogEngine):
    """Handles the main blog roll home page."""

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
            self.render("blog_roll.html", **params)


APP = webapp2.WSGIApplication([
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
