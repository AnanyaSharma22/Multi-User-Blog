import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'temp')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'udacity'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
 
# Base class for all the handlers!
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    # This function checks if the post is present or not.
    def post_is_present(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post: 
            self.error(404)
            return
        return post

    #This function checks whether a user is currently signed in or not.
    def user_signed_in(self, user):
        if not user:
            self.redirect('/login')
            return
        else:
            return True

    # This function checks if the post is user's own post or not.
    def user_self_post(self, user, post):
	#print post.user_id
        return int(post.user_id) == user.key().id()

    # This function checks whether the comment by the user is present or not.
    def comment_is_present(self, comm_id):
        key = db.Key.from_path('Comment', int(comm_id))
        comment = db.get(key)

        if not comment:
            self.error(404)
            return
        return comment

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')

##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

# User Model
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

##### blog stuff
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# The Post Model.
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    user_id = db.StringProperty()
    last_modified = db.DateTimeProperty(auto_now = True)
    l = db.StringProperty(default = "0")
    d = db.StringProperty(default = "0")


    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

# The Comment Model.
class Comment(db.Model):
    user_id = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    owner = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def UserName(self):
        user = User.by_id(self.user_id)
        return user.name

# Render the blog front page.
class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

# Render the single post view.
class PostPage(BlogHandler):
    
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)
 
# Handler for the post creation.
class NewPost(BlogHandler): 

    def get(self):
        if self.user_signed_in(self.user):
            self.render("newpost.html")
        else:
	    self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content)
            p.user_id = str(self.user.key().id())
            p.put()
            Comm = Comment.all().filter('post_id =', p.key().id())
            self.render("permalink.html", post=p, comments=Comm)
        else:
            error = "Please, enter the subject and content!"
            self.render(
                "newpost.html", subject=subject, content=content,
                error=error)

# Handler for the post deletion.
class DeletePost(BlogHandler):

    def get(self, pId):
        if self.user_signed_in(self.user):
            p = self.post_is_present(pId)
            if p:
		#print post.subject
                if self.user_self_post(self.user, p):
                    p.delete()
                    posts = greetings = Post.all().order('-created')
                    self.redirect('/blog/')
                else:
                    Comm = Comment.all().filter('post_id =', pId)
                    self.render(
                        "permalink.html", post=p,
                        error="You cannot delete this post, as user"
			       "can only delete his/her own post.",
                        comments=Comm)			
        	
# Handler for the post edits.
class EditPost(BlogHandler):

    def get(self, pId):
        if self.user_signed_in(self.user):
            p = self.post_is_present(pId)
            if p:
                if self.user_self_post(self.user, p):
                    self.render(
                        "editpost.html", subject=p.subject,
                        content=p.content)
                else:
                    Comm = Comment.all().filter('post_id =', pId)
                    self.render(
                        "permalink.html", post=p,
                        error="You cannot edit this post, as user"
			      "can only delete his/her own post.",
   			comments=Comm)
	 
    def post(self, pId):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        p = self.post_is_present(pId)
        if not p:
            return

        if not self.user_self_post(self.user, p):
            Comm = Comment.all().filter('post_id =', pId)
            self.render("permalink.html", post=p,
                        error="You cannot edit this post, as user"
			      "can only delete his/her own post.",
                        comments=Comm)
        elif subject and content:
            p.subject = subject
            p.content = content
            p.put()
            Comm = Comment.all().filter('post_id =', pId)
            self.render("permalink.html", post=p, comments=Comm)
        else:
            error = "Please, enter the subject and content!"
            self.render(
	    "editpost.html", subject=subject, content=content, error=error)

# Handler for the comment mainpage.
class CommentMainPage(BlogHandler):

    def post(self, pId):
        if self.user_signed_in(self.user):
            recentComm = self.request.get("comment")
            p = self.post_is_present(pId)
            if not recentComm:
                self.render(
                    "permalink.html", post=p,
                    content=recentComm,
                    error="It not a valid comment, enter a valid comment!")
                return

            # create a new row "comments"and update the Comment entity
            a = Comment(user_id=str(self.user.key().id()),
                        post_id=pId, comment=recentComm,
                        owner=self.user.name)
            a.put()
            if p:
                Comm = Comment.all().filter('post_id =', pId).order('-created')
                self.render("permalink.html", post=p, comments=Comm)

# Handler for the comment creation.
class PostComment(BlogHandler):

    def get(self, pId):
        if self.user_signed_in(self.user):
            p = self.post_is_present(pId)
            if p:
                Comm = Comment.all().filter('post_id =', pId).order('-created')
                self.render("permalink.html", post=p, comments=Comm)

# Handler for the comment deletion.
class DeleteComment(BlogHandler):

    def get(self, cId):
        if not self.user_signed_in(self.user):
            return

        c = self.comment_is_present(cId)
        if not c:
            return

        pId = c.post_id
        p = self.post_is_present(pId)
        if not p:
            return

        if int(c.user_id) == self.user.key().id():
            c.delete()
            Comm = Comment.all().filter(
                          'post_id =', pId).order('-created')
            self.render("permalink.html", post=p, comments=Comm)
        else:
            Comm = Comment.all().filter(
                          'post_id =', pId).order('-created')
            self.render(
                    "permalink.html",
                     post=p,
                     error="You cannot delete this comment, as user"
		           "can only delete his/her own comment!",
                     comments=Comm)

# Handler for the comment edits.
class EditComment(BlogHandler):

    def get(self, cId):
        if not self.user_signed_in(self.user):
            return

        c = self.comment_is_present(cId)
        if not c:
            return

        p = self.post_is_present(c.post_id)
        if not p:
            return
        Comm = Comment.all().filter('post_id =', c.post_id).order('-created')

        if int(c.user_id) == self.user.key().id():
            self.render("editcomment.html",
                         post=p,
                         content=c.comment,
                         comment=c)
        else:
            self.render("permalink.html",
                         post=p,
                         error="You cannot edit this comment, as user"
			       "can only edit his/her own comment!",
                         comments=Comm)

    def post(self, cId):
        if not self.user_signed_in(self.user):
            return

        c = self.comment_is_present(cId)
        if not c:
            return
        p = self.post_is_present(c.post_id)
        if not p:
            return

        newComm = self.request.get("comment")
        if not newComm:
            error = "This is invalid, enter valid content !"
            self.render("editcomment.html", post=p, 
		content=newComm, error=error, comment=c)
            return

        # update the row and the Comment entity
        key = db.Key.from_path('Comment', int(cId))
        c = db.get(key)
        c.comment = newComm
	if int(c.user_id)==self.user.key().id():
            c.put()
        Comm = Comment.all().filter('post_id =', c.post_id).order('-created')
        self.render("permalink.html", post=p, comments=Comm)

# The Like Model.
class LikeModel(db.Model):
    user_id = db.StringProperty()
    post_id = db.StringProperty()

    def User_Name(self):
        user = User.by_id(self.user_id)
	return user.name

# Handler for the functionality of liking a post.
class LikePost(BlogHandler):

    def get(self, pId):
        if self.user_signed_in(self.user):
            p = self.post_is_present(pId)
            if p:
                Comm = Comment.all().filter('post_id =', pId)
                if self.user_self_post(self.user, p):
                    self.render(
                        "permalink.html", post=p,
                        error="You cannot like this post, as user"
			      "cannot like his/her own post!",
                        comments=Comm)
                    return

                l = LikeModel.all()
                l.filter('user_id =', str(self.user.key().id())).filter(
                    'post_id =', pId)

                if l.get():
                    self.render(
                        "permalink.html", post=p,
                        error="This post is already liked by you.",
                        comments=Comm)
                    return

                like = LikeModel(user_id=str(self.user.key().id()), post_id=pId)
                like.put()

                p.l = str(int(p.l) + 1)
                p.put()
	        self.render("permalink.html", post=p, comments=Comm)

# The Dislike Model.
class DislikeModel(db.Model):
    user_id = db.StringProperty()
    post_id = db.StringProperty()

    def User_Name(self):
        user = User.by_id(self.user_id)
	return user.name

# Handler for the functionality if disliking a post.
class DislikePost(BlogHandler):

    def get(self, pId):
        if self.user_signed_in(self.user):
            p = self.post_is_present(pId)
            if p:
                Comm = Comment.all().filter('post_id =', pId)
                if self.user_self_post(self.user, p):
                    return self.render(
                        "permalink.html",
                        post=p,
                        error="You cannot dislike this post, as user"
			      "cannot dislike his/her own post!",
                        comments=Comm)

                d = DislikeModel.all()
                d.filter('user_id =', str(self.user.key().id())).filter(
                    'post_id =', pId)

                if d.get():
                    self.render(
                        "permalink.html", post=p,
                        error="This post is already disliked by you.",
                        comments=Comm)
                    return

                dislike = DislikeModel(user_id=str(self.user.key().id()), post_id=pId)
                dislike.put()

                p.d = str(int(p.d) + 1)
                p.put()
		self.render("permalink.html", post=p, comments=Comm)

###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Handler for user account creation.
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

# Handler for user account registration.
class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

# Handler for user account login.
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

# Handler for user account logout.
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/commentMainPage/([0-9]+)', CommentMainPage),
                               ('/blog/postcomment/([0-9]+)', PostComment),
                               ('/blog/deletecomment/([0-9]+)', DeleteComment),
                               ('/blog/editcomment/([0-9]+)', EditComment),
                               ('/blog/likepost/([0-9]+)', LikePost),
                               ('/blog/dislikepost/([0-9]+)', DislikePost),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ],
                              debug=True)
