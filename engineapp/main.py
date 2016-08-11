#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import jinja2
import os
import logging
import re
from google.appengine.ext import db
import hashlib
import hmac
from string import letters
import random

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


secret = 'fart'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class MainHandler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.out.write(*a,**kw)

    def render_str(self,template,**params):
        t=jinja_env.get_template(template)
        return t.render(params)

    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        logging.info('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%')
        logging.info(cookie_val)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        self.uid = self.read_secure_cookie('user_id')
        self.user = self.uid and User.by_id(int(self.uid))



def users_key(group = 'default'):
    return db.Key.from_path('User', group)

class User(db.Model):
    user_name = db.StringProperty(required=True)
    user_pw_hash = db.StringProperty(required=True)
    user_email = db.StringProperty(required=True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
       # blogs = db.GqlQuery("select * from User ")
        #for blog in blogs:
         #   logging.info("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
          #  logging.info(blog.user_name)
        u = User.all().filter('user_name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    user_name=name,
                    user_pw_hash=pw_hash,
                    user_email=email)
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
       # logging.info("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
       # logging.info(u)
        #logging.info(u.user_name )
        if u and valid_pw(name, pw, u.user_pw_hash):
            return u



class Register(MainHandler):
    def send_data(self, file, items=""):
        self.render(file, items=items)

    def get(self):
        self.send_data("sign-up.html")

    def post(self):
        user_name = self.request.get("userName")
        user_pass = self.request.get("password")
        user_pass_re = self.request.get("passwordRe")
        user_email = self.request.get("email")
        check_name = USER_RE.match(user_name)
        logging.info("**************************")
        logging.info(user_name)
        check_email = EMAIL_RE.match(user_email)

        check_pass = PASS_RE.match(user_pass)
        user_error = ""
        pass_error = ""
        email_error = ""
        pass_re_error = ""

        check_re_pass = "Ok"
        if (user_pass != user_pass_re):
            pass_re_error = "Password does not match"
            check_re_pass = None
        if (check_pass and check_email and check_name and check_re_pass):
            u = User.by_name(user_name)
            if u:
                msg = 'That user already exists.'
                self.render('signup-form.html', error_username=msg)
            else:
                u = User.register(user_name, user_pass, user_email)
                u.put()

                self.login(u)
                self.redirect('/blog')
           # self.redirect("/blog/welcome?userName=" + user_name)
        if not check_name:
            user_error = "User Name not correct"
        if not check_pass:
            pass_error = "Password not correct"
        if not check_email:
            email_error = "Email Address not correct"
        self.send_data("sign-up.html",
                       items={"UserName": user_name, "email": user_email, "UserError": user_error,
                              "PassError": pass_error
                           , "EmailError": email_error, "PassReError": pass_re_error})




class ThanksHandler(webapp2.RequestHandler):
    def get(self):
        user_name = self.request.get('userName')
        self.response.out.write("Welcome " + user_name)

class Login(MainHandler):
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
            self.render('login-form.html', error=msg)

class Logout(MainHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')
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



class MainPage(MainHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visit_cookie_str = self.request.cookies.get('visits')
        visits = 0
        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)
        visits = visits + 1
        new_cookie_val = make_secure_val(str(visits))
        self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)
        self.write("been here for %s times" % visits)


class Blog(db.Model):
    subject = db.StringProperty(required=True)
    blog = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    owner=db.StringProperty(required=False)

class  LIKE(db.Model):
    c_post_id=db.IntegerProperty(required=True)
    c_likes=db.IntegerProperty()
    like_list=db.ListProperty(long)

class BlogPage(MainHandler):
    def render_front(self, subject="", blog='', error=''):
        self.render('newblog.html', subject=subject, blog=blog, error=error)

    def get(self):
        if self.user:
           self.render_front()
        else:
            self.redirect('/blog/register')

    def post(self):
        user_subject = self.request.get("subject")
        user_blog = self.request.get("blog")
        if user_blog and user_subject:
            a = Blog(subject=user_subject, blog=user_blog, owner=self.uid)
            a_key = a.put()
            list_appended=[]
            #logging.info("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            #logging.info(a.owner)
            list_appended.append(a.owner)
            #logging.info("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            #logging.info(a_key.id())
            #logging.info(list_appended)
            b=LIKE(c_post_id=a_key.id(), c_likes=0, like_list=list_appended)
            b.put()
            self.redirect('/blog/%d' % a_key.id())
        else:
            error = "Pl input both fields."
            self.render_front(subject=user_subject, blog=user_blog, error=error)


class Permalink(MainHandler):
    def get(self, blog_id):
        #logging.info("###########################################")
       # logging.info(blog_id)
       # blog_id=blog_id.split(',')
       # logging.info(blog_id[0])
       # logging.info(blog_id[1])

        s = Blog.get_by_id(int(blog_id))
        likes = db.GqlQuery("select * from LIKE")

        #key = db.Key.from_path('LIKE', int(blog_id[0]))
        #like_key = db.get(key)
        #likes=LIKE.get_by_id(like_key)
        self.render('blog.html', blogs=[s],like=likes)


class MainBlogPage(MainHandler):
    def render_front(self):
        #    employee_k = db.Key.from_path('Blog',5629499534213120)
        #   db.delete(employee_k)
        blogs = db.GqlQuery("select * from Blog order by created desc ")
        likes = db.GqlQuery("select * from LIKE")
        #for blog in blogs:
         #   blog.delete()
        #for like in likes:
         #   like.delete()


        #  for like in likes:
        #    logging.info(likes.c_post)
        self.render('blog.html', blogs=blogs, like=likes)

    def get(self):
        if self.user:
            self.render_front()
        else:
            self.redirect('/blog/register')


    def post(self):

        like_button_id=self.request.get("like_button_id")
       # key = db.Key.from_path('LIKE',like_button_id)
        #like_key = db.get(key)
        logging.info("***************************************************")

        logging.info(long(self.uid))
        logging.info(self.user.user_name)
        s = LIKE.get_by_id(int(like_button_id))

        logging.info(s.like_list)
        if long(self.uid) in s.like_list:
            logging.info("Item found")
        else:
            logging.info("Item not found " )
            s.c_likes = s.c_likes + 1
            s.put()
            s.put()
        self.render_front()
class EditBlog(MainHandler):
    def render_front(self,post_id):
        s = Blog.get_by_id(int(post_id))
        self.render('edit-blog.html', s=s)
    def get(self):

        # put check for owner and blog's owner from id

        post_id=self.request.get("post_id")
        post = Blog.get_by_id(int(post_id))
        if(self.uid == post.owner):
            self.render_front(post_id)
        else:
            self.redirect("/blog")

    def post(self):
        post_id = self.request.get("post_id")
        logging.info("::::::::::::::::::::::::::::::::::::::::::::::::::::%s"%post_id)
        self.redirect('/blog/edit?post_id='+post_id)

class PostEdition(MainHandler):
    def post(self):
        blog_id=self.request.get("blog_id")
        user_blog = self.request.get("blog")
        logging.info("~~~~~~~~~~~~~~~~~~~~~~~%s and %s"%(blog_id, user_blog))
        if user_blog:
            post=Blog.get_by_id(int(blog_id))
            post.blog=user_blog
            post.put()
            post.put()

            self.redirect('/blog')
        else:
            error = "Pl input field."
            self.render_front(subject=user_subject, blog=user_blog, error=error)


app = webapp2.WSGIApplication([('/blog/newpost', BlogPage), ('/blog/(\d+)', Permalink), ('/blog', MainBlogPage),
                               ('/blog/register',Register),('/blog/welcome',ThanksHandler),('/blog/login',Login),
                               ('/blog/logout',Logout),('/blog/edit',EditBlog),('/blog/postEdition',PostEdition)],
                              debug=True)


class AsciiPage(MainHandler):
    def render_front(self, title="", art='', error=''):
        arts = db.GqlQuery("select * from Art order by created desc")
        self.render('front.html', title=title, art=art, error=error, arts=arts)

    def get(self):
        self.render_front()

    def post(self):
        user_title = self.request.get("title")
        user_art = self.request.get("art")
        if user_art and user_title:
            a = Art(title=user_title, art=user_art)
            a.put()
            self.redirect('/ascii')

        else:
            error = "Pl input both fields."
            self.render_front(title=user_title, art=user_title, error=error)




class ConvertToRot13(MainHandler):
    def convertToRot13(self, data):
        result = ""
        for item in data:
            #  logging.info (item)
            ch = ord(item)
            if ch >= ord('a') and ch <= ord('z'):
                if ch > ord('m'):
                    ch -= 13
                else:
                    ch += 13
            elif ch >= ord('A') and ch <= ord('Z'):
                if ch > ord('M'):
                    ch -= 13
                else:
                    ch += 13
            result += chr(ch)
        return result

    def send_data(self, file, items=""):
        self.render(file, items=items)

    def get(self):
        self.send_data("rot13.html")

    def post(self):
        items = self.request.get("text")
        logging.info(items)
        update_item = self.convertToRot13(items)
        self.send_data("rot13.html", items=update_item)


class MainPage(MainHandler):
    def test(self):
        items = self.request.get("text")
        logging.info(items)
        update_item = self.convertToRot13(items)
        self.send_data("rot13.html", items=update_item)


def chapter2(self):
    class MainPage(MainHandler):
        def get(self):
            items = self.request.get_all("food")
            self.render("shopping-list.html", items=items)

        def not_needed(self):
            output = form
            output_hidden = ""
            output_items = ""
            items = self.request.get_all("food")
            if items:
                for item in items:
                    output_hidden += hidden_html % item
                    output_items += item_html % item
                output_shopping = shopping_list % output_items
                output += output_shopping
            output = output % output_hidden

            self.write(output)

    app = webapp2.WSGIApplication([
        ('/', MainPage)], debug=True)


def chapter1(self):
    form = """
    <form method="POST">
    <h2> When is your birthday ?</h2>
    <label>Month<input type="text" name="month" value="%(month)s"></label>
    <label>Day<input type="text" name="day" value="%(day)s"></label>
    <div> %(error)s</div>

    <input type="Submit">
    </form>
    """

    months = ['January', 'February', "March", "April"]
    month_abbr = dict((m[:3].lower(), m) for m in months)

    def escape_html(s):
        return cgi.escape(s, quote=True)

    class MainHandler(webapp2.RequestHandler):

        def check_mon(self, month):
            if month:
                short_momth = month[:3].lower()
                return month_abbr.get(short_momth)

        def check_day(self, day):
            if day and day.isdigit():
                day = int(day)
                if day > 0 and day <= 31:
                    return day

        def write_form(self, error="", day="", month=""):
            self.response.out.write(form % {"error": error, "day": escape_html(day), "month": escape_html(month)})

        def get(self):
            self.write_form()

        def post(self):
            user_month = self.request.get("month")
            user_day = self.request.get("day")
            checked_month = self.check_mon(user_month)
            checked_day = self.check_day(user_day)

            if not (checked_month and checked_day):
                self.write_form("Looks problemmm", user_day, user_month)
                # self.response.out.write(user_month)
            # self.response.out.write(user_month)
            else:
                self.redirect("/thanks")
                # self.r esponse.headers['content-type']='text/plain'
                # self.response.out.write(self.request)

        class ThanksHandler(webapp2.RequestHandler):
            def get(self):
                self.response.out.write("Thanks...")

        app = webapp2.WSGIApplication([
            ('/', MainHandler), ('/thanks', ThanksHandler)
        ], debug=True)