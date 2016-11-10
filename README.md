# multiBlog
A social blogging web application.
![blog_screenshot](https://cloud.githubusercontent.com/assets/15641327/20195577/0004b20e-a74c-11e6-84c6-bbc6db9084fa.png)

## Project Specifications:
1. Create a Basic Blog
  
  Blog must include the following features:
    
    * Front page that lists blog posts.
    
    * A form to submit new entries.
    
    * Blog posts have their own page.
    
    * View instructions and solutions here.
2.  Add User Registration

    * Have a registration form that validates user input, and displays the
     error(s) when necessary.
    * After a successful registration, a user is directed to a welcome page
     with a greeting, “Welcome, ” where is a name set in a cookie.
    * If a user attempts to visit the welcome page without being signed in
     (without having a cookie), then redirect to the Signup page.
    * Be sure to store passwords securely.
3.  Add Login

    * Have a login form that validates user input, and displays the error(s)
    when necessary.
    * After a successful login, the user is directed to the same welcome page
     from Step 2.
4.  Add Logout

    * Have a logout form that validates user input, and displays the error(s)
    when necessary.
    * After logging out, the cookie is cleared and user is redirected to the
     Signup page from Step 2.
5.  Add Other Features on Your Own

    * Users should only be able to edit/delete their posts. They receive an error
     message if they disobey this rule.
    * Users can like/unlike posts, but not their own. They receive an error
     message if they disobey this rule.
    * Users can comment on posts. They can only edit/delete their own posts,
     and they should receive an error message if they disobey this rule.

## How to Run this project ?
1. Go to folder: /engineapp/
2. Template folder: comsist of all .html files required by main.py
3. main.py: This is main python file that renders html files, and other
             operations such as Login,Logout etc.
4.This project requires google app engine installed on your machine.
## 

* For details click: https://cloud.google.com/appengine/docs/python/getting-started/python-standard-env

* To run at localhost: http://localhost:8080/blog

* To see the pubic view, check at **http://mythic-producer-137123.appspot.com/blog**
