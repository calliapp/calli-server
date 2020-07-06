import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import time
import datetime as dt
import secrets
import random

import json
import bcrypt
import jinja2


app = Flask(__name__)

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///calli.db")

app.add_template_filter(dt.datetime)

## Landing page ##

@app.route("/")
def root():
    return render_template("homenew.html")

## Docs ##

@app.route("/docs")
def docs():
    return render_template("docs.html")

@app.route("/docs/cli")
def docs_cli():
    return render_template("docs_cli.html")

@app.route("/docs/api")
def docs_api():
    return render_template("docs_api.html")

@app.route("/docs/server")
def docs_server():
    return render_template("docs_server.html")

## WEBAPP ##

@app.route("/dash", methods=["GET"])
def web_dash():
    if request.method == "GET":
        try:
            session['user_id']
        except KeyError:
            return redirect('/login')
        else:
            ## Today ##
            now = dt.datetime.utcnow().strftime('%s')
            today_start = dt.datetime.now().strftime('%s')
            today_end = (dt.datetime.combine((dt.datetime.today()+dt.timedelta(days=1)), dt.time(0))+dt.timedelta(hours=(-1*int(session['offset'])))).strftime("%s")
            today_calendar = db.execute("SELECT * FROM calendar WHERE userid=(:userid) AND start BETWEEN (:start) AND (:end) ORDER BY start", userid=session['user_id'], start=today_start, end=str(int(today_end)-1))
            for event in today_calendar:
                event['start'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
                event['end'] = (((dt.datetime.utcfromtimestamp(int(event['end'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
            ## Tomorrow ##
            tomorrow_start = (dt.datetime.combine((dt.datetime.today()+dt.timedelta(days=1)), dt.time(0))+dt.timedelta(hours=(-1*int(session['offset'])))).strftime("%s")
            tomorrow_end = (dt.datetime.combine((dt.datetime.today()+dt.timedelta(days=2)), dt.time(0))+dt.timedelta(hours=(-1*int(session['offset'])))).strftime("%s")
            tomorrow_calendar = db.execute("SELECT * FROM calendar WHERE userid=(:userid) AND start BETWEEN (:start) AND (:end) ORDER BY start", userid=session['user_id'], start=tomorrow_start, end=str(int(tomorrow_end)-1))
            for event in tomorrow_calendar:
                event['start'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
                event['end'] = (((dt.datetime.utcfromtimestamp(int(event['end'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
            ## Rest of the week ##
            rest_start = (dt.datetime.combine((dt.datetime.today()+dt.timedelta(days=2)), dt.time(0))+dt.timedelta(hours=(-1*int(session['offset'])))).strftime("%s")
            reset_end = (dt.datetime.combine((dt.datetime.today()+dt.timedelta(days=7)), dt.time(0))+dt.timedelta(hours=(-1*int(session['offset'])))).strftime("%s")
            rest_calendar = db.execute("SELECT * FROM calendar WHERE userid=(:userid) AND start BETWEEN (:start) AND (:end) ORDER BY start", userid=session['user_id'], start=rest_start, end=str(int(reset_end)-1))
            for event in rest_calendar:
                event['day'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%a %d %b %y"))
                event['start'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
                event['end'] = (((dt.datetime.utcfromtimestamp(int(event['end'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
            return render_template("dash.html", userid=session['user_id'], username=session['username'], today_calendar=today_calendar, tomorrow_calendar=tomorrow_calendar, rest_calendar=rest_calendar, offset=session['offset'])
    else:
        return "only get"

@app.route("/dash/events")
def dash_events():
    if request.method == "GET":
        try:
            session['user_id']
        except KeyError:
            return redirect('/login')
        else:
            ## From now onwards ##
            today_start = dt.datetime.now().strftime('%s')
            events_calendar = db.execute("SELECT * FROM calendar WHERE userid=(:userid) AND type='E' AND start>=(:start) ORDER BY start", userid=session['user_id'], start=today_start)
            for event in events_calendar:
                event['day'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%a %d %b %y"))
                event['start'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
                event['end'] = (((dt.datetime.utcfromtimestamp(int(event['end'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
            return render_template("dash_events.html", userid=session['user_id'], username=session['username'], events_calendar=events_calendar, offset=session['offset'])
    else:
        return "no"


@app.route("/dash/reminders")
def dash_remind():
    if request.method == "GET":
        try:
            session['user_id']
        except KeyError:
            return redirect('/login')
        else:
            ## From now onwards ##
            today_start = dt.datetime.now().strftime('%s')
            reminds_calendar = db.execute("SELECT * FROM calendar WHERE userid=(:userid) AND type='R' AND start>=(:start) ORDER BY start", userid=session['user_id'], start=today_start)
            for event in reminds_calendar:
                event['day'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%a %d %b %y"))
                event['start'] = (((dt.datetime.utcfromtimestamp(int(event['start'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
                event['end'] = (((dt.datetime.utcfromtimestamp(int(event['end'])).replace(tzinfo=dt.timezone.utc)) + dt.timedelta(hours=int(session['offset']))).strftime("%I:%M%p"))
            return render_template("dash_reminds.html", userid=session['user_id'], username=session['username'], reminds_calendar=reminds_calendar, offset=session['offset'])
    else:
        return "no"

@app.route("/logout")
def logout():
    """Log user out"""
    # Forget any user_id
    session.clear()
    # Redirect user to login form
    return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def web_login():
    if request.method == "GET":
        return render_template("login.html")
    elif request.method == "POST":
        session.clear()
        session['offset'] = request.form.get('timeoffset')
        if not request.form.get("username"):
            return render_template("login.html", show_error="please provide a username")
        elif not request.form.get("password"):
            return render_template("login.html", show_error="please provide a password")
        users = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        if users:
            if bcrypt.checkpw(request.form.get("password").encode('utf-8'), users[0]['hash']):
                session["user_id"] = users[0]["userid"]
                session["token"] = users[0]["token"]
                session["username"] = users[0]["username"]
                return redirect('/dash')
            else:
                return render_template("login.html", show_error="invalid username or password")

@app.route("/register", methods=["GET", "POST"])
def web_register():
    if request.method == "GET":
        return render_template("register.html")
    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if password != confirmation:
            return render_template("register.html", show_error="passwords must match")
        if not username or not password:
             return render_template("register.html", show_error="enter a username and a password")
        else:
            ## This is not guaranteed to be unique - just extremely unlikely (one in ~2^2600 before a collision)
            token = secrets.token_urlsafe(42)
            db.execute("INSERT INTO users (username, hash, token) VALUES (:username, :hash, :token)", username=username, hash=bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(5)), token=token)
            return redirect("/")


## API ##

@app.route("/api/test", methods=["GET"])
def test():
    return jsonify(""), 204, {}

@app.route("/api/events", methods=["POST", "GET", "DELETE", "PATCH"])
def new_event():
    if request.method == "GET":
        auth = db.execute("SELECT * FROM users WHERE token=(:token)", token=request.headers['token'])
        if auth:
            start = request.args.get('start')
            end = request.args.get('end')
            today_calendar = db.execute("SELECT * FROM calendar WHERE userid=(:userid) AND start BETWEEN (:start) AND (:end) ORDER BY start", userid=auth[0]['userid'], start=start, end=end)
            return jsonify(today_calendar)
    elif request.method == "POST":
        auth = db.execute("SELECT userid FROM users WHERE token=(:token)", token=request.headers['token'])
        if auth:
            content = request.json
            r = lambda: random.randint(0,255)
            existing = db.execute("SELECT eventhex FROM calendar WHERE userid=(:userid)", userid=auth[0]['userid'])
            eventhex = '@%02X%02X%02X' % (r(),r(),r())
            while any(d['eventhex'] == eventhex for d in existing):
                eventhex = '@%02X%02X%02X' % (r(),r(),r())
            try:
                content['end']
            except KeyError:
                content['end'] = str(0)
            db.execute("INSERT INTO calendar (userid, eventhex, type, name, start, end, info) VALUES (:userid, :eventhex, :etype, :name, :start, :end, :info)", userid=auth[0]['userid'], eventhex=eventhex, etype=content['type'], name=content['name'], start=content['start'], end=content['end'], info=content['info'])
            return json.dumps({'eventhex':eventhex}), 200, {'ContentType':'application/json'}
    elif request.method == "DELETE":
        auth = db.execute("SELECT userid FROM users WHERE token=(:token)", token=request.headers['token'])
        if auth:
            content = request.json
            deleted = 0
            for eventhex in content['hex']:
                deleted += db.execute("DELETE FROM calendar WHERE userid=(:userid) AND eventhex=(:eventhex)", userid=auth[0]['userid'], eventhex=eventhex.upper())
            if deleted == len(content['hex']):
                return json.dumps({'eventhex':eventhex}), 204, {'ContentType':'application/json'}
            else:
                return jsonify("failed"), 401, {'ContentType':'application/json'}
    elif request.method == "PATCH":
        auth = db.execute("SELECT * FROM users WHERE token=(:token)", token=request.headers['token'])
        if auth:
            eventid = "@" + request.args.get('eventhex')
            content = request.json
            print(eventid)
            for i in content:
                if content[i]:
                    print(i, content[i])
                    db.execute("UPDATE calendar SET :col=:val WHERE userid=(:userid) AND eventhex=(:eventid)", col=i, val=content[i], userid=auth[0]['userid'], eventid=eventid)
            return "boobs"

@app.route("/api/login", methods=["POST"])
def login():
    if request.method == "POST":
        content = request.json
        users = db.execute("SELECT * FROM users WHERE username=(:username)", username=content['username'])
        if users:
            if bcrypt.checkpw(content['password'].encode('utf-8'), users[0]['hash']):
                return jsonify(users[0]['token']), 200, {'ContentType':'application/json'}
            else:
                return jsonify("failed"), 401, {'ContentType':'application/json'}