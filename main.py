from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5


app = Flask(__name__)
Bootstrap5(app)


@app.route("/")
def home():
    return render_template("index.html", role='instructor')


if __name__ == "__main__":
    app.run(debug=True)
